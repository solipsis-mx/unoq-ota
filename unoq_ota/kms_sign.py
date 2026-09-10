"""Sign OTA manifests with an AWS KMS asymmetric ed25519 key instead of a
local PEM file. The private key material never leaves KMS.

Generic AWS glue, not fleet-specific -- any UNO Q owner with their own AWS
account can use this the same way `unoq_ota.sources.s3_presigned` already
lets them use their own S3 bucket.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# `MessageType: RAW` signs the message directly (no pre-hash) and is the
# only mode `cryptography`'s `Ed25519PublicKey.verify()` can check against,
# since EdDSA folds hashing into the signing algorithm itself -- there is
# no separate "digest mode" compatible with a bare Ed25519 verify. KMS caps
# a RAW message at 4096 bytes; `sign_with_kms` enforces that ceiling itself
# so a bad manifest fails fast and locally instead of as an opaque KMS
# ValidationException.
SIGNING_ALGORITHM = "ED25519_SHA_512"
MESSAGE_TYPE = "RAW"
MAX_RAW_MESSAGE_BYTES = 4096


class KmsSignError(Exception):
    """A KMS Sign/GetPublicKey call did not return a usable ed25519 result."""


def sign_with_kms(kms_client, key_id: str, message: bytes) -> bytes:
    if len(message) > MAX_RAW_MESSAGE_BYTES:
        raise KmsSignError(
            f"message is {len(message)} bytes; kms:Sign with MessageType=RAW "
            f"caps ed25519 messages at {MAX_RAW_MESSAGE_BYTES} bytes"
        )
    response = kms_client.sign(
        KeyId=key_id,
        Message=message,
        MessageType=MESSAGE_TYPE,
        SigningAlgorithm=SIGNING_ALGORITHM,
    )
    signature = response.get("Signature")
    if not isinstance(signature, (bytes, bytearray)):
        raise KmsSignError(f"kms:Sign returned no usable Signature: {signature!r}")
    return bytes(signature)


def get_kms_ed25519_public_key(kms_client, key_id: str) -> Ed25519PublicKey:
    """Fetch and decode a KMS asymmetric key's public half.

    KMS returns the public key as a DER-encoded X.509 SubjectPublicKeyInfo,
    not raw bytes -- `load_der_public_key` does the ASN.1 work so nothing
    here has to.
    """
    response = kms_client.get_public_key(KeyId=key_id)
    der = response.get("PublicKey")
    if not isinstance(der, (bytes, bytearray)):
        raise KmsSignError(f"kms:GetPublicKey returned no usable PublicKey: {der!r}")
    key = serialization.load_der_public_key(bytes(der))
    if not isinstance(key, Ed25519PublicKey):
        raise KmsSignError(f"KMS key {key_id} is not an Ed25519 key: {type(key).__name__}")
    return key


def public_key_b64(public_key: Ed25519PublicKey) -> str:
    """Encode a public key the same way `tools/keygen.py` writes `*.public.b64`."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def default_kms_client(region: str | None = None):
    """Build a KMS client from the standard AWS credential chain.

    Mirrors `unoq_ota.sources.s3_presigned.default_client` exactly -- same
    lazy botocore import, same optional-extra story (`pip install
    'unoq-ota[s3]'`), same region-from-env fallback.
    """
    try:
        import botocore.session
    except ImportError as exc:
        raise KmsSignError(
            "KMS signing requires botocore; install with: pip install 'unoq-ota[s3]'"
        ) from exc
    import os

    region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    return botocore.session.get_session().create_client("kms", **kwargs)
