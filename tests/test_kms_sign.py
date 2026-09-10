from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unoq_ota.kms_sign import (
    KmsSignError,
    get_kms_ed25519_public_key,
    public_key_b64,
    sign_with_kms,
)


class _FakeKms:
    def __init__(self, signature=None, public_key_der=None):
        self._signature = signature
        self._public_key_der = public_key_der
        self.sign_calls = []

    def sign(self, **kwargs):
        self.sign_calls.append(kwargs)
        return {"Signature": self._signature}

    def get_public_key(self, **kwargs):
        return {"PublicKey": self._public_key_der}


def test_sign_with_kms_calls_the_right_algorithm_and_message_type():
    client = _FakeKms(signature=b"\x01" * 64)
    sig = sign_with_kms(client, "alias/ota-signing", b"hello")
    assert sig == b"\x01" * 64
    assert client.sign_calls == [
        {
            "KeyId": "alias/ota-signing",
            "Message": b"hello",
            "MessageType": "RAW",
            "SigningAlgorithm": "ED25519_SHA_512",
        }
    ]


def test_sign_with_kms_refuses_a_message_over_4096_bytes():
    client = _FakeKms()
    with pytest.raises(KmsSignError, match="4096"):
        sign_with_kms(client, "alias/ota-signing", b"x" * 4097)


def test_sign_with_kms_rejects_a_missing_signature():
    class _Empty:
        def sign(self, **kwargs):
            return {}

    with pytest.raises(KmsSignError, match="Signature"):
        sign_with_kms(_Empty(), "k", b"hi")


def test_get_kms_ed25519_public_key_decodes_der_spki():
    key = Ed25519PrivateKey.generate()
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client = _FakeKms(public_key_der=der)
    public_key = get_kms_ed25519_public_key(client, "alias/ota-signing")
    raw_expected = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    raw_actual = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert raw_actual == raw_expected


def test_get_kms_ed25519_public_key_rejects_a_non_ed25519_key():
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

    key = generate_private_key(SECP256R1())
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client = _FakeKms(public_key_der=der)
    with pytest.raises(KmsSignError, match="not an Ed25519 key"):
        get_kms_ed25519_public_key(client, "alias/wrong-kind")


def test_public_key_b64_matches_the_on_device_keyring_file_format():
    key = Ed25519PrivateKey.generate()
    encoded = public_key_b64(key.public_key())
    assert base64.b64decode(encoded, validate=True) == key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
