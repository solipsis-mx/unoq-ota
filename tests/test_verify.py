from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unoq_ota.verify import (
    VerificationError,
    canonical_bytes,
    verify_digest,
    verify_sequence,
    verify_signature,
)


def _signed(manifest, key, key_id="k1"):
    manifest = dict(manifest)
    manifest.pop("signature", None)
    sig = key.sign(canonical_bytes(manifest))
    manifest["signature"] = {
        "alg": "ed25519",
        "key_id": key_id,
        "sig": base64.b64encode(sig).decode(),
    }
    return manifest


@pytest.fixture
def keypair():
    key = Ed25519PrivateKey.generate()
    return key, {"k1": key.public_key()}


def test_canonical_bytes_excludes_the_signature_block():
    assert b"signature" not in canonical_bytes({"a": 1, "signature": {"sig": "x"}})


def test_canonical_bytes_is_order_independent():
    assert canonical_bytes({"a": 1, "b": 2}) == canonical_bytes({"b": 2, "a": 1})


def test_accepts_a_valid_signature(keypair):
    key, public_keys = keypair
    verify_signature(_signed({"version": "1.0.0", "sequence": 1}, key), public_keys)


def test_rejects_a_tampered_manifest(keypair):
    key, public_keys = keypair
    manifest = _signed({"version": "1.0.0", "sequence": 1}, key)
    manifest["version"] = "6.6.6"

    with pytest.raises(VerificationError, match="signature"):
        verify_signature(manifest, public_keys)


def test_rejects_an_unknown_key_id(keypair):
    key, _ = keypair
    manifest = _signed({"version": "1.0.0", "sequence": 1}, key, key_id="rotated-out")

    with pytest.raises(VerificationError, match="key_id"):
        verify_signature(manifest, {"k1": key.public_key()})


def test_rejects_a_replayed_older_sequence():
    # A correctly signed old manifest is a downgrade attack: it pushes firmware
    # that was legitimately published once and later found to be bad.
    with pytest.raises(VerificationError, match="sequence"):
        verify_sequence({"sequence": 5}, last_sequence=9)


def test_accepts_a_newer_sequence():
    verify_sequence({"sequence": 10}, last_sequence=9)


def test_verifies_a_file_digest(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello")
    verify_digest(path, hashlib.sha256(b"hello").hexdigest())


def test_rejects_a_bad_digest(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello")

    with pytest.raises(VerificationError, match="sha256"):
        verify_digest(path, "0" * 64)
