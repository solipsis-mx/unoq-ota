from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unoq_ota.verify import (
    VerificationError,
    canonical_bytes,
    verify_digest,
    verify_manifest,
    verify_sequence,
    verify_signature,
    verify_window,
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


def test_string_last_sequence_raises_verification_error():
    # last_sequence comes from on-device state (already sanitized to a real
    # int by unoq_ota.state) and must be held to the same standard as the
    # manifest's own `sequence` field -- no int()-coercion of strings/bools.
    with pytest.raises(VerificationError, match="last_sequence"):
        verify_sequence({"sequence": 10}, last_sequence="9")


def test_bool_last_sequence_raises_verification_error():
    with pytest.raises(VerificationError, match="last_sequence"):
        verify_sequence({"sequence": 10}, last_sequence=True)


def test_float_last_sequence_raises_verification_error():
    with pytest.raises(VerificationError, match="last_sequence"):
        verify_sequence({"sequence": 10}, last_sequence=9.9)


# ---------------------------------------------------------------------------
# Finding 3 (A1-A3): verify_window's malformed-input handling had zero
# enforcement coverage. These tests exercise real expiry/not-before rejection
# (including through verify_manifest's `now` parameter), naive-timestamp
# handling, and the falsy-but-present fields that used to fail open.
# ---------------------------------------------------------------------------


def test_expired_manifest_is_rejected():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    expires = now - timedelta(days=1)
    manifest = {"sequence": 1, "expires": expires.isoformat()}

    with pytest.raises(VerificationError, match="expired"):
        verify_window(manifest, now=now)


def test_future_not_before_is_rejected():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    not_before = now + timedelta(days=1)
    manifest = {"sequence": 1, "not_before": not_before.isoformat()}

    with pytest.raises(VerificationError, match="not valid until"):
        verify_window(manifest, now=now)


def test_manifest_inside_its_window_passes():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    manifest = {
        "sequence": 1,
        "not_before": (now - timedelta(days=1)).isoformat(),
        "expires": (now + timedelta(days=1)).isoformat(),
    }

    verify_window(manifest, now=now)


def test_manifest_with_neither_window_field_passes():
    verify_window({"sequence": 1})


def test_verify_manifest_propagates_a_window_rejection(keypair):
    # Exercises verify_manifest's own `now` parameter, not just verify_window
    # called directly -- the gap the review flagged as completely untested.
    key, public_keys = keypair
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    expires = now - timedelta(days=1)
    manifest = _manifest(sequence=1)
    manifest["expires"] = expires.isoformat()
    manifest = _signed(manifest, key)

    with pytest.raises(VerificationError, match="expired"):
        verify_manifest(manifest, public_keys, last_sequence=0, now=now)


def test_verify_manifest_passes_inside_its_window(keypair):
    key, public_keys = keypair
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    manifest = _manifest(sequence=1)
    manifest["not_before"] = (now - timedelta(days=1)).isoformat()
    manifest["expires"] = (now + timedelta(days=1)).isoformat()
    manifest = _signed(manifest, key)

    verify_manifest(manifest, public_keys, last_sequence=0, now=now)


def test_naive_expires_timestamp_is_rejected():
    # Reversal of the earlier "normalise to UTC" decision: a signer in, say,
    # UTC+5:30 who writes an offset-less local value meaning "expire 18:30
    # UTC" would otherwise get a manifest that keeps verifying for 5.5 hours
    # past their intended deadline (up to ~14h for far-east zones). Since
    # `expires` is the emergency-revocation mechanism, guessing UTC is the
    # unsafe direction -- so a naive timestamp must raise, not be assumed.
    manifest = {"sequence": 1, "expires": "2026-06-02T00:00:00"}

    with pytest.raises(VerificationError, match="UTC offset"):
        verify_window(manifest)


def test_naive_not_before_timestamp_is_rejected():
    manifest = {"sequence": 1, "not_before": "2026-06-02T00:00:00"}

    with pytest.raises(VerificationError, match="UTC offset"):
        verify_window(manifest)


def test_offset_qualified_expired_timestamp_is_still_rejected():
    # A non-UTC but explicit offset must be honoured, not just "Z": this
    # instant is 2026-06-01T18:30:00Z, already in the past relative to `now`.
    now = datetime(2026, 6, 2, 12, 0, tzinfo=timezone.utc)
    manifest = {"sequence": 1, "expires": "2026-06-02T00:00:00+05:30"}

    with pytest.raises(VerificationError, match="expired"):
        verify_window(manifest, now=now)


def test_offset_qualified_timestamp_inside_window_still_passes():
    # Same instant as above (2026-06-01T18:30:00Z), but `now` is earlier --
    # the explicit offset must be converted and compared correctly, not
    # rejected just for being non-UTC.
    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    manifest = {"sequence": 1, "expires": "2026-06-02T00:00:00+05:30"}

    verify_window(manifest, now=now)


@pytest.mark.parametrize("falsy", ["", 0, [], {}, False])
def test_falsy_but_present_expires_raises_rather_than_passing_silently(falsy):
    # A2: `if not raw: continue` used to treat these as "no window given"
    # and silently disable the expiry check.
    manifest = {"sequence": 1, "expires": falsy}

    with pytest.raises(VerificationError):
        verify_window(manifest)


@pytest.mark.parametrize("falsy", ["", 0, [], {}, False])
def test_falsy_but_present_not_before_raises_rather_than_passing_silently(falsy):
    manifest = {"sequence": 1, "not_before": falsy}

    with pytest.raises(VerificationError):
        verify_window(manifest)


@pytest.mark.parametrize("field", ["not_before", "expires"])
def test_absent_window_field_is_not_an_error(field):
    # Absent (key missing, or explicitly None) is the real "no window given"
    # case and must keep passing.
    verify_window({"sequence": 1, field: None})
    verify_window({"sequence": 1})


def test_verifies_a_file_digest(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello")
    verify_digest(path, hashlib.sha256(b"hello").hexdigest())


def test_rejects_a_bad_digest(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello")

    with pytest.raises(VerificationError, match="sha256"):
        verify_digest(path, "0" * 64)


def test_verify_digest_is_case_insensitive(tmp_path):
    # An uppercase digest is a confusing interop trap, not a security issue --
    # it must still match rather than failing closed on casing alone.
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello")
    verify_digest(path, hashlib.sha256(b"hello").hexdigest().upper())


def _manifest(sequence=1, artifact_sha256=None):
    manifest = {"version": "1.0.0", "sequence": sequence}
    if artifact_sha256 is not None:
        manifest["artifact"] = {"sha256": artifact_sha256}
    return manifest


# ---------------------------------------------------------------------------
# Finding 1: verify_manifest must actually verify artifact bytes when asked,
# and must be explicit about not doing so when it isn't.
# ---------------------------------------------------------------------------


def test_verify_manifest_with_matching_artifact_path_passes(keypair, tmp_path):
    key, public_keys = keypair
    artifact_path = tmp_path / "firmware.bin"
    artifact_path.write_bytes(b"real-firmware-bytes")
    digest = hashlib.sha256(b"real-firmware-bytes").hexdigest()
    manifest = _signed(_manifest(sequence=1, artifact_sha256=digest), key)

    verify_manifest(manifest, public_keys, last_sequence=0, artifact_path=artifact_path)


def test_verify_manifest_with_artifact_path_rejects_mismatched_bytes(keypair, tmp_path):
    key, public_keys = keypair
    artifact_path = tmp_path / "firmware.bin"
    artifact_path.write_bytes(b"tampered-bytes-on-disk")
    digest_of_original = hashlib.sha256(b"real-firmware-bytes").hexdigest()
    manifest = _signed(_manifest(sequence=1, artifact_sha256=digest_of_original), key)

    with pytest.raises(VerificationError, match="sha256"):
        verify_manifest(manifest, public_keys, last_sequence=0, artifact_path=artifact_path)


def test_verify_manifest_without_artifact_path_still_runs_signature_and_sequence(keypair):
    key, public_keys = keypair

    # A tampered payload is still caught by the signature check alone.
    tampered = _signed(_manifest(sequence=1), key)
    tampered["version"] = "6.6.6"
    with pytest.raises(VerificationError, match="signature"):
        verify_manifest(tampered, public_keys, last_sequence=0)

    # A replayed (older) sequence is still caught without an artifact path.
    replayed = _signed(_manifest(sequence=1), key)
    with pytest.raises(VerificationError, match="sequence"):
        verify_manifest(replayed, public_keys, last_sequence=5)


def test_verify_manifest_without_artifact_path_does_not_check_digest(keypair, tmp_path):
    # Pins the documented gap: omitting artifact_path means artifact bytes on
    # disk are never read, even when they don't match the manifest's declared
    # digest. Callers MUST call verify_digest themselves in that case.
    key, public_keys = keypair
    artifact_path = tmp_path / "firmware.bin"
    artifact_path.write_bytes(b"tampered-bytes-on-disk")
    digest_of_something_else = hashlib.sha256(b"real-firmware-bytes").hexdigest()
    manifest = _signed(_manifest(sequence=1, artifact_sha256=digest_of_something_else), key)

    # No artifact_path passed -> passes despite the mismatched bytes sitting
    # right there on disk.
    verify_manifest(manifest, public_keys, last_sequence=0)


def test_verify_manifest_with_artifact_path_but_missing_artifact_block(keypair, tmp_path):
    key, public_keys = keypair
    artifact_path = tmp_path / "firmware.bin"
    artifact_path.write_bytes(b"anything")
    manifest = _signed(_manifest(sequence=1), key)  # no "artifact" key at all

    with pytest.raises(VerificationError, match="artifact"):
        verify_manifest(manifest, public_keys, last_sequence=0, artifact_path=artifact_path)


def test_verify_manifest_with_artifact_path_but_artifact_block_not_a_dict(keypair, tmp_path):
    key, public_keys = keypair
    artifact_path = tmp_path / "firmware.bin"
    artifact_path.write_bytes(b"anything")
    manifest = {"version": "1.0.0", "sequence": 1, "artifact": "not-a-dict"}
    manifest = _signed(manifest, key)

    with pytest.raises(VerificationError, match="artifact"):
        verify_manifest(manifest, public_keys, last_sequence=0, artifact_path=artifact_path)


def test_verify_manifest_with_artifact_path_but_no_usable_sha256(keypair, tmp_path):
    key, public_keys = keypair
    artifact_path = tmp_path / "firmware.bin"
    artifact_path.write_bytes(b"anything")
    manifest = {"version": "1.0.0", "sequence": 1, "artifact": {"sha256": 12345}}
    manifest = _signed(manifest, key)

    with pytest.raises(VerificationError, match="sha256"):
        verify_manifest(manifest, public_keys, last_sequence=0, artifact_path=artifact_path)


# ---------------------------------------------------------------------------
# Finding 2: every public function must raise VerificationError (never a bare
# AttributeError/TypeError/OSError/etc.) for malformed input, so a caller that
# catches only VerificationError doesn't crash-loop on garbage input.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_manifest", [["not", "a", "dict"], "just a string", None])
def test_non_dict_manifest_raises_verification_error_everywhere(bad_manifest, keypair):
    _, public_keys = keypair

    with pytest.raises(VerificationError):
        verify_signature(bad_manifest, public_keys)
    with pytest.raises(VerificationError):
        verify_sequence(bad_manifest, last_sequence=0)
    with pytest.raises(VerificationError):
        verify_window(bad_manifest)
    with pytest.raises(VerificationError):
        verify_manifest(bad_manifest, public_keys, last_sequence=0)


def test_missing_signature_block_raises_verification_error(keypair):
    _, public_keys = keypair
    manifest = {"version": "1.0.0", "sequence": 1}

    with pytest.raises(VerificationError, match="signature"):
        verify_signature(manifest, public_keys)


def test_non_dict_signature_block_raises_verification_error(keypair):
    _, public_keys = keypair
    manifest = {"version": "1.0.0", "sequence": 1, "signature": "not-a-dict"}

    with pytest.raises(VerificationError):
        verify_signature(manifest, public_keys)


def test_unhashable_key_id_raises_verification_error(keypair):
    key, public_keys = keypair
    manifest = _signed(_manifest(sequence=1), key)
    manifest["signature"]["key_id"] = ["not", "hashable"]

    with pytest.raises(VerificationError, match="key_id"):
        verify_signature(manifest, public_keys)


def test_invalid_base64_signature_raises_verification_error(keypair):
    key, public_keys = keypair
    manifest = _signed(_manifest(sequence=1), key)
    manifest["signature"]["sig"] = "not-valid-base64!!"

    with pytest.raises(VerificationError):
        verify_signature(manifest, public_keys)


@pytest.mark.parametrize("field", ["not_before", "expires"])
def test_non_string_timestamp_raises_verification_error(field):
    manifest = {"version": "1.0.0", "sequence": 1, field: 12345}

    with pytest.raises(VerificationError):
        verify_window(manifest)


def test_string_sequence_raises_verification_error():
    with pytest.raises(VerificationError, match="sequence"):
        verify_sequence({"sequence": "10"}, last_sequence=0)


def test_float_sequence_raises_verification_error():
    with pytest.raises(VerificationError, match="sequence"):
        verify_sequence({"sequence": 10.5}, last_sequence=0)


def test_absent_sequence_raises_verification_error():
    with pytest.raises(VerificationError, match="sequence"):
        verify_sequence({}, last_sequence=0)


def test_verify_digest_rejects_a_non_string_expected_sha256(tmp_path):
    # The docstring promises every public function raises only
    # VerificationError, and explicitly invites direct calls to this one --
    # `.lower()` on a non-str expected_sha256 must not escape as a bare
    # AttributeError.
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello")

    with pytest.raises(VerificationError):
        verify_digest(path, 12345)


def test_verify_digest_on_missing_file_raises_verification_error(tmp_path):
    missing = tmp_path / "does-not-exist.bin"

    with pytest.raises(VerificationError):
        verify_digest(missing, "0" * 64)


def test_verification_error_chains_original_cause(tmp_path):
    # The module promises the original exception stays attached via `from`,
    # so failures stay diagnosable instead of just becoming a generic message.
    missing = tmp_path / "does-not-exist.bin"

    with pytest.raises(VerificationError) as excinfo:
        verify_digest(missing, "0" * 64)

    assert isinstance(excinfo.value.__cause__, OSError)


def test_deliberate_verification_error_is_not_swallowed_or_reworded(keypair):
    # A VerificationError raised deliberately by an inner check (replay here)
    # must surface from verify_manifest with its own specific message intact,
    # not get caught and re-wrapped into something vaguer.
    key, public_keys = keypair
    manifest = _signed(_manifest(sequence=1), key)

    with pytest.raises(VerificationError, match="refusing a possible replay"):
        verify_manifest(manifest, public_keys, last_sequence=5)
