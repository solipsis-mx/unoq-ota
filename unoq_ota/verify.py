"""Manifest and artifact verification. Fail-closed, in a fixed order.

Order matters: signature first, so nothing downstream trusts attacker-chosen
fields; then the validity window; then the replay check; then (when an
artifact path is supplied) the digest. A correctly signed but *older*
manifest is a real attack -- it republishes firmware that was legitimately
signed once and later found to be bad -- which is why sequence is enforced
on-device rather than trusted from the server.

Every public function here raises only `VerificationError` for malformed
input (bad shapes, wrong types, missing files) as well as for genuine
verification failures. This matters beyond tidiness: a caller -- the OTA
agent included -- catches `VerificationError` to mark an update rejected
and poison its version. Anything that instead escapes as a bare
`AttributeError`/`TypeError`/`KeyError`/`OSError` skips that handling
entirely, and a supervised process that retries the same malformed manifest
after every restart turns a clean rejection into an infinite crash loop.
The original exception, when there is one, is always chained with `from`
so the failure stays diagnosable.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature


class VerificationError(Exception):
    """The update is not trustworthy and must not be flashed."""


def _require_dict(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise VerificationError(f"{what} must be an object, got {type(value).__name__}")
    return value


def canonical_bytes(manifest: dict) -> bytes:
    manifest = _require_dict(manifest, "manifest")
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    except TypeError as exc:
        raise VerificationError(f"manifest is not JSON-serialisable: {exc}") from exc


def verify_signature(manifest: dict, public_keys: dict) -> None:
    manifest = _require_dict(manifest, "manifest")

    if "signature" not in manifest:
        raise VerificationError("manifest has no signature block")
    block = _require_dict(manifest["signature"], "signature block")

    if block.get("alg") != "ed25519":
        raise VerificationError(f"unsupported signature alg {block.get('alg')!r}")

    key_id = block.get("key_id")
    try:
        key = public_keys.get(key_id)
    except TypeError as exc:
        raise VerificationError(f"key_id is not a usable lookup key: {key_id!r}") from exc
    if key is None:
        raise VerificationError(f"unknown key_id {key_id!r}")

    try:
        signature = base64.b64decode(block.get("sig", ""), validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise VerificationError(f"signature is not valid base64: {exc}") from exc

    payload = canonical_bytes(manifest)
    try:
        key.verify(signature, payload)
    except InvalidSignature as exc:
        raise VerificationError("signature does not match the manifest") from exc
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"signature could not be verified: {exc}") from exc


def verify_sequence(manifest: dict, last_sequence: int) -> None:
    manifest = _require_dict(manifest, "manifest")

    sequence = manifest.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise VerificationError(f"manifest has no usable sequence: {sequence!r}")

    try:
        baseline = int(last_sequence)
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"last_sequence is not usable: {last_sequence!r}") from exc

    if sequence <= baseline:
        raise VerificationError(
            f"manifest sequence {sequence} is not newer than {baseline}; "
            "refusing a possible replay"
        )


def verify_window(manifest: dict, now: datetime = None) -> None:
    manifest = _require_dict(manifest, "manifest")
    now = now or datetime.now(timezone.utc)

    for field, compare in (("not_before", "before"), ("expires", "after")):
        raw = manifest.get(field)
        if not raw:
            continue
        if not isinstance(raw, str):
            raise VerificationError(
                f"{field} must be a string timestamp, got {type(raw).__name__}"
            )
        try:
            moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise VerificationError(f"{field} is not a valid timestamp: {raw!r}") from exc
        if compare == "before" and now < moment:
            raise VerificationError(f"manifest is not valid until {raw}")
        if compare == "after" and now > moment:
            raise VerificationError(f"manifest expired at {raw}")


def verify_digest(path: Path, expected_sha256: str) -> None:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise VerificationError(f"could not read artifact at {path}: {exc}") from exc

    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise VerificationError(
            f"sha256 mismatch: expected {expected_sha256}, got {digest}"
        )


def verify_manifest(
    manifest: dict,
    public_keys: dict,
    last_sequence: int,
    now: datetime = None,
    artifact_path: Path = None,
) -> None:
    """Run the manifest checks, in fixed order: signature -> validity window
    -> sequence -> digest.

    Pass `artifact_path` to also verify the artifact's bytes against the
    manifest's declared ``artifact.sha256`` as the final step. With a path
    given, a single passing call to this function is sufficient grounds to
    trust both the manifest and the file it describes.

    *** WITHOUT `artifact_path`, THE ARTIFACT BYTES ARE NOT VERIFIED. ***
    A manifest can pass every check this function runs -- valid signature,
    inside its validity window, a fresh sequence number -- and still be
    paired with a tampered or corrupted artifact file, because nothing in
    that case ever reads the file. Callers that omit `artifact_path` MUST
    call `verify_digest` themselves, against the manifest's declared
    digest, before flashing anything the manifest describes.
    """
    manifest = _require_dict(manifest, "manifest")

    verify_signature(manifest, public_keys)
    verify_window(manifest, now=now)
    verify_sequence(manifest, last_sequence)

    if artifact_path is not None:
        artifact_block = _require_dict(manifest.get("artifact"), "manifest.artifact")
        expected_sha256 = artifact_block.get("sha256")
        if not isinstance(expected_sha256, str) or not expected_sha256:
            raise VerificationError("manifest has no usable artifact.sha256")
        verify_digest(artifact_path, expected_sha256)
