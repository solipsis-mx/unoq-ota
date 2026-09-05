"""Manifest and artifact verification. Fail-closed, in a fixed order.

Order matters: signature first, so nothing downstream trusts attacker-chosen
fields; then the replay check; then the digest. A correctly signed but *older*
manifest is a real attack -- it republishes firmware that was legitimately
signed once and later found to be bad -- which is why sequence is enforced
on-device rather than trusted from the server.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature


class VerificationError(Exception):
    """The update is not trustworthy and must not be flashed."""


def canonical_bytes(manifest: dict) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify_signature(manifest: dict, public_keys: dict) -> None:
    block = manifest.get("signature") or {}
    if block.get("alg") != "ed25519":
        raise VerificationError(f"unsupported signature alg {block.get('alg')!r}")

    key_id = block.get("key_id")
    key = public_keys.get(key_id)
    if key is None:
        raise VerificationError(f"unknown key_id {key_id!r}")

    try:
        signature = base64.b64decode(block.get("sig", ""), validate=True)
    except Exception:
        raise VerificationError("signature is not valid base64")

    try:
        key.verify(signature, canonical_bytes(manifest))
    except InvalidSignature:
        raise VerificationError("signature does not match the manifest")


def verify_sequence(manifest: dict, last_sequence: int) -> None:
    try:
        sequence = int(manifest.get("sequence"))
    except (TypeError, ValueError):
        raise VerificationError("manifest has no usable sequence")
    if sequence <= int(last_sequence):
        raise VerificationError(
            f"manifest sequence {sequence} is not newer than {last_sequence}; "
            "refusing a possible replay"
        )


def verify_window(manifest: dict, now: datetime = None) -> None:
    now = now or datetime.now(timezone.utc)
    for field, compare in (("not_before", "before"), ("expires", "after")):
        raw = manifest.get(field)
        if not raw:
            continue
        try:
            moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            raise VerificationError(f"{field} is not a valid timestamp: {raw!r}")
        if compare == "before" and now < moment:
            raise VerificationError(f"manifest is not valid until {raw}")
        if compare == "after" and now > moment:
            raise VerificationError(f"manifest expired at {raw}")


def verify_digest(path: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise VerificationError(
            f"sha256 mismatch: expected {expected_sha256}, got {digest}"
        )


def verify_manifest(
    manifest: dict, public_keys: dict, last_sequence: int, now: datetime = None
) -> None:
    verify_signature(manifest, public_keys)
    verify_window(manifest, now=now)
    verify_sequence(manifest, last_sequence)
