"""Manifest and artifact verification. Fail-closed, in a fixed order.

Order matters: signature first, so nothing downstream trusts attacker-chosen
fields; then the validity window; then the replay check; then (when an
artifact path is supplied) the digest. A correctly signed but *older*
manifest is a real attack -- it republishes firmware that was legitimately
signed once and later found to be bad -- which is why sequence is enforced
on-device rather than trusted from the server.

Every public function here raises only `VerificationError` for malformed
*manifest and artifact* input (bad shapes, wrong types, missing files) as
well as for genuine verification failures. This matters beyond tidiness: a
caller -- the OTA agent included -- catches `VerificationError` to mark an
update rejected and poison its version. Anything that instead escapes as a
bare `AttributeError`/`TypeError`/`KeyError`/`OSError` skips that handling
entirely, and a supervised process that retries the same malformed manifest
after every restart turns a clean rejection into an infinite crash loop.
The original exception, when there is one, is always chained with `from`
so the failure stays diagnosable.

`not_before` and `expires` timestamps must carry an explicit UTC offset
("Z" or "+HH:MM"/"-HH:MM"); a timezone-naive timestamp raises
`VerificationError` rather than being assumed to mean UTC, because `expires`
is the emergency-revocation mechanism and assuming UTC is the direction that
can silently widen a signer's intended validity window. See
`_parse_timestamp`.

That guarantee covers the manifest and the artifact bytes -- data that
arrives over the wire and must be treated as hostile. It does not extend to
`public_keys`, which comes from the caller's own trusted `load_keyring()`
(itself returning `{}` on failure): a non-dict `public_keys` is a
programming error in the caller, not malformed input, and is left to raise
its natural `AttributeError` rather than being hidden behind
`VerificationError`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature

from unoq_ota.board import FlashTarget

UNOQ_BOARD = "arduino_uno_q"


class VerificationError(Exception):
    """The update is not trustworthy and must not be flashed.

    `poisonable` is True only for failures of a *signed* manifest (wrong
    board, digest mismatch). A bad signature, stale window, or replay must
    not poison: the version string in an unsigned blob is attacker-chosen.
    """

    def __init__(self, message: str, *, poisonable: bool = False):
        super().__init__(message)
        self.poisonable = poisonable


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

    if not isinstance(last_sequence, int) or isinstance(last_sequence, bool):
        raise VerificationError(f"last_sequence is not usable: {last_sequence!r}")
    baseline = last_sequence

    if sequence <= baseline:
        raise VerificationError(
            f"manifest sequence {sequence} is not newer than {baseline}; "
            "refusing a possible replay"
        )


def _parse_timestamp(raw: str, field: str) -> datetime:
    """Parse an ISO-8601 timestamp, requiring an explicit UTC offset.

    A timezone-naive timestamp (no "Z", no "+HH:MM") is rejected rather than
    assumed to be UTC. `expires`/`not_before` are the emergency-revocation
    mechanism, and "assume UTC" is the unsafe direction to guess wrong in: a
    signer east of UTC (e.g. UTC+5:30) who means a naive value as their own
    local time gets a manifest that keeps verifying for up to ~14 hours past
    the deadline they intended (the exact offset), because assuming their
    local clock reading is already UTC pushes the assumed expiry later than
    they meant. A signer west of UTC gets the opposite error -- the assumed
    expiry lands earlier than intended, which only narrows their window
    (fail-safe, not a correctness problem). Since this routine can't tell
    which the caller meant, it declines to guess and raises instead -- the
    failure is loud, and the device just keeps running its current firmware
    until the manifest is fixed to carry an offset.
    """
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise VerificationError(f"{field} is not a valid timestamp: {raw!r}") from exc
    if moment.tzinfo is None:
        raise VerificationError(
            f"{field} has no UTC offset ({raw!r}); timestamps must be "
            "explicitly qualified (end with 'Z' or an explicit +HH:MM/-HH:MM "
            "offset) -- a naive timestamp is ambiguous about the signer's "
            "local time and cannot be safely assumed to mean UTC"
        )
    return moment


def verify_window(manifest: dict, now: Optional[datetime] = None) -> None:
    manifest = _require_dict(manifest, "manifest")
    now = now or datetime.now(timezone.utc)

    for field, compare in (("not_before", "before"), ("expires", "after")):
        if field not in manifest or manifest[field] is None:
            continue
        raw = manifest[field]
        if not isinstance(raw, str):
            raise VerificationError(
                f"{field} must be a string timestamp, got {type(raw).__name__}"
            )
        moment = _parse_timestamp(raw, field)
        if compare == "before" and now < moment:
            raise VerificationError(f"manifest is not valid until {raw}")
        if compare == "after" and now > moment:
            raise VerificationError(f"manifest expired at {raw}")


def verify_digest(path: Path, expected_sha256: str) -> None:
    if not isinstance(expected_sha256, str):
        raise VerificationError(
            f"expected_sha256 must be a string, got {type(expected_sha256).__name__}"
        )

    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise VerificationError(f"could not read artifact at {path}: {exc}") from exc

    digest = hashlib.sha256(data).hexdigest()
    if digest.lower() != expected_sha256.lower():
        raise VerificationError(
            f"sha256 mismatch: expected {expected_sha256}, got {digest}",
            poisonable=True,
        )


def verify_target(manifest: dict, target: FlashTarget) -> None:
    """Refuse a signed manifest that was not built for this board.

    Sketch header magic is shared across Arduino Zephyr boards. Without this
    check a Ventuno Q (or any other) artifact would pass validation, get
    flashed at the UNO Q offset, fail health, and burn a rollback.
    """
    manifest = _require_dict(manifest, "manifest")
    block = manifest.get("target")
    if not isinstance(block, dict):
        raise VerificationError("manifest has no target block", poisonable=True)

    board = block.get("board")
    if board != UNOQ_BOARD:
        raise VerificationError(
            f"manifest target board {board!r} is not {UNOQ_BOARD}",
            poisonable=True,
        )

    raw_offset = block.get("sketch_offset")
    try:
        if isinstance(raw_offset, str):
            offset = int(raw_offset, 0)
        elif isinstance(raw_offset, int) and not isinstance(raw_offset, bool):
            offset = raw_offset
        else:
            raise ValueError
    except (ValueError, TypeError):
        raise VerificationError(
            f"manifest has no usable target.sketch_offset: {raw_offset!r}",
            poisonable=True,
        )
    if offset != target.address:
        raise VerificationError(
            f"manifest sketch_offset 0x{offset:08x} does not match board "
            f"0x{target.address:08x}",
            poisonable=True,
        )

    size = block.get("partition_size")
    if size is not None:
        if not isinstance(size, int) or isinstance(size, bool):
            raise VerificationError(
                f"manifest has no usable target.partition_size: {size!r}",
                poisonable=True,
            )
        if size != target.max_size:
            raise VerificationError(
                f"manifest partition_size {size} does not match board {target.max_size}",
                poisonable=True,
            )

    link_mode = block.get("link_mode")
    if link_mode is not None and link_mode != "dynamic":
        raise VerificationError(
            f"unsupported link_mode {link_mode!r}",
            poisonable=True,
        )


def verify_manifest(
    manifest: dict,
    public_keys: dict,
    last_sequence: int,
    now: Optional[datetime] = None,
    artifact_path: Optional[Path] = None,
    host_payload_path: Optional[Path] = None,
    target: Optional[FlashTarget] = None,
) -> None:
    """Run the manifest checks, in fixed order: signature -> validity window
    -> sequence -> target compatibility -> digest.

    Pass `artifact_path` to also verify the artifact's bytes against the
    manifest's declared ``artifact.sha256`` as the final step. With a path
    given, a single passing call to this function is sufficient grounds to
    trust both the manifest and the file it describes.

    Pass `host_payload_path` to verify an optional host tarball against
    ``host_payload.sha256``. Omitting the path skips that digest, the same
    way omitting `artifact_path` skips the sketch digest.

    Pass `target` to refuse a signed manifest built for a different board or
    flash offset. Callers that omit it skip that check.

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
    if target is not None:
        verify_target(manifest, target)

    if artifact_path is not None:
        artifact_block = _require_dict(manifest.get("artifact"), "manifest.artifact")
        expected_sha256 = artifact_block.get("sha256")
        if not isinstance(expected_sha256, str) or not expected_sha256:
            raise VerificationError("manifest has no usable artifact.sha256", poisonable=True)
        verify_digest(artifact_path, expected_sha256)

    if host_payload_path is not None:
        host_block = _require_dict(manifest.get("host_payload"), "manifest.host_payload")
        expected_host = host_block.get("sha256")
        if not isinstance(expected_host, str) or not expected_host:
            raise VerificationError(
                "manifest has no usable host_payload.sha256", poisonable=True
            )
        verify_digest(host_payload_path, expected_host)
