#!/usr/bin/env python3
"""Build and sign a manifest for a compiled sketch artifact."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from unoq_ota.artifact import load_artifact          # noqa: E402
from unoq_ota.verify import canonical_bytes          # noqa: E402


def _require_utc_qualified(raw: str, flag: str) -> str:
    """Refuse a `--not-before`/`--expires` value with no explicit UTC offset.

    unoq_ota.verify now rejects a timezone-naive `not_before`/`expires`
    outright (VerificationError) rather than assuming UTC -- assuming UTC is
    the direction that can silently widen a signer's intended validity
    window, and `expires` is the emergency-revocation mechanism. A naive
    value passed through here would produce a manifest every device refuses,
    so this tool refuses to sign one instead of letting the operator publish
    something that will fail closed on every device rather than at build
    time, where the mistake is cheap to fix.
    """
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SystemExit(f"--{flag} is not a valid ISO-8601 timestamp: {raw!r} ({exc})")
    if moment.tzinfo is None:
        raise SystemExit(
            f"--{flag} has no UTC offset ({raw!r}); every device rejects a naive "
            f"timestamp outright, so refusing to sign one -- end it with 'Z' or an "
            f"explicit +HH:MM/-HH:MM offset"
        )
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--sketch-offset", default="0x08100000")
    parser.add_argument(
        "--not-before",
        default=None,
        help="ISO-8601 timestamp with explicit UTC offset (e.g. 2026-09-05T00:00:00Z); "
        "manifest is invalid before this",
    )
    parser.add_argument(
        "--expires",
        default=None,
        help="ISO-8601 timestamp with explicit UTC offset; manifest is invalid after "
        "this -- the emergency-revocation mechanism",
    )
    parser.add_argument("--out", type=Path, default=Path("manifest.json"))
    args = parser.parse_args()

    # Validate before signing: never sign an artifact that would be refused.
    validated = load_artifact(args.artifact)

    manifest = {
        "schema": 1,
        "version": args.version,
        "sequence": args.sequence,
        "artifact": {
            "url": args.url,
            "size": validated.size,
            "sha256": validated.sha256,
        },
        "target": {
            "board": "arduino_uno_q",
            "link_mode": "dynamic",
            # sketch_offset is descriptive only: nothing on the device side
            # reads it back or checks it against the board's actual flash
            # target (unoq_ota.board.resolve_flash_target() is the sole
            # source of truth there), so there is nothing to validate this
            # against at sign time beyond the CLI default.
            "sketch_offset": args.sketch_offset,
        },
    }

    if args.not_before is not None:
        manifest["not_before"] = _require_utc_qualified(args.not_before, "not-before")
    if args.expires is not None:
        manifest["expires"] = _require_utc_qualified(args.expires, "expires")

    key = serialization.load_pem_private_key(
        args.private_key.read_bytes(), password=None
    )
    manifest["signature"] = {
        "alg": "ed25519",
        "key_id": args.key_id,
        "sig": base64.b64encode(key.sign(canonical_bytes(manifest))).decode(),
    }

    args.out.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"signed {validated.size} bytes -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
