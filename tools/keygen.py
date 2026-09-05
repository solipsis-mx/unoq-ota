#!/usr/bin/env python3
"""Generate an ed25519 signing keypair.

The private key never leaves your build machine. Only the public key goes on
devices. No keys are committed to this repository.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    args = parser.parse_args()

    key = Ed25519PrivateKey.generate()
    private_path = args.out_dir / f"{args.key_id}.private.pem"
    public_path = args.out_dir / f"{args.key_id}.public.b64"

    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)

    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_path.write_text(base64.b64encode(raw).decode() + "\n")

    print(f"private key: {private_path}  (never commit or copy to a device)")
    print(f"public key:  {public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
