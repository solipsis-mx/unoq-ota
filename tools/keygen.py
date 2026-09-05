#!/usr/bin/env python3
"""Generate an ed25519 signing keypair.

The private key never leaves your build machine. Only the public key goes on
devices. No keys are committed to this repository.
"""

from __future__ import annotations

import argparse
import base64
import os
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

    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Opened at 0600 from the moment it exists, rather than written with the
    # default umask (often 0644) and chmod'd after -- the write-then-chmod
    # sequence leaves the key briefly world-readable, and O_EXCL doubles as
    # the refusal to clobber an existing key.
    try:
        fd = os.open(private_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(f"refusing to overwrite existing private key {private_path}")
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)

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
