"""The device's trust store.

A keyring rather than a single key, on purpose. Rotating a lone baked-in key
means physically visiting every device -- exactly the cost this project exists
to avoid. Ship several keys with overlapping validity so a rotation can happen
over the air.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

log = logging.getLogger(__name__)

DEFAULT_KEYRING_DIR = Path("/etc/unoq-ota/keys")


def load_keyring(directory: Path) -> dict[str, Ed25519PublicKey]:
    """Load every `<key_id>.public.b64` file in `directory` into a mapping.

    A missing directory is not an error -- a fresh device or a bench setup
    without a keyring provisioned yet simply verifies nothing, which the
    caller (an empty keyring rejects every manifest) already treats safely.
    One unreadable or malformed key file is skipped with a warning rather
    than aborting the whole load: an operator's typo in a new key must not
    be able to take every other, already-working key down with it.
    """
    directory = Path(directory)
    if not directory.is_dir():
        log.warning("no keyring directory at %s; no updates can be verified", directory)
        return {}

    keys: dict[str, Ed25519PublicKey] = {}
    for path in sorted(directory.glob("*.public.b64")):
        key_id = path.name[: -len(".public.b64")]
        try:
            raw = base64.b64decode(path.read_text().strip(), validate=True)
            keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:  # noqa: BLE001 - one bad key file must not take down the rest
            log.warning("ignoring unreadable public key %s: %s", path, exc)
    return keys
