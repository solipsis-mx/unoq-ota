"""A manifest polled from any static URL: S3, GitHub Releases, a web server.

Polls with jitter so a fleet of devices does not stampede the origin and
update in lockstep -- a bad version should not reach every device at once.
"""

from __future__ import annotations

import json
import logging
import math
import random
import time
from pathlib import Path

import requests

from unoq_ota.interfaces import Status, Update
from unoq_ota.preflight import MAX_PAYLOAD_BYTES

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 30.0


def require_jitter_s(jitter_s: float) -> float:
    """Reject inf/nan/negative jitter at construction, not at first poll.

    inf/nan both pass a plain `isinstance` + `< 0` check (NaN compares False
    either way), and `random.uniform(0, inf/nan)` doesn't raise -- it's
    `time.sleep` fed the result that raises, which then reads on every poll
    as an ordinary network-fetch failure. That makes a permanently dead
    device indistinguishable from a flaky link. Reject loudly where the
    misconfiguration was made.
    """
    if (
        not isinstance(jitter_s, (int, float))
        or isinstance(jitter_s, bool)
        or not math.isfinite(jitter_s)
        or jitter_s < 0
    ):
        raise ValueError(
            f"jitter_s must be a finite non-negative number, got {jitter_s!r}"
        )
    return float(jitter_s)


def download(url: str, dest: Path, session=None, max_bytes: int = MAX_PAYLOAD_BYTES) -> Path:
    """Stream a URL to disk with a hard size cap.

    Removes `dest` on any failure -- the size cap, a dropped connection, a
    timeout, a bad status -- so a truncated file is never left behind for a
    later step to pick up, and so the disk space the caller's own space
    precondition depends on isn't quietly wasted.
    """
    http = session or requests
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with http.get(url, stream=True, timeout=DEFAULT_TIMEOUT_S) as response:
            response.raise_for_status()
            with dest.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=65536):
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError(f"artifact exceeded {max_bytes} bytes")
                    handle.write(chunk)
    except Exception:
        # The cleanup unlink must never be able to supersede the original
        # failure (a ConnectionError, a size-cap ValueError, ...): a caller
        # catching a specific exception type needs to see *that* type, not
        # whatever unlink() happened to raise (e.g. PermissionError on a
        # locked-down directory). Guard it in its own except so a cleanup
        # failure can only be logged, never propagate in place of the cause.
        try:
            dest.unlink(missing_ok=True)
        except OSError as cleanup_exc:
            log.warning(
                "failed to remove partial download at %s: %s", dest, cleanup_exc
            )
        raise
    return dest


class HttpManifestSource:
    def __init__(self, manifest_url: str, poisoned=None, session=None, jitter_s: float = 30.0):
        self.manifest_url = manifest_url
        self._poisoned = poisoned or (lambda version: False)
        self._session = session or requests
        self.jitter_s = require_jitter_s(jitter_s)

    def check(self):
        try:
            if self.jitter_s:
                time.sleep(random.uniform(0, self.jitter_s))
        except Exception as exc:
            # Kept separate from the fetch below so a jitter misconfiguration
            # (e.g. jitter_s mutated to something nonsensical after
            # construction) is never reported under the same "manifest fetch
            # failed" message as a genuine network outage -- the two need
            # different responses from whoever is triaging.
            log.warning("jitter sleep failed: %s", exc)
            return None

        try:
            response = self._session.get(self.manifest_url, timeout=DEFAULT_TIMEOUT_S)
            response.raise_for_status()
            raw = response.content
            manifest = json.loads(raw)
            version = str(manifest["version"])
            sequence = int(manifest["sequence"])
        except Exception as exc:
            log.warning("manifest fetch failed: %s", exc)
            return None

        # See unoq_ota/sources/local.py's check() for why this is guarded
        # separately from the fetch above: `poisoned` is caller-supplied,
        # typically backed by persisted state on disk, and is the
        # load-bearing guard against a flash -> fail health -> roll back ->
        # re-offer loop -- it must not be able to make check() raise.
        try:
            poisoned = self._poisoned(version)
        except Exception as exc:
            log.warning("poison-list check failed for version %s: %s", version, exc)
            return None

        if poisoned:
            return None

        return Update(
            version=version, sequence=sequence, manifest=manifest, raw_manifest=raw
        )

    def report(self, update: Update, status: Status, detail: str) -> None:
        log.info("update %s -> %s (%s)", update.version, status.value, detail)
