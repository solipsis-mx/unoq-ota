"""A manifest polled from any static URL: S3, GitHub Releases, a web server.

Polls with jitter so a fleet of devices does not stampede the origin and
update in lockstep -- a bad version should not reach every device at once.
"""

from __future__ import annotations

import json
import logging
import random
import time
from pathlib import Path

import requests

from unoq_ota.interfaces import Status, Update

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 30.0


def download(url: str, dest: Path, session=None, max_bytes: int = 4_000_000) -> Path:
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
        dest.unlink(missing_ok=True)
        raise
    return dest


class HttpManifestSource:
    def __init__(self, manifest_url: str, poisoned=None, session=None, jitter_s: float = 30.0):
        if not isinstance(jitter_s, (int, float)) or isinstance(jitter_s, bool) or jitter_s < 0:
            raise ValueError(f"jitter_s must be a non-negative number, got {jitter_s!r}")
        self.manifest_url = manifest_url
        self._poisoned = poisoned or (lambda version: False)
        self._session = session or requests
        self.jitter_s = jitter_s

    def check(self):
        try:
            if self.jitter_s:
                time.sleep(random.uniform(0, self.jitter_s))
            response = self._session.get(self.manifest_url, timeout=DEFAULT_TIMEOUT_S)
            response.raise_for_status()
            raw = response.content
            manifest = json.loads(raw)
            version = str(manifest["version"])
            sequence = int(manifest["sequence"])
        except Exception as exc:
            log.warning("manifest fetch failed: %s", exc)
            return None

        if self._poisoned(version):
            return None

        return Update(
            version=version, sequence=sequence, manifest=manifest, raw_manifest=raw
        )

    def report(self, update: Update, status: Status, detail: str) -> None:
        log.info("update %s -> %s (%s)", update.version, status.value, detail)
