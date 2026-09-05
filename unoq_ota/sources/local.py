"""A manifest read from a directory. For development, bench work, and
air-gapped deployments where updates arrive by hand."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from unoq_ota.interfaces import Status, Update

log = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"


class LocalFileSource:
    def __init__(self, directory: Path, poisoned=None):
        self.directory = Path(directory)
        self._poisoned = poisoned or (lambda version: False)

    def check(self):
        path = self.directory / MANIFEST_NAME
        try:
            if not path.is_file():
                return None
            raw = path.read_bytes()
            manifest = json.loads(raw)
            version = str(manifest["version"])
            sequence = int(manifest["sequence"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("ignoring unreadable manifest at %s: %s", path, exc)
            return None

        if self._poisoned(version):
            log.info("skipping poisoned version %s", version)
            return None

        return Update(
            version=version, sequence=sequence, manifest=manifest, raw_manifest=raw
        )

    def report(self, update: Update, status: Status, detail: str) -> None:
        log.info("update %s -> %s (%s)", update.version, status.value, detail)
