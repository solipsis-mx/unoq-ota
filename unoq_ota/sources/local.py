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
        except Exception as exc:
            # Broad on purpose: `manifest.json` is attacker-influenced content
            # (the design treats every source as untrusted), and malformed
            # content can trigger failure modes far outside the "flaky disk"
            # tuple this used to be -- e.g. a pathologically nested JSON array
            # blows the interpreter's recursion limit and raises
            # RecursionError, a RuntimeError subclass. check() must never
            # raise, so nothing here is allowed to escape uncaught.
            log.warning("ignoring unreadable manifest at %s: %s", path, exc)
            return None

        # The poison-list predicate is caller-supplied and in practice reads
        # persisted state from disk -- exactly the kind of I/O the block
        # above is guarded against. Give it its own try/except (rather than
        # folding it into the block above) so a poison-list failure is
        # logged distinctly from a malformed manifest, which matters for
        # triage: this predicate is the load-bearing guard against a
        # flash -> fail health -> roll back -> re-offer loop, so an operator
        # needs to be able to tell "the manifest was garbage" apart from
        # "the poison list itself is broken" at a glance.
        try:
            poisoned = self._poisoned(version)
        except Exception as exc:
            log.warning("poison-list check failed for version %s: %s", version, exc)
            return None

        if poisoned:
            log.info("skipping poisoned version %s", version)
            return None

        return Update(
            version=version, sequence=sequence, manifest=manifest, raw_manifest=raw
        )

    def report(self, update: Update, status: Status, detail: str) -> None:
        log.info("update %s -> %s (%s)", update.version, status.value, detail)
