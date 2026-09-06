"""Append-only OTA event journal.

Local NDJSON is the durable record an operator can read after a power cut
or a dead bearer. Optional HTTP POST is best-effort and must never be able
to fail an update: a device with no connectivity still has to flash, roll
back, and recover at boot.

Unsent lines are tracked by a sibling offset file so a failed POST is
retried on the next record, which is what a CAT-4 link actually needs.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

JOURNAL_NAME = "journal.ndjson"
POST_TIMEOUT_S = 5.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class EventLog:
    def __init__(
        self,
        path: Path,
        *,
        device_id: str,
        report_url: str | None = None,
        session=None,
        post_timeout_s: float = POST_TIMEOUT_S,
    ):
        self.path = Path(path)
        self.device_id = device_id
        self.report_url = report_url
        self._session = session
        self.post_timeout_s = post_timeout_s
        self._offset_path = self.path.with_name(self.path.name + ".offset")

    def record(self, **fields) -> None:
        """Append one event, then try to POST anything still unsent.

        Never raises. A full disk or a dead bearer is logged and ignored:
        the flash path must not depend on observability.
        """
        event = {"ts": _utc_now(), "device": self.device_id, **fields}
        try:
            self._append(event)
        except Exception as exc:  # noqa: BLE001 - journal must not fail the agent
            log.warning("journal append failed: %s", exc)
            return
        try:
            self.flush_unsent()
        except Exception as exc:  # noqa: BLE001
            log.warning("journal flush failed: %s", exc)

    def last(self) -> dict | None:
        try:
            lines = self.path.read_text().splitlines()
        except OSError:
            return None
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    def flush_unsent(self) -> None:
        if not self.report_url:
            return
        try:
            data = self.path.read_bytes()
        except OSError:
            return
        offset = self._read_offset()
        if offset > len(data):
            offset = 0
        rest = data[offset:]
        start = 0
        while True:
            nl = rest.find(b"\n", start)
            if nl < 0:
                break
            raw = rest[start:nl]
            start = nl + 1
            new_offset = offset + start
            try:
                event = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._write_offset(new_offset)
                continue
            self._post(event)
            self._write_offset(new_offset)

    def _append(self, event: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(event, separators=(",", ":")) + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

    def _post(self, event: dict) -> None:
        session = self._session
        if session is None:
            import requests

            session = requests
        response = session.post(
            self.report_url,
            json=event,
            timeout=self.post_timeout_s,
            headers={"Content-Type": "application/json"},
        )
        if hasattr(response, "raise_for_status"):
            response.raise_for_status()

    def _read_offset(self) -> int:
        try:
            return max(0, int(self._offset_path.read_text().strip()))
        except (OSError, ValueError):
            return 0

    def _write_offset(self, offset: int) -> None:
        self._offset_path.parent.mkdir(parents=True, exist_ok=True)
        self._offset_path.write_text(str(int(offset)))
