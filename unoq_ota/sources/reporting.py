"""Wrap an UpdateSource so every report is also written to the event journal."""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class ReportingSource:
    def __init__(self, inner, events):
        self._inner = inner
        self._events = events

    def check(self):
        return self._inner.check()

    def report(self, update, status, detail: str) -> None:
        try:
            self._events.record(
                kind="update",
                version=getattr(update, "version", None),
                status=getattr(status, "value", status),
                detail=detail,
            )
        except Exception as exc:  # noqa: BLE001 - observability must not fail an update
            log.warning("event record failed: %s", exc)
        self._inner.report(update, status, detail)
