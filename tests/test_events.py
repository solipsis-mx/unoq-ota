"""Append-only OTA event journal and best-effort upstream POST.

An integrator who published a firmware needs to know whether the device
committed, rolled back, or recovered at boot. Local NDJSON is the durable
record; HTTP POST is best-effort and must never be able to fail an update.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unoq_ota.events import EventLog, JOURNAL_NAME
from unoq_ota.interfaces import Status, Update
from unoq_ota.sources.reporting import ReportingSource


class FakeSession:
    def __init__(self, fail_times=0):
        self.posts = []
        self.fail_times = fail_times

    def post(self, url, json=None, timeout=None, headers=None):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise ConnectionError("bearer down")
        self.posts.append({"url": url, "json": json, "timeout": timeout})

        class _Response:
            def raise_for_status(self):
                return None

        return _Response()


def test_record_appends_one_json_line(tmp_path):
    log = EventLog(tmp_path / JOURNAL_NAME, device_id="unoq2")
    log.record(kind="update", version="1.0.0", status="committed", detail="healthy")

    lines = (tmp_path / JOURNAL_NAME).read_text().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["device"] == "unoq2"
    assert row["kind"] == "update"
    assert row["version"] == "1.0.0"
    assert row["status"] == "committed"
    assert row["detail"] == "healthy"
    assert "T" in row["ts"]


def test_record_does_not_raise_when_the_journal_cannot_be_written(tmp_path, monkeypatch):
    log = EventLog(tmp_path / JOURNAL_NAME, device_id="unoq2")

    def _raise(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", _raise)
    log.record(kind="update", version="x", status="rejected", detail="nope")


def test_posts_the_event_when_a_report_url_is_set(tmp_path):
    session = FakeSession()
    log = EventLog(
        tmp_path / JOURNAL_NAME,
        device_id="unoq2",
        report_url="http://example.invalid/ota",
        session=session,
    )
    log.record(kind="update", version="1.0.0", status="committed", detail="healthy")

    assert len(session.posts) == 1
    posted = session.posts[0]
    assert posted["url"] == "http://example.invalid/ota"
    assert posted["json"]["status"] == "committed"
    assert posted["json"]["device"] == "unoq2"
    assert posted["timeout"] == 5.0


def test_a_failed_post_does_not_raise_and_is_retried_on_the_next_record(tmp_path):
    session = FakeSession(fail_times=1)
    log = EventLog(
        tmp_path / JOURNAL_NAME,
        device_id="unoq2",
        report_url="http://example.invalid/ota",
        session=session,
    )
    log.record(kind="update", version="1.0.0", status="flashing", detail="writing")
    log.record(kind="update", version="1.0.0", status="committed", detail="healthy")

    assert [p["json"]["status"] for p in session.posts] == ["flashing", "committed"]


def test_last_returns_the_most_recent_event(tmp_path):
    log = EventLog(tmp_path / JOURNAL_NAME, device_id="unoq2")
    log.record(kind="update", version="1", status="flashing", detail="a")
    log.record(kind="reconcile", action="reflashed", image="current.bin", healthy=True)

    last = log.last()
    assert last["kind"] == "reconcile"
    assert last["action"] == "reflashed"
    assert last["image"] == "current.bin"
    assert last["healthy"] is True


def test_last_returns_none_when_the_journal_is_missing(tmp_path):
    log = EventLog(tmp_path / JOURNAL_NAME, device_id="unoq2")
    assert log.last() is None


def test_reporting_source_records_then_delegates(tmp_path):
    inner_reports = []

    class Inner:
        def check(self):
            return Update(version="1.0.0", sequence=1, manifest={}, raw_manifest=b"{}")

        def report(self, update, status, detail):
            inner_reports.append((update.version, status, detail))

    events = EventLog(tmp_path / JOURNAL_NAME, device_id="board")
    source = ReportingSource(Inner(), events)
    update = source.check()
    source.report(update, Status.COMMITTED, "healthy")

    assert inner_reports == [("1.0.0", Status.COMMITTED, "healthy")]
    row = events.last()
    assert row["kind"] == "update"
    assert row["version"] == "1.0.0"
    assert row["status"] == "committed"
    assert row["detail"] == "healthy"


def test_reporting_source_still_delegates_when_the_journal_raises(tmp_path):
    inner_reports = []

    class Inner:
        def report(self, update, status, detail):
            inner_reports.append(status)

    class BrokenLog:
        def record(self, **kwargs):
            raise OSError("journal broken")

    source = ReportingSource(Inner(), BrokenLog())
    source.report(
        Update(version="1", sequence=1, manifest={}, raw_manifest=b""),
        Status.REJECTED,
        "bad sig",
    )
    assert inner_reports == [Status.REJECTED]
