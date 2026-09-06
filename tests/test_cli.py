"""Tests for the composition root: unoq_ota.cli.

The CLI is the one place that wires a source, the gate, health checks and
the state store into a running Agent. Everything it touches that would open
a socket or drive real hardware (Agent, resolve_flash_target, download) is
replaced with a fake or a monkeypatch here -- nothing in this file makes a
network request or reads real board state.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from unoq_ota import cli
from unoq_ota.board import FlashTarget
from unoq_ota.state import Phase, StateStore


def _write_public_key(directory, key_id, raw: bytes | None = None) -> Ed25519PrivateKey:
    directory.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    if raw is None:
        raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    (directory / f"{key_id}.public.b64").write_text(base64.b64encode(raw).decode())
    return key


def _manifest(version="1.0.0", sequence=1):
    return {
        "schema": 1,
        "version": version,
        "sequence": sequence,
        "artifact": {"url": "file:///tmp/x.bin", "size": 10, "sha256": "0" * 64},
        "signature": {"alg": "ed25519", "key_id": "k1", "sig": ""},
    }


# ---------------------------------------------------------------------------
# _load_public_keys
# ---------------------------------------------------------------------------


def test_load_public_keys_returns_a_usable_mapping(tmp_path):
    _write_public_key(tmp_path, "k1")

    keys = cli._load_public_keys(tmp_path)

    assert set(keys) == {"k1"}
    assert isinstance(keys["k1"], Ed25519PublicKey)


def test_load_public_keys_tolerates_a_missing_directory(tmp_path):
    assert cli._load_public_keys(tmp_path / "does-not-exist") == {}


def test_load_public_keys_skips_a_garbage_key_file_without_crashing(tmp_path):
    _write_public_key(tmp_path, "good")
    # Valid base64, but not 32 bytes -- Ed25519PublicKey.from_public_bytes
    # rejects it. A typo in one operator's key file must not take every
    # other key down with it.
    (tmp_path / "bad.public.b64").write_text(base64.b64encode(b"too-short").decode())

    keys = cli._load_public_keys(tmp_path)

    assert set(keys) == {"good"}


# ---------------------------------------------------------------------------
# _fetch
# ---------------------------------------------------------------------------


def test_fetch_dispatches_http_scheme_to_download(monkeypatch, tmp_path):
    calls = []

    def fake_download(url, dest, max_bytes=None):
        calls.append((url, dest))
        dest.write_bytes(b"payload")

    monkeypatch.setattr(cli, "download", fake_download)
    dest = tmp_path / "out.bin"

    cli._fetch("http://example.invalid/a.bin", dest, None)

    assert calls == [("http://example.invalid/a.bin", dest)]
    assert dest.read_bytes() == b"payload"


def test_fetch_dispatches_https_scheme_to_download(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        cli, "download", lambda url, dest, max_bytes=None: calls.append((url, dest))
    )
    dest = tmp_path / "out.bin"

    cli._fetch("https://example.invalid/a.bin", dest, None)

    assert calls == [("https://example.invalid/a.bin", dest)]


def test_fetch_reads_a_file_scheme_url_from_disk(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"hello")
    dest = tmp_path / "out.bin"

    cli._fetch(f"file://{src}", dest, None)

    assert dest.read_bytes() == b"hello"


def test_fetch_reads_a_bare_absolute_path_from_disk(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"hello")
    dest = tmp_path / "out.bin"

    cli._fetch(str(src), dest, None)

    assert dest.read_bytes() == b"hello"


def test_fetch_resolves_a_bare_relative_path_against_source_dir(tmp_path):
    source_dir = tmp_path / "srcdir"
    source_dir.mkdir()
    (source_dir / "a.bin").write_bytes(b"world")
    dest = tmp_path / "out.bin"

    cli._fetch("a.bin", dest, source_dir)

    assert dest.read_bytes() == b"world"


def test_fetch_raises_a_clear_error_on_an_unsupported_scheme(tmp_path):
    # s3://... used to be silently treated as a literal filesystem path,
    # failing safely ("download failed") but hiding the real cause.
    dest = tmp_path / "out.bin"

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        cli._fetch("s3://bucket/key", dest, None)


# ---------------------------------------------------------------------------
# _run -- the composition root itself.
#
# Agent and resolve_flash_target are replaced with fakes: Agent because
# constructing the real one and calling run_once() would exercise fetch,
# verify, flash and health-check machinery entirely out of scope for a CLI
# wiring test, and resolve_flash_target because it reads real Arduino
# installation state from disk and this test must not depend on what is or
# isn't installed on the machine running the suite.
# ---------------------------------------------------------------------------


def _fake_target(core_root=None):
    return FlashTarget(address=0x08100000, max_size=786432, core_version="1.0.0")


def _patch_agent(monkeypatch, captured, run_once=lambda: Phase.IDLE):
    class FakeAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run_once(self):
            return run_once()

    monkeypatch.setattr(cli, "Agent", FakeAgent)


def _run_args(tmp_path, **overrides):
    defaults = dict(
        state_dir=tmp_path / "state",
        keys_dir=tmp_path / "keys",
        source="local",
        source_dir=tmp_path / "src",
        manifest_url=None,
        poll_interval=0.0,
        jitter=0.0,
        once=True,
        report_url=None,
        device_id=None,
        host_dir=None,
        host_unit=None,
        core_root=None,
        max_payload_bytes=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_run_wires_the_poison_predicate_to_the_agents_own_state_dir(monkeypatch, tmp_path):
    state_dir = tmp_path / "state"
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "manifest.json").write_text(json.dumps(_manifest(version="bad")))

    # Poison "bad" through a *separate* StateStore instance pointed at the
    # same directory the agent will use -- StateStore re-reads the file on
    # every call, so this must be visible to the source's own predicate.
    StateStore(state_dir / "state.json").poison("bad")

    captured: dict = {}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    _patch_agent(monkeypatch, captured)

    args = _run_args(tmp_path, state_dir=state_dir, source_dir=source_dir)
    assert cli._run(args, argparse.ArgumentParser()) == 0

    source = captured["source"]
    assert source.check() is None


def test_run_passes_a_working_fetch_for_the_local_source(monkeypatch, tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "manifest.json").write_text(json.dumps(_manifest()))
    (source_dir / "artifact.bin").write_bytes(b"payload")

    captured: dict = {}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    _patch_agent(monkeypatch, captured)

    args = _run_args(tmp_path, source_dir=source_dir)
    assert cli._run(args, argparse.ArgumentParser()) == 0

    dest = tmp_path / "fetched.bin"
    captured["fetch"]("artifact.bin", dest)
    assert dest.read_bytes() == b"payload"


def test_run_errors_clearly_when_local_source_missing_source_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    args = _run_args(tmp_path, source_dir=None)
    parser = argparse.ArgumentParser()

    with pytest.raises(SystemExit):
        cli._run(args, parser)


def test_run_errors_clearly_when_http_source_missing_manifest_url(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    args = _run_args(tmp_path, source="http", source_dir=None, manifest_url=None)
    parser = argparse.ArgumentParser()

    with pytest.raises(SystemExit):
        cli._run(args, parser)


def test_run_once_runs_a_single_cycle_and_returns_without_sleeping(monkeypatch, tmp_path):
    calls = {"run_once": 0, "sleep": 0}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)

    def run_once():
        calls["run_once"] += 1
        return Phase.IDLE

    captured: dict = {}
    _patch_agent(monkeypatch, captured, run_once=run_once)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: calls.__setitem__("sleep", calls["sleep"] + 1))

    args = _run_args(tmp_path, once=True)
    assert cli._run(args, argparse.ArgumentParser()) == 0

    assert calls == {"run_once": 1, "sleep": 0}


def test_poll_loop_paces_itself_with_sleep_between_cycles(monkeypatch, tmp_path):
    # The loop has no built-in stop condition other than --once, so it is
    # bounded here by making the second sleep() call raise -- proving the
    # loop calls run_once() then sleeps rather than spinning hot, and that a
    # caller-side interrupt of sleep() (a real SIGTERM in production) is what
    # actually stops it.
    calls = {"run_once": 0, "sleep": 0}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)

    def run_once():
        calls["run_once"] += 1
        return Phase.IDLE

    class _StopTheLoop(Exception):
        pass

    def fake_sleep(seconds):
        calls["sleep"] += 1
        raise _StopTheLoop()

    captured: dict = {}
    _patch_agent(monkeypatch, captured, run_once=run_once)
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)

    args = _run_args(tmp_path, once=False)
    with pytest.raises(_StopTheLoop):
        cli._run(args, argparse.ArgumentParser())

    assert calls == {"run_once": 1, "sleep": 1}


# ---------------------------------------------------------------------------
# main() -- argument parsing and exit codes.
# ---------------------------------------------------------------------------


def test_main_help_exits_cleanly():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0


def test_main_run_help_exits_cleanly():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["run", "--help"])
    assert exc_info.value.code == 0


def test_reconcile_builds_an_identity_agnostic_health_check(monkeypatch, tmp_path):
    captured = {}

    def fake_reconcile(state_dir, health, target):
        captured["expected_version"] = health.expected_version
        from unoq_ota.reconciler import ReconcileResult

        return ReconcileResult(healthy=True, action="none")

    monkeypatch.setattr(cli, "reconcile", fake_reconcile)
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)

    assert cli.main(["--state-dir", str(tmp_path), "reconcile"]) == 0
    assert captured["expected_version"] is None


def test_main_run_without_required_args_exits_nonzero_naming_them(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["run"])

    assert exc_info.value.code != 0
    stderr = capsys.readouterr().err
    assert "--source" in stderr
    assert "--keys-dir" in stderr


def test_status_json_reads_state_and_the_journal(tmp_path, capsys):
    from unoq_ota.events import EventLog, JOURNAL_NAME
    from unoq_ota.state import Phase, State

    store = StateStore(tmp_path / "state.json")
    store.save(
        State(
            phase=Phase.COMMITTED,
            version="bench-wifi-1",
            committed_version="bench-wifi-1",
            sequence=1,
        )
    )
    EventLog(tmp_path / JOURNAL_NAME, device_id="board-1").record(
        kind="update", version="bench-wifi-1", status="committed", detail="healthy"
    )

    assert cli.main(["--state-dir", str(tmp_path), "--device-id", "board-1", "status", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["device"] == "board-1"
    assert payload["phase"] == "committed"
    assert payload["committed_version"] == "bench-wifi-1"
    assert payload["last_event"]["status"] == "committed"


def test_reconcile_records_an_event_in_the_journal(monkeypatch, tmp_path):
    from unoq_ota.events import JOURNAL_NAME
    from unoq_ota.reconciler import ReconcileResult

    def fake_reconcile(state_dir, health, target):
        return ReconcileResult(healthy=True, action="reflashed", image="current.bin")

    monkeypatch.setattr(cli, "reconcile", fake_reconcile)
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)

    assert cli.main(["--state-dir", str(tmp_path), "--device-id", "board-1", "reconcile"]) == 0
    lines = (tmp_path / JOURNAL_NAME).read_text().splitlines()
    row = json.loads(lines[-1])
    assert row["kind"] == "reconcile"
    assert row["action"] == "reflashed"
    assert row["image"] == "current.bin"
    assert row["healthy"] is True


def test_run_wraps_the_source_so_reports_land_in_the_journal(monkeypatch, tmp_path):
    from unoq_ota.events import JOURNAL_NAME
    from unoq_ota.interfaces import Status, Update
    from unoq_ota.sources.local import LocalFileSource

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "manifest.json").write_text(json.dumps(_manifest()))
    captured: dict = {}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    _patch_agent(monkeypatch, captured)

    args = _run_args(
        tmp_path,
        source_dir=source_dir,
        device_id="board-1",
        report_url=None,
    )
    assert cli._run(args, argparse.ArgumentParser()) == 0

    source = captured["source"]
    assert not isinstance(source, LocalFileSource)
    update = Update(version="1.0.0", sequence=1, manifest={}, raw_manifest=b"{}")
    source.report(update, Status.COMMITTED, "healthy")
    row = json.loads((tmp_path / "state" / JOURNAL_NAME).read_text().splitlines()[-1])
    assert row["status"] == "committed"
    assert row["device"] == "board-1"


# ---------------------------------------------------------------------------
# --core-root -- pointing the agent at an Arduino installation that is not
# under the running account's home. Without it the only lever is HOME, which
# forces a unit file to name one distribution's interactive user.
# ---------------------------------------------------------------------------


def _recording_target(seen):
    def resolve(core_root=None):
        seen.append(core_root)
        return _fake_target()

    return resolve


def test_core_root_flag_reaches_the_flash_target_resolver(monkeypatch, tmp_path, capsys):
    seen = []
    monkeypatch.setattr(cli, "resolve_flash_target", _recording_target(seen))

    assert cli.main(["--core-root", str(tmp_path), "target"]) == 0
    assert seen == [tmp_path]


def test_core_root_defaults_to_the_environment(monkeypatch, tmp_path, capsys):
    seen = []
    monkeypatch.setattr(cli, "resolve_flash_target", _recording_target(seen))
    monkeypatch.setenv("UNOQ_OTA_CORE_ROOT", str(tmp_path))

    assert cli.main(["target"]) == 0
    assert seen == [tmp_path]


def test_core_root_is_unset_by_default(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(cli, "resolve_flash_target", _recording_target(seen))
    monkeypatch.delenv("UNOQ_OTA_CORE_ROOT", raising=False)

    assert cli.main(["target"]) == 0
    assert seen == [None]


def test_reconcile_honours_the_core_root(monkeypatch, tmp_path):
    from unoq_ota.reconciler import ReconcileResult

    seen = []
    monkeypatch.setattr(cli, "resolve_flash_target", _recording_target(seen))
    monkeypatch.setattr(
        cli,
        "reconcile",
        lambda state_dir, health, target: ReconcileResult(healthy=True, action="none"),
    )

    core_root = tmp_path / "core"
    assert cli.main(["--state-dir", str(tmp_path), "--core-root", str(core_root), "reconcile"]) == 0
    assert seen == [core_root]


def test_run_honours_the_core_root(monkeypatch, tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "manifest.json").write_text(json.dumps(_manifest()))

    seen = []
    captured: dict = {}
    monkeypatch.setattr(cli, "resolve_flash_target", _recording_target(seen))
    _patch_agent(monkeypatch, captured)

    core_root = tmp_path / "core"
    args = _run_args(tmp_path, source_dir=source_dir, core_root=core_root)
    assert cli._run(args, argparse.ArgumentParser()) == 0
    assert seen == [core_root]


# ---------------------------------------------------------------------------
# --max-payload-bytes -- one knob for "how big may a payload be". A sketch is
# bounded by its partition, but a host tarball is bounded only by what this
# package is willing to write, and 4 MB of default is a guess about someone
# else's application. The fetch cap and the disk reserve are the same policy
# seen from two sides, so one flag has to move both or the pair drifts.
# ---------------------------------------------------------------------------


def test_fetch_passes_the_payload_cap_to_the_downloader(monkeypatch, tmp_path):
    seen = {}

    def fake_download(url, dest, max_bytes=None):
        seen["max_bytes"] = max_bytes

    monkeypatch.setattr(cli, "download", fake_download)
    cli._fetch("http://example.invalid/a.bin", tmp_path / "a.bin", None, max_bytes=123)

    assert seen["max_bytes"] == 123


def test_run_wires_the_payload_cap_into_the_agent(monkeypatch, tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "manifest.json").write_text(json.dumps(_manifest()))

    captured: dict = {}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    _patch_agent(monkeypatch, captured)

    args = _run_args(tmp_path, source_dir=source_dir, max_payload_bytes=64_000_000)
    assert cli._run(args, argparse.ArgumentParser()) == 0
    assert captured["host_max_bytes"] == 64_000_000


def test_payload_cap_defaults_to_the_packages_own_limit(monkeypatch, tmp_path):
    from unoq_ota.preflight import MAX_PAYLOAD_BYTES

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "manifest.json").write_text(json.dumps(_manifest()))

    captured: dict = {}
    monkeypatch.setattr(cli, "resolve_flash_target", _fake_target)
    _patch_agent(monkeypatch, captured)

    assert cli._run(_run_args(tmp_path, source_dir=source_dir), argparse.ArgumentParser()) == 0
    assert captured["host_max_bytes"] == MAX_PAYLOAD_BYTES


def test_status_reports_an_unreadable_state_file_without_a_traceback(monkeypatch, tmp_path, caplog):
    # A root-run service leaves root-owned state; a later non-root `status`
    # should say so in one line, not dump a stack trace at an operator who
    # is probably already having a bad day.
    from unoq_ota.state import StateError

    def boom(self):
        raise StateError("cannot read /var/lib/unoq-ota/state.json: Permission denied")

    monkeypatch.setattr(StateStore, "load", boom)

    with caplog.at_level(logging.ERROR, logger="unoq_ota.cli"):
        assert cli.main(["--state-dir", str(tmp_path), "status"]) == 1

    assert "Permission denied" in caplog.text
