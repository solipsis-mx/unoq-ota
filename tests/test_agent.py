from __future__ import annotations

import base64
import contextlib
import hashlib
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import make_artifact_bytes
from unoq_ota import agent as agent_module
from unoq_ota.agent import Agent
from unoq_ota.artifact import load_artifact
from unoq_ota.board import FlashTarget
from unoq_ota.flasher import FlashError
from unoq_ota.interfaces import Status, Update
from unoq_ota.preflight import MAX_PAYLOAD_BYTES, PreflightError
from unoq_ota.state import MAX_ATTEMPTS, Phase, State, StateStore
from unoq_ota.verify import VerificationError, canonical_bytes

TARGET = FlashTarget(address=0x08100000, max_size=786432, core_version="1.0.0")


@pytest.fixture(autouse=True)
def _no_swd_in_agent_tests(monkeypatch):
    """detect_drift's default read_header talks to OpenOCD. Unit tests must not."""
    import unoq_ota.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "detect_drift", lambda *args, **kwargs: False)


@contextlib.contextmanager
def _fake_router_stopped():
    """A no-op stand-in for `unoq_ota.flasher.router_stopped`.

    The real one shells out to `systemctl`. Every test in this file that
    reaches `run_once`'s flash step must use this instead -- never the real
    thing -- so nothing here ever risks touching a real systemd, on this
    machine or, worse, on the actual board.
    """
    yield True


class StubSource:
    def __init__(self, update):
        self.update = update
        self.reports = []

    def check(self):
        return self.update

    def report(self, update, status, detail):
        self.reports.append((status, detail))


class StubGate:
    def __init__(self, allowed=True):
        self.allowed = allowed

    def may_flash(self):
        return (self.allowed, "ok" if self.allowed else "supply unstable")


class StubHealth:
    def __init__(self, results):
        self.results = list(results)

    def _next(self):
        return self.results.pop(0) if self.results else False

    def wait_healthy(self, timeout_s):
        item = self._next()
        if isinstance(item, str):
            return True
        return bool(item)

    def wait_alive(self, timeout_s):
        item = self._next()
        if isinstance(item, str):
            return item
        if item is True:
            return "alive"
        return None


class ScriptedHealth:
    """A HealthCheck backed by a script shared across every factory call.

    Script entries are bools, version strings, or exceptions. bools feed
    `wait_healthy`; strings feed `wait_alive`; exceptions are raised.
    """

    def __init__(self, script):
        self.script = script

    def _take(self):
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def wait_healthy(self, timeout_s):
        item = self._take()
        if isinstance(item, str):
            return True
        return bool(item)

    def wait_alive(self, timeout_s):
        item = self._take()
        if isinstance(item, str):
            return item
        if item is True:
            return "alive"
        return None


class RecordingHealthFactory:
    """A health_factory that records the version it was called with.

    Every test elsewhere in this file uses `lambda version: health`, which
    discards the argument entirely -- that would pass identically if the
    agent called `self.health_factory("")`. This one lets a test assert the
    factory actually received `update.version`, which is what stops an old
    image that survived a failed flash from being read as success.
    """

    def __init__(self, health):
        self.health = health
        self.calls = []

    def __call__(self, version):
        self.calls.append(version)
        return self.health


def _update(version="1.0.0", sequence=1):
    manifest = {
        "version": version,
        "sequence": sequence,
        "artifact": {"url": "http://x/a.bin", "size": 1, "sha256": "0" * 64},
    }
    return Update(version=version, sequence=sequence, manifest=manifest, raw_manifest=b"{}")


def _agent(
    tmp_path, source, gate, health, flashed=None, verify_ok=True, health_factory=None, verify_error=None, no_flash=False
):
    def fetch(url, dest):
        Path(dest).write_bytes(make_artifact_bytes())
        return Path(dest)

    def flash(artifact, target):
        if flashed is not None:
            flashed.append(artifact.path.name)

    def verify(manifest, path, last_sequence):
        if verify_error is not None:
            raise verify_error
        if not verify_ok:
            raise VerificationError("bad signature")

    return Agent(
        state_dir=tmp_path,
        source=source,
        gate=gate,
        health_factory=health_factory or (lambda version: health),
        target=TARGET,
        flash=flash,
        fetch=fetch,
        verify=verify,
        router_stopped=_fake_router_stopped,
        no_flash=no_flash,
    )


def test_idles_when_there_is_no_update(tmp_path):
    agent = _agent(tmp_path, StubSource(None), StubGate(), StubHealth([]))
    assert agent.run_once() == Phase.IDLE


def test_commits_a_healthy_update(tmp_path):
    flashed = []
    source = StubSource(_update())
    agent = _agent(tmp_path, source, StubGate(), StubHealth([True]), flashed)

    assert agent.run_once() == Phase.COMMITTED
    assert flashed == ["staged.bin"]
    assert (tmp_path / "current.bin").is_file()
    assert Status.COMMITTED in [s for s, _ in source.reports]


def test_waits_when_the_gate_refuses(tmp_path):
    flashed = []
    agent = _agent(tmp_path, StubSource(_update()), StubGate(False), StubHealth([]), flashed)

    assert agent.run_once() == Phase.STAGED
    assert flashed == []
    assert (tmp_path / "staged.bin").is_file()


def test_rejects_an_unverifiable_update_without_poisoning_unsigned_input(tmp_path):
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([]), verify_ok=False
    )

    assert agent.run_once() == Phase.IDLE
    assert not StateStore(tmp_path / "state.json").is_poisoned("1.0.0")


def test_rolls_back_when_the_new_firmware_is_unhealthy(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    flashed = []
    # Post-flash: new firmware unhealthy. Rollback of current.bin: that
    # image comes up as a *different* live version, which is success.
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, "0.9.0"]), flashed
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


def test_rollback_does_not_treat_a_silent_mcu_as_restored(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    (tmp_path / "golden.bin").write_bytes(make_artifact_bytes())
    flashed = []
    # current.bin flashes but the MCU stays silent; golden.bin then reports.
    agent = _agent(
        tmp_path,
        StubSource(_update()),
        StubGate(),
        StubHealth([False, None, "golden-1"]),
        flashed,
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin", "golden.bin"]


def test_rollback_requires_the_committed_version_when_it_is_known(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    (tmp_path / "golden.bin").write_bytes(make_artifact_bytes())
    store = StateStore(tmp_path / "state.json")
    state = store.load()
    state.committed_version = "0.9.0"
    store.save(state)
    flashed = []
    agent = _agent(
        tmp_path,
        StubSource(_update(version="2.0.0")),
        StubGate(),
        StubHealth([False, "other-live", "golden-1"]),
        flashed,
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin", "golden.bin"]


def test_commit_records_the_version_stored_in_current_bin(tmp_path):
    agent = _agent(tmp_path, StubSource(_update(version="3.1.0")), StubGate(), StubHealth([True]))

    assert agent.run_once() == Phase.COMMITTED
    assert StateStore(tmp_path / "state.json").load().committed_version == "3.1.0"


def test_poisons_a_version_that_failed_its_health_check(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, "0.9.0"])
    )
    agent.run_once()

    assert StateStore(tmp_path / "state.json").is_poisoned("1.0.0")


def test_refuses_a_version_that_exceeded_its_attempt_cap(tmp_path):
    store = StateStore(tmp_path / "state.json")
    for _ in range(MAX_ATTEMPTS):
        store.record_attempt("1.0.0")
    flashed = []
    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([]), flashed)

    assert agent.run_once() == Phase.REJECTED
    assert flashed == []


# ---------------------------------------------------------------------------
# Additional coverage beyond the brief: these exercise the two places the
# reference implementation's exception handling was too narrow for what its
# own collaborators can actually raise, the missing report on a download
# failure, and the real (non-stubbed) `_default_verify` binding.
# ---------------------------------------------------------------------------


def test_reports_download_failure_to_the_source(tmp_path):
    def fetch(url, dest):
        raise ConnectionError("network unreachable")

    def flash(artifact, target):
        pass

    def verify(manifest, path, last_sequence):
        pass

    source = StubSource(_update())
    agent = Agent(
        state_dir=tmp_path,
        source=source,
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        flash=flash,
        fetch=fetch,
        verify=verify,
    )

    assert agent.run_once() == Phase.IDLE
    assert any(status == Status.REJECTED for status, _ in source.reports)


def test_returns_to_idle_without_poisoning_on_unexpected_verify_error(tmp_path):
    """load_artifact's own docstring promises only ArtifactError, but it
    starts with Path.read_bytes(), which can raise OSError/MemoryError (see
    unoq_ota/reconciler.py's own defence against exactly this). A narrow
    `except (VerificationError, ArtifactError)` would let that escape
    run_once() entirely -- a supervised agent would then retry the same
    update forever without ever poisoning it, per the task brief's warning.
    """

    def fetch(url, dest):
        Path(dest).write_bytes(make_artifact_bytes())
        return Path(dest)

    def flash(artifact, target):
        pass

    def verify(manifest, path, last_sequence):
        raise RuntimeError("keyring backend timed out")

    source = StubSource(_update())
    agent = Agent(
        state_dir=tmp_path,
        source=source,
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        flash=flash,
        fetch=fetch,
        verify=verify,
    )

    assert agent.run_once() == Phase.IDLE
    assert not StateStore(tmp_path / "state.json").is_poisoned("1.0.0")


def test_rollback_skips_a_candidate_that_raises_an_unexpected_error(tmp_path):
    """The rollback loop walks the same CANDIDATES list as the reconciler,
    which defends every candidate with a broad `except Exception` for this
    exact reason (see reconciler.py). The reference code's narrower
    `except (FlashError, ArtifactError)` would let an unexpected error from
    a bad current.bin abort rollback instead of falling through to
    previous.bin.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    (tmp_path / "previous.bin").write_bytes(make_artifact_bytes())
    flashed = []

    def fetch(url, dest):
        Path(dest).write_bytes(make_artifact_bytes())
        return Path(dest)

    def flash(artifact, target):
        flashed.append(artifact.path.name)

    def verify(manifest, path, last_sequence):
        pass

    def load(path):
        path = Path(path)
        if path.name == "current.bin":
            raise OSError("disk gremlin")
        return load_artifact(path)

    shared_health = StubHealth([False, "0.9.0"])
    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(_update()),
        gate=StubGate(),
        health_factory=lambda version: shared_health,
        target=TARGET,
        flash=flash,
        load=load,
        fetch=fetch,
        verify=verify,
        router_stopped=_fake_router_stopped,
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "previous.bin"]


def test_default_verify_binds_public_keys_and_the_staged_path(tmp_path):
    key = Ed25519PrivateKey.generate()
    public_keys = {"k1": key.public_key()}
    artifact_bytes = make_artifact_bytes()
    digest = hashlib.sha256(artifact_bytes).hexdigest()

    manifest = {
        "version": "2.0.0",
        "sequence": 5,
        "artifact": {"url": "http://x/a.bin", "size": len(artifact_bytes), "sha256": digest},
        "target": {
            "board": "arduino_uno_q",
            "link_mode": "dynamic",
            "sketch_offset": "0x08100000",
            "partition_size": 786432,
        },
    }
    sig = key.sign(canonical_bytes(manifest))
    manifest["signature"] = {
        "alg": "ed25519",
        "key_id": "k1",
        "sig": base64.b64encode(sig).decode(),
    }

    staged = tmp_path / "staged.bin"
    staged.write_bytes(artifact_bytes)

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(None),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        public_keys=public_keys,
        fetch=lambda url, dest: None,
    )

    # Correctly signed manifest, matching artifact bytes on disk: must not raise.
    agent._default_verify(manifest, staged, last_sequence=0)


def test_default_verify_rejects_a_tampered_artifact(tmp_path):
    """Regression guard for the signature-vs-brief mismatch called out in the
    task: `_default_verify` must pass `artifact_path` into `verify_manifest`
    so the *bytes actually staged on disk* are checked, not just the
    manifest's own claims about them.
    """
    key = Ed25519PrivateKey.generate()
    public_keys = {"k1": key.public_key()}
    artifact_bytes = make_artifact_bytes()
    digest = hashlib.sha256(artifact_bytes).hexdigest()

    manifest = {
        "version": "2.0.0",
        "sequence": 5,
        "artifact": {"url": "http://x/a.bin", "size": len(artifact_bytes), "sha256": digest},
        "target": {
            "board": "arduino_uno_q",
            "link_mode": "dynamic",
            "sketch_offset": "0x08100000",
            "partition_size": 786432,
        },
    }
    sig = key.sign(canonical_bytes(manifest))
    manifest["signature"] = {
        "alg": "ed25519",
        "key_id": "k1",
        "sig": base64.b64encode(sig).decode(),
    }

    staged = tmp_path / "staged.bin"
    staged.write_bytes(make_artifact_bytes(body_len=999))  # different bytes, same declared digest

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(None),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        public_keys=public_keys,
        fetch=lambda url, dest: None,
    )

    with pytest.raises(VerificationError):
        agent._default_verify(manifest, staged, last_sequence=0)


# ---------------------------------------------------------------------------
# Adversarial-review fixes: C1, C2, I1, I2, I3, I4, M1 (see task-9-brief.md).
# ---------------------------------------------------------------------------


def test_rollback_falls_through_to_golden_bin_when_current_bin_still_reports_bad_version(
    tmp_path,
):
    """C1: the rollback loop must not stop at the first candidate that merely
    flashes without raising. `current.bin`'s post-flash identity check
    reporting `True` means the device still looks like the bad firmware
    (the flash did not take) -- that must be treated as failure and fall
    through, all the way to `golden.bin` if that is what it takes.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    (tmp_path / "golden.bin").write_bytes(make_artifact_bytes())
    flashed = []
    # post-flash check: False (unhealthy, triggers rollback)
    # current.bin: still reports the bad version -- flash did not take
    # golden.bin: a different live version -- restored
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, "1.0.0", "golden-1"]), flashed
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin", "golden.bin"]


def test_rollback_returns_a_result_rather_than_raising_when_a_health_check_raises(tmp_path):
    """C2: `_is_healthy` must swallow an exception from a rollback
    candidate's own check exactly like `reconciler._is_healthy` does --
    treated the same as a clean `False` return (uninformative, accepted) --
    and it must never propagate out of `run_once`.

    Note on regression evidence: this call site does not exist at all in
    the pre-fix code (its rollback loop performs no health check on any
    candidate), so this exact scenario cannot fail there -- there is no
    call for the injected RuntimeError to interrupt, and pre-fix code
    produces the same `flashed`/`Phase` result by simply never trying. It
    is kept because the exception-during-a-rollback-check branch is
    otherwise entirely uncovered; the pre-fix crash for the *unguarded*
    health check is reproduced separately by
    `test_run_once_does_not_propagate_when_wait_healthy_raises_after_the_flash`
    below, which does fail against the pre-fix code.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    (tmp_path / "previous.bin").write_bytes(make_artifact_bytes())
    flashed = []
    script = [False, RuntimeError("health backend crashed"), "0.9.0"]
    agent = _agent(
        tmp_path,
        StubSource(_update()),
        StubGate(),
        None,
        flashed,
        health_factory=lambda version: ScriptedHealth(script),
    )

    result = agent.run_once()  # must not raise

    assert result == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin", "previous.bin"]


def test_run_once_does_not_propagate_when_wait_healthy_raises_after_the_flash(tmp_path):
    """C2: an unguarded `wait_healthy()` at the post-flash check meant any
    exception there skipped the rollback block entirely and escaped
    `run_once`. It must instead be treated as unhealthy, and rollback must
    still run.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    flashed = []
    script = [RuntimeError("health backend crashed"), "0.9.0"]
    agent = _agent(
        tmp_path,
        StubSource(_update()),
        StubGate(),
        None,
        flashed,
        health_factory=lambda version: ScriptedHealth(script),
    )

    result = agent.run_once()  # must not raise

    assert result == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


def test_skips_download_when_sequence_not_newer_than_watermark(tmp_path):
    store = StateStore(tmp_path / "state.json")
    store.save(State(last_verified_sequence=11, last_verified_version="probe"))
    fetch_calls = []

    def fetch(url, dest):
        fetch_calls.append(url)

    flashed = []
    source = StubSource(_update(version="probe", sequence=11))
    agent = _agent(tmp_path, source, StubGate(), StubHealth([True, True]), flashed)
    agent._fetch = fetch

    result = agent.run_once()

    assert result == Phase.IDLE
    assert fetch_calls == []
    assert flashed == []


def test_skips_download_when_sequence_not_newer_than_committed_sequence(tmp_path):
    store = StateStore(tmp_path / "state.json")
    store.save(State(sequence=5))
    fetch_calls = []

    def fetch(url, dest):
        fetch_calls.append(url)

    flashed = []
    source = StubSource(_update(version="5.0.0", sequence=5))
    agent = _agent(tmp_path, source, StubGate(), StubHealth([True, True]), flashed)
    agent._fetch = fetch

    result = agent.run_once()

    assert result == Phase.IDLE
    assert fetch_calls == []
    assert flashed == []


def test_no_flash_verifies_without_flashing_and_stamps_watermark(tmp_path):
    flashed = []
    source = StubSource(_update(version="probe-2", sequence=12))
    agent = _agent(tmp_path, source, StubGate(), StubHealth([True, True]), flashed)
    agent.no_flash = True

    result = agent.run_once()

    assert result == Phase.IDLE
    assert flashed == []
    assert not (tmp_path / "staged.bin").exists()
    state = StateStore(tmp_path / "state.json").load()
    assert state.last_verified_sequence == 12
    assert state.last_verified_version == "probe-2"
    assert state.sequence == 0
    assert state.committed_version is None
    assert any(status == Status.VERIFIED for status, _ in source.reports)


def test_no_flash_unlinks_staged_before_persisting_watermark(tmp_path, monkeypatch):
    seen = {}
    original_save = StateStore.save

    def save(self, state):
        if state.last_verified_sequence == 2 and "staged_exists" not in seen:
            seen["staged_exists"] = (tmp_path / "staged.bin").exists()
            seen["host_exists"] = (tmp_path / "staged-host.tar.gz").exists()
        return original_save(self, state)

    monkeypatch.setattr(StateStore, "save", save)

    def fetch(url, dest):
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(_host_bytes() if "host" in url else make_artifact_bytes())

    source = StubSource(_coupled_update())
    agent = Agent(
        state_dir=tmp_path,
        source=source,
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        flash=lambda artifact, target: None,
        fetch=fetch,
        verify=lambda manifest, path, last_sequence: None,
        router_stopped=_fake_router_stopped,
        no_flash=True,
    )

    assert agent.run_once() == Phase.IDLE
    assert seen["staged_exists"] is False
    assert seen["host_exists"] is False
    assert not (tmp_path / "staged.bin").exists()
    assert not (tmp_path / "staged-host.tar.gz").exists()


def test_skip_path_unlinks_leftover_staged_files_and_reports_up_to_date(tmp_path):
    store = StateStore(tmp_path / "state.json")
    store.save(State(last_verified_sequence=11, last_verified_version="probe"))
    (tmp_path / "staged.bin").write_bytes(b"leftover")
    (tmp_path / "staged-host.tar.gz").write_bytes(b"leftover-host")
    fetch_calls = []

    def fetch(url, dest):
        fetch_calls.append(url)

    source = StubSource(_update(version="probe", sequence=11))
    agent = _agent(tmp_path, source, StubGate(), StubHealth([]))
    agent._fetch = fetch

    result = agent.run_once()

    assert result == Phase.IDLE
    assert fetch_calls == []
    assert not (tmp_path / "staged.bin").exists()
    assert not (tmp_path / "staged-host.tar.gz").exists()
    assert source.reports == [(Status.VERIFIED, "up to date")]


def test_a_poisoned_version_is_rejected_without_downloading(tmp_path):
    """I2: is_poisoned had no production caller anywhere -- a poisoned
    version must be rejected before the network is touched.
    """
    store = StateStore(tmp_path / "state.json")
    store.poison("1.0.0")

    fetch_calls = []

    def fetch(url, dest):
        fetch_calls.append(url)
        Path(dest).write_bytes(make_artifact_bytes())

    source = StubSource(_update())
    agent = Agent(
        state_dir=tmp_path,
        source=source,
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        flash=lambda artifact, target: None,
        fetch=fetch,
        verify=lambda manifest, path, last_sequence: None,
    )

    assert agent.run_once() == Phase.REJECTED
    assert fetch_calls == []
    assert any(status == Status.REJECTED for status, _ in source.reports)


def test_a_signed_verify_failure_records_an_attempt_as_well_as_poisoning(tmp_path):
    agent = _agent(
        tmp_path,
        StubSource(_update()),
        StubGate(),
        StubHealth([]),
        verify_error=VerificationError("sha256 mismatch", poisonable=True),
    )

    assert agent.run_once() == Phase.REJECTED

    store = StateStore(tmp_path / "state.json")
    assert store.attempts_for("1.0.0") == 1
    assert store.is_poisoned("1.0.0")


def test_health_factory_is_called_with_the_update_version(tmp_path):
    """I3: every other test's `health_factory=lambda version: health`
    discards the argument entirely. This is the one thing that stops an old
    image surviving a failed flash from being read as success.
    """
    factory = RecordingHealthFactory(StubHealth([True]))
    update = _update(version="9.9.9")
    agent = _agent(tmp_path, StubSource(update), StubGate(), None, health_factory=factory)

    assert agent.run_once() == Phase.COMMITTED
    assert factory.calls == ["9.9.9"]


def test_commit_copy_failure_does_not_leave_a_partial_current_bin(tmp_path, monkeypatch):
    """I1: the commit-path copies were non-atomic and unguarded. A crash or
    ENOSPC mid-copy must never leave a partial current.bin -- the primary
    rollback candidate both this loop and the reconciler reach for first.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    original = b"ORIGINAL-CURRENT-BYTES-UNCHANGED"
    (tmp_path / "current.bin").write_bytes(original)

    real_replace = os.replace

    def flaky_replace(src, dst):
        # Only the final staged.bin -> current.bin replace fails. state.json
        # saves and the current.bin -> previous.bin copy must be unaffected,
        # so this isolates the exact write this test is about.
        if Path(dst).name == "current.bin":
            raise OSError("ENOSPC (simulated)")
        return real_replace(src, dst)

    monkeypatch.setattr(agent_module.os, "replace", flaky_replace)

    source = StubSource(_update())
    agent = _agent(tmp_path, source, StubGate(), StubHealth([True]))

    result = agent.run_once()

    assert result != Phase.COMMITTED
    assert (tmp_path / "current.bin").read_bytes() == original
    assert not any(p.suffix == ".tmp" for p in tmp_path.iterdir())


def test_rollback_proceeds_when_poison_raises(tmp_path, monkeypatch):
    """I4: store.poison() was unguarded and state.py re-raises on write
    failure. A full or read-only /var/lib must not be able to abort the
    rollback of a device that is, right now, running unhealthy firmware.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    flashed = []

    def raising_poison(self, version):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(StateStore, "poison", raising_poison)

    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, "0.9.0"]), flashed
    )

    result = agent.run_once()  # must not raise

    assert result == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


def test_commit_survives_a_failed_state_save(tmp_path, monkeypatch):
    real_save = StateStore.save

    def flaky_save(self, state):
        if state.phase == Phase.COMMITTED:
            raise OSError("disk full (simulated)")
        return real_save(self, state)

    monkeypatch.setattr(StateStore, "save", flaky_save)
    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([True]))

    assert agent.run_once() == Phase.COMMITTED


def test_flash_proceeds_when_record_attempt_raises(tmp_path, monkeypatch):
    def boom(self, version):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(StateStore, "record_attempt", boom)
    flashed = []
    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([True]), flashed)

    assert agent.run_once() == Phase.COMMITTED
    assert flashed == ["staged.bin"]


def test_constructing_an_agent_without_fetch_raises(tmp_path):
    """M1: a missing `fetch` is a construction mistake. Left as the default
    None, every call falls into `self._fetch(...)` raising `TypeError`,
    which the broad download-failure handler reports as "download failed" --
    indistinguishable from permanently no connectivity.
    """
    with pytest.raises(TypeError):
        Agent(
            state_dir=tmp_path,
            source=StubSource(None),
            gate=StubGate(),
            health_factory=lambda version: StubHealth([]),
            target=TARGET,
        )


# ---------------------------------------------------------------------------
# Task 11: preflight guards wired into run_once (clock, disk, router)
# ---------------------------------------------------------------------------


def test_drift_discards_stale_current_bin_so_rollback_does_not_flash_fiction(
    tmp_path, monkeypatch
):
    import unoq_ota.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "detect_drift", lambda *args, **kwargs: True)

    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    (tmp_path / "golden.bin").write_bytes(make_artifact_bytes())
    flashed = []
    agent = _agent(
        tmp_path,
        StubSource(_update()),
        StubGate(),
        StubHealth([False, "golden-1"]),
        flashed,
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "golden.bin"]
    assert not (tmp_path / "current.bin").exists()


def test_matching_resident_image_is_kept_as_rollback_target(tmp_path, monkeypatch):
    import unoq_ota.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "detect_drift", lambda *args, **kwargs: False)

    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    flashed = []
    agent = _agent(
        tmp_path,
        StubSource(_update()),
        StubGate(),
        StubHealth([False, "0.9.0"]),
        flashed,
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


def test_clock_guard_defers_without_counting_an_attempt_or_poisoning(tmp_path, monkeypatch):
    import unoq_ota.preflight as preflight_module

    def fail_clock(now=None, floor_year=2020):
        raise PreflightError("system clock reads 1980-01-06; deferring")

    monkeypatch.setattr(preflight_module, "check_clock", fail_clock)

    flashed = []
    source = StubSource(_update())
    agent = _agent(tmp_path, source, StubGate(), StubHealth([]), flashed)

    assert agent.run_once() == Phase.IDLE
    assert flashed == []
    assert any(status == Status.WAITING_FOR_GATE for status, _ in source.reports)
    store = StateStore(tmp_path / "state.json")
    assert not store.is_poisoned("1.0.0")
    assert store.attempts_for("1.0.0") == 0


def test_disk_guard_defers_without_counting_an_attempt_or_poisoning(tmp_path, monkeypatch):
    import unoq_ota.preflight as preflight_module

    def fail_disk(path, needed_bytes, margin_bytes=50_000_000):
        raise PreflightError("insufficient disk space")

    monkeypatch.setattr(preflight_module, "check_disk_space", fail_disk)

    flashed = []
    source = StubSource(_update())
    agent = _agent(tmp_path, source, StubGate(), StubHealth([]), flashed)

    assert agent.run_once() == Phase.IDLE
    assert flashed == []
    assert any(status == Status.WAITING_FOR_GATE for status, _ in source.reports)
    store = StateStore(tmp_path / "state.json")
    assert not store.is_poisoned("1.0.0")
    assert store.attempts_for("1.0.0") == 0


def test_preflight_guard_leaves_state_consistent_with_its_return_value(tmp_path, monkeypatch):
    """The reference wiring returns Phase.IDLE from the clock/disk guard
    without persisting it, which can disagree with whatever phase state.json
    was left holding by an earlier, unrelated cycle -- exactly the kind of
    inconsistent guard the task warns about. `run_once`'s return value must
    match what it left in the store.
    """
    import unoq_ota.preflight as preflight_module

    def fail_clock(now=None, floor_year=2020):
        raise PreflightError("system clock reads 1980-01-06; deferring")

    monkeypatch.setattr(preflight_module, "check_clock", fail_clock)

    store = StateStore(tmp_path / "state.json")
    state = store.load()
    state.phase = Phase.STAGED
    state.version = "0.0.1-stale"
    store.save(state)

    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([]))

    assert agent.run_once() == Phase.IDLE
    assert store.load().phase == Phase.IDLE


def test_missing_artifact_size_does_not_poison_unsigned_manifest_fields(tmp_path):
    manifest = {
        "version": "1.0.0",
        "sequence": 1,
        "artifact": {"url": "http://x/a.bin", "sha256": "0" * 64},  # no "size"
    }
    update = Update(version="1.0.0", sequence=1, manifest=manifest, raw_manifest=b"{}")
    flashed = []
    agent = _agent(tmp_path, StubSource(update), StubGate(), StubHealth([True]), flashed)

    assert agent.run_once() == Phase.COMMITTED
    assert flashed == ["staged.bin"]
    assert not StateStore(tmp_path / "state.json").is_poisoned("1.0.0")


def test_device_side_error_from_clock_check_is_not_misattributed_to_the_manifest(
    tmp_path, monkeypatch
):
    # I2: check_clock()/check_disk_space() used to share one `try` with the
    # artifact-size parse. Anything other than PreflightError raised by
    # either of them -- not just a bad manifest -- fell into the sibling
    # `except (KeyError, TypeError, ValueError)` and was poisoned as
    # "manifest has no usable artifact size", permanently rejecting a good
    # version over a device-side condition with a diagnostic that lies about
    # the cause. Forcing check_clock to raise a bare TypeError (standing in
    # for any such device-side bug, unrelated to the manifest) must not be
    # swallowed into that poisoning path.
    import unoq_ota.preflight as preflight_module

    def broken_clock(now=None, floor_year=2020):
        raise TypeError("device-side bug unrelated to the manifest")

    monkeypatch.setattr(preflight_module, "check_clock", broken_clock)

    source = StubSource(_update())
    agent = _agent(tmp_path, source, StubGate(), StubHealth([]))

    with pytest.raises(TypeError):
        agent.run_once()

    store = StateStore(tmp_path / "state.json")
    assert not store.is_poisoned("1.0.0")
    assert not any(
        "manifest has no usable artifact size" in detail for _, detail in source.reports
    )


def test_absurd_manifest_size_does_not_cause_indefinite_deferral(tmp_path):
    # I4: the pre-download disk check must not trust the manifest's declared
    # artifact.size -- it is attacker input until self._verify(...) runs,
    # later in run_once. Before this fix, an inflated declared size made
    # check_disk_space fail every single cycle: the PreflightError branch
    # defers without poisoning and without counting an attempt, so nothing
    # ever capped the retries -- a durable denial-of-update from
    # unauthenticated manifest input. The bound must instead come from the
    # board's own sketch partition (self.target.max_size), which a served
    # manifest cannot influence. This uses the real, unmocked
    # unoq_ota.preflight.check_disk_space against the real filesystem.
    manifest = {
        "version": "1.0.0",
        "sequence": 1,
        "artifact": {"url": "http://x/a.bin", "size": 10**15, "sha256": "0" * 64},
    }
    update = Update(version="1.0.0", sequence=1, manifest=manifest, raw_manifest=b"{}")
    flashed = []
    agent = _agent(tmp_path, StubSource(update), StubGate(), StubHealth([True]), flashed)

    assert agent.run_once() == Phase.COMMITTED
    assert flashed == ["staged.bin"]


def test_flash_step_runs_inside_router_stopped(tmp_path):
    calls = []

    @contextlib.contextmanager
    def spy_router_stopped():
        calls.append("enter")
        yield True
        calls.append("exit")

    flashed = []

    def fetch(url, dest):
        Path(dest).write_bytes(make_artifact_bytes())
        return Path(dest)

    def flash(artifact, target):
        assert calls == ["enter"]  # the write happens while the router is "stopped"
        flashed.append(artifact.path.name)

    def verify(manifest, path, last_sequence):
        pass

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(_update()),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([True]),
        target=TARGET,
        flash=flash,
        fetch=fetch,
        verify=verify,
        router_stopped=spy_router_stopped,
    )

    assert agent.run_once() == Phase.COMMITTED
    assert calls == ["enter", "exit"]
    assert flashed == ["staged.bin"]


def test_router_is_restarted_even_when_the_flash_raises(tmp_path):
    calls = []

    @contextlib.contextmanager
    def spy_router_stopped():
        calls.append("enter")
        try:
            yield True
        finally:
            calls.append("exit")

    def fetch(url, dest):
        Path(dest).write_bytes(make_artifact_bytes())
        return Path(dest)

    def flash(artifact, target):
        raise FlashError("write failed")

    def verify(manifest, path, last_sequence):
        pass

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(_update()),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([]),
        target=TARGET,
        flash=flash,
        fetch=fetch,
        verify=verify,
        router_stopped=spy_router_stopped,
    )

    assert agent.run_once() == Phase.IDLE
    assert calls == ["enter", "exit"]


def _host_bytes():
    return b"host-payload-bytes"


def _coupled_update():
    update = _update(version="2.0.0", sequence=2)
    digest = hashlib.sha256(_host_bytes()).hexdigest()
    update.manifest["host_payload"] = {
        "url": "http://x/host.tar.gz",
        "size": len(_host_bytes()),
        "sha256": digest,
    }
    return update


def test_omitting_host_payload_does_not_touch_the_host_tree(tmp_path):
    applied = []
    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([True]))
    agent._apply_host = lambda archive, live: applied.append(live)
    assert agent.run_once() == Phase.COMMITTED
    assert applied == []


def test_applies_host_payload_after_the_mcu_is_healthy(tmp_path):
    applied = []
    restarted = []

    def fetch(url, dest):
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(_host_bytes() if "host" in url else make_artifact_bytes())

    def apply_host(archive, live):
        applied.append((Path(archive).name, Path(live).name))

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(_coupled_update()),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([True]),
        target=TARGET,
        flash=lambda artifact, target: None,
        fetch=fetch,
        verify=lambda manifest, path, last_sequence: None,
        router_stopped=_fake_router_stopped,
        apply_host=apply_host,
        host_restart=lambda: restarted.append("restart"),
        host_health=lambda: True,
    )
    assert agent.run_once() == Phase.COMMITTED
    assert applied == [("staged-host.tar.gz", "host")]
    assert restarted == ["restart"]
    assert (tmp_path / "staged-host.tar.gz").is_file()


def test_host_health_failure_rolls_back_host_and_mcu(tmp_path):
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    rolled = []
    flashed = []

    def fetch(url, dest):
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(_host_bytes() if "host" in url else make_artifact_bytes())

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(_coupled_update()),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([True, "1.0.0"]),
        target=TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
        fetch=fetch,
        verify=lambda manifest, path, last_sequence: None,
        router_stopped=_fake_router_stopped,
        apply_host=lambda archive, live: None,
        rollback_host=lambda live: rolled.append(Path(live).name),
        host_health=lambda: False,
    )
    assert agent.run_once() == Phase.ROLLED_BACK
    assert rolled == ["host"]
    assert flashed == ["staged.bin", "current.bin"]


# ---------------------------------------------------------------------------
# Disk preflight with a coupled host payload.
#
# The sketch bound comes from the partition, not the manifest (see run_once's
# own comment on why an attacker-chosen size must never drive this check).
# A host tarball has no partition to bound it, so the reserve is the same
# configured cap the fetch is allowed to write -- again not the manifest's
# declared `host_payload.size`, for exactly the same reason.
# ---------------------------------------------------------------------------


def _spy_disk(monkeypatch):
    import unoq_ota.preflight as preflight_module

    seen = []

    def spy(path, needed_bytes, margin_bytes=50_000_000):
        seen.append((Path(path), needed_bytes))

    monkeypatch.setattr(preflight_module, "check_disk_space", spy)
    return seen


def _coupled_agent(tmp_path, host_dir=None, host_max_bytes=None):
    def fetch(url, dest):
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(_host_bytes() if "host" in url else make_artifact_bytes())

    kwargs = {}
    if host_max_bytes is not None:
        kwargs["host_max_bytes"] = host_max_bytes
    return Agent(
        state_dir=tmp_path,
        source=StubSource(_coupled_update()),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([True]),
        target=TARGET,
        flash=lambda artifact, target: None,
        fetch=fetch,
        verify=lambda manifest, path, last_sequence: None,
        router_stopped=_fake_router_stopped,
        apply_host=lambda archive, live: None,
        host_dir=host_dir,
        **kwargs,
    )


def test_disk_preflight_reserves_room_for_the_host_tarball(tmp_path, monkeypatch):
    seen = _spy_disk(monkeypatch)
    agent = _coupled_agent(tmp_path, host_dir=tmp_path / "opt" / "app")

    assert agent.run_once() == Phase.COMMITTED
    assert (tmp_path, TARGET.max_size + MAX_PAYLOAD_BYTES) in seen


def test_disk_preflight_checks_the_host_directorys_filesystem_too(tmp_path, monkeypatch):
    # --host-dir routinely names a different mount from --state-dir, and
    # room on one says nothing about room on the other: the tarball is
    # staged next to state.json but unpacked over there.
    host_dir = tmp_path / "opt" / "app"
    seen = _spy_disk(monkeypatch)
    agent = _coupled_agent(tmp_path, host_dir=host_dir)

    assert agent.run_once() == Phase.COMMITTED
    assert (host_dir, MAX_PAYLOAD_BYTES) in seen


def test_disk_preflight_reserves_nothing_extra_for_an_mcu_only_update(tmp_path, monkeypatch):
    seen = _spy_disk(monkeypatch)
    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([True]))

    assert agent.run_once() == Phase.COMMITTED
    assert seen == [(tmp_path, TARGET.max_size)]


def test_the_host_reserve_is_configurable(tmp_path, monkeypatch):
    # An integrator whose fetch allows larger tarballs must be able to say so
    # here too, or the check reserves less room than the download can use.
    seen = _spy_disk(monkeypatch)
    agent = _coupled_agent(tmp_path, host_dir=tmp_path / "opt", host_max_bytes=64_000_000)

    assert agent.run_once() == Phase.COMMITTED
    assert (tmp_path, TARGET.max_size + 64_000_000) in seen


def test_records_which_core_supplied_the_flash_target(tmp_path):
    # state.json carries a core_version field that nothing ever wrote. The
    # offset and partition size come from whichever Arduino core is
    # installed, so recording which one was in use is what makes a stale
    # offset diagnosable after the fact.
    agent = _agent(tmp_path, StubSource(_update()), StubGate(), StubHealth([True]))

    assert agent.run_once() == Phase.COMMITTED
    assert StateStore(tmp_path / "state.json").load().core_version == TARGET.core_version
