from __future__ import annotations

import base64
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
from unoq_ota.interfaces import Status, Update
from unoq_ota.state import MAX_ATTEMPTS, Phase, StateStore
from unoq_ota.verify import VerificationError, canonical_bytes

TARGET = FlashTarget(address=0x08100000, max_size=786432, core_version="1.0.0")


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

    def wait_healthy(self, timeout_s):
        return self.results.pop(0) if self.results else False


class ScriptedHealth:
    """A HealthCheck backed by a script shared across every factory call.

    Used where a test needs to control the outcome of several successive
    `wait_healthy()` calls -- possibly made through separate `health_factory`
    invocations -- some of which may need to raise. The script list is
    shared by reference (never copied), so multiple `ScriptedHealth`
    instances wrapping the same list consume it in order.
    """

    def __init__(self, script):
        self.script = script

    def wait_healthy(self, timeout_s):
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


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


def _agent(tmp_path, source, gate, health, flashed=None, verify_ok=True, health_factory=None):
    def fetch(url, dest):
        Path(dest).write_bytes(make_artifact_bytes())
        return Path(dest)

    def flash(artifact, target):
        if flashed is not None:
            flashed.append(artifact.path.name)

    def verify(manifest, path, last_sequence):
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


def test_rejects_and_poisons_an_unverifiable_update(tmp_path):
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([]), verify_ok=False
    )

    assert agent.run_once() == Phase.REJECTED
    assert StateStore(tmp_path / "state.json").is_poisoned("1.0.0")


def test_rolls_back_when_the_new_firmware_is_unhealthy(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    flashed = []
    # First `False`: the new firmware's post-flash check -- unhealthy,
    # triggers rollback. Second `False`: the post-rollback check against
    # `current.bin` -- uninformative (the restored image is not
    # `update.version`), which is exactly the case this loop must accept as
    # "restored" rather than loop forever waiting for a `True` that a
    # correctly-restored image would never produce.
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, False]), flashed
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


def test_poisons_a_version_that_failed_its_health_check(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, False])
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

    agent = Agent(
        state_dir=tmp_path,
        source=StubSource(_update()),
        gate=StubGate(),
        health_factory=lambda version: StubHealth([False]),
        target=TARGET,
        flash=flash,
        load=load,
        fetch=fetch,
        verify=verify,
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
    # current.bin check: True (still reports the bad version -- flash did
    #   not take, fall through)
    # golden.bin check: False (uninformative, accepted)
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, True, False]), flashed
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
    flashed = []
    script = [False, RuntimeError("health backend crashed")]
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


def test_run_once_does_not_propagate_when_wait_healthy_raises_after_the_flash(tmp_path):
    """C2: an unguarded `wait_healthy()` at the post-flash check meant any
    exception there skipped the rollback block entirely and escaped
    `run_once`. It must instead be treated as unhealthy, and rollback must
    still run.
    """
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    flashed = []
    script = [RuntimeError("health backend crashed"), False]
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


def test_a_verify_failure_records_an_attempt_as_well_as_poisoning(tmp_path):
    """I2: without record_attempt here, attempts_for stayed at zero forever,
    so a signature-invalid or replayed manifest produced a full download,
    verify, and reject on every cycle rather than ever engaging the cap.
    """
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([]), verify_ok=False
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
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, False]), flashed
    )

    result = agent.run_once()  # must not raise

    assert result == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


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
