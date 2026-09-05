from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import make_artifact_bytes
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


def _update(version="1.0.0", sequence=1):
    manifest = {
        "version": version,
        "sequence": sequence,
        "artifact": {"url": "http://x/a.bin", "size": 1, "sha256": "0" * 64},
    }
    return Update(version=version, sequence=sequence, manifest=manifest, raw_manifest=b"{}")


def _agent(tmp_path, source, gate, health, flashed=None, verify_ok=True):
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
        health_factory=lambda version: health,
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
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, True]), flashed
    )

    assert agent.run_once() == Phase.ROLLED_BACK
    assert flashed == ["staged.bin", "current.bin"]


def test_poisons_a_version_that_failed_its_health_check(tmp_path):
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes())
    agent = _agent(
        tmp_path, StubSource(_update()), StubGate(), StubHealth([False, True])
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
    )

    try:
        agent._default_verify(manifest, staged, last_sequence=0)
        assert False, "expected VerificationError for a tampered artifact"
    except VerificationError:
        pass
