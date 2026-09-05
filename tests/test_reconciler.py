from __future__ import annotations

from pathlib import Path

from tests.conftest import make_artifact_bytes
from unoq_ota.board import FlashTarget
from unoq_ota.reconciler import ReconcileResult, reconcile

TARGET = FlashTarget(address=0x08100000, max_size=786432, core_version="1.0.0")


class FakeHealth:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def wait_healthy(self, timeout_s: float) -> bool:
        self.calls += 1
        return self.results.pop(0) if self.results else False


def _seed(state_dir: Path, *names):
    state_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        (state_dir / name).write_bytes(make_artifact_bytes())


def test_does_nothing_when_the_mcu_is_already_healthy(tmp_path):
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    result = reconcile(
        tmp_path, FakeHealth([True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert result.healthy is True
    assert result.action == "none"
    assert flashed == []


def test_reflashes_current_when_the_mcu_is_silent(tmp_path):
    # The power-loss-during-erase case: MCU alive but running nothing.
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    result = reconcile(
        tmp_path, FakeHealth([False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert result.healthy is True
    assert result.image == "current.bin"
    assert flashed == ["current.bin"]


def test_falls_back_to_previous_then_golden(tmp_path):
    _seed(tmp_path, "current.bin", "previous.bin", "golden.bin")
    flashed = []

    result = reconcile(
        tmp_path, FakeHealth([False, False, False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert flashed == ["current.bin", "previous.bin", "golden.bin"]
    assert result.image == "golden.bin"
    assert result.healthy is True


def test_reports_failure_when_every_candidate_is_exhausted(tmp_path):
    _seed(tmp_path, "current.bin", "golden.bin")

    result = reconcile(
        tmp_path, FakeHealth([False, False, False]), TARGET,
        flash=lambda artifact, target: None,
    )

    assert result.healthy is False
    assert result.action == "exhausted"


def test_ignores_a_corrupt_candidate_and_moves_on(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes(truncate_to=100))
    (tmp_path / "golden.bin").write_bytes(make_artifact_bytes())
    flashed = []

    result = reconcile(
        tmp_path, FakeHealth([False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert flashed == ["golden.bin"]
    assert result.healthy is True


def test_does_not_read_agent_state(tmp_path):
    # The whole point: a corrupt or absent state.json must not stop recovery.
    _seed(tmp_path, "golden.bin")
    (tmp_path / "state.json").write_text("{ corrupt")
    flashed = []

    result = reconcile(
        tmp_path, FakeHealth([False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert result.healthy is True
    assert flashed == ["golden.bin"]


class RaisingHealth:
    """A HealthCheck double whose wait_healthy() can raise instead of return.

    `results` entries are either a bool (returned) or an Exception instance
    (raised). This stands in for the real VersionReportHealthCheck, which
    shells out to a subprocess and reads a temp file -- subprocess errors,
    OSError, and decoding failures are all live possibilities there.
    """

    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def wait_healthy(self, timeout_s: float) -> bool:
        self.calls += 1
        outcome = self.results.pop(0) if self.results else False
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def test_initial_health_check_raising_still_proceeds_to_recovery(tmp_path):
    # A health check that blows up is not evidence the board is fine.
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    result = reconcile(
        tmp_path,
        RaisingHealth([RuntimeError("subprocess exploded"), True]),
        TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert result.healthy is True
    assert result.image == "current.bin"
    assert flashed == ["current.bin"]


def test_post_flash_health_check_raising_for_current_continues_to_golden(tmp_path):
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    result = reconcile(
        tmp_path,
        RaisingHealth([False, OSError("temp file vanished"), True]),
        TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert flashed == ["current.bin", "golden.bin"]
    assert result.healthy is True
    assert result.image == "golden.bin"


def test_health_check_raising_every_time_reports_exhausted_not_an_exception(tmp_path):
    _seed(tmp_path, "current.bin", "golden.bin")

    result = reconcile(
        tmp_path,
        RaisingHealth([
            RuntimeError("boom"),
            OSError("boom"),
            ValueError("boom"),
        ]),
        TARGET,
        flash=lambda artifact, target: None,
    )

    assert result == ReconcileResult(healthy=False, action="exhausted")


def test_candidate_whose_is_file_raises_oserror_is_skipped(tmp_path, monkeypatch):
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    real_is_file = Path.is_file
    current_path = tmp_path / "current.bin"

    def flaky_is_file(self):
        if self == current_path:
            raise OSError("simulated stat failure")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", flaky_is_file)

    result = reconcile(
        tmp_path, FakeHealth([False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
    )

    assert flashed == ["golden.bin"]
    assert result.healthy is True
    assert result.image == "golden.bin"
