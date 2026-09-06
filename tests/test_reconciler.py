from __future__ import annotations

import logging
from pathlib import Path

from tests.conftest import make_artifact_bytes
from unoq_ota.artifact import load_artifact
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

    def wait_alive(self, timeout_s: float) -> str | None:
        return "alive" if self.wait_healthy(timeout_s) else None


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


def test_ignores_a_corrupt_candidate_and_moves_on(tmp_path, caplog):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "current.bin").write_bytes(make_artifact_bytes(truncate_to=100))
    (tmp_path / "golden.bin").write_bytes(make_artifact_bytes())
    flashed = []

    with caplog.at_level(logging.WARNING):
        result = reconcile(
            tmp_path, FakeHealth([False, True]), TARGET,
            flash=lambda artifact, target: flashed.append(artifact.path.name),
        )

    assert flashed == ["golden.bin"]
    assert result.healthy is True
    assert "current.bin" in caplog.text
    assert "load()" in caplog.text


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

    def wait_alive(self, timeout_s: float) -> str | None:
        return "alive" if self.wait_healthy(timeout_s) else None


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


def test_candidate_whose_is_file_raises_oserror_is_skipped(tmp_path, monkeypatch, caplog):
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    real_is_file = Path.is_file
    current_path = tmp_path / "current.bin"

    def flaky_is_file(self):
        if self == current_path:
            raise OSError("simulated stat failure")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", flaky_is_file)

    with caplog.at_level(logging.WARNING):
        result = reconcile(
            tmp_path, FakeHealth([False, True]), TARGET,
            flash=lambda artifact, target: flashed.append(artifact.path.name),
        )

    assert flashed == ["golden.bin"]
    assert result.healthy is True
    assert result.image == "golden.bin"
    assert "current.bin" in caplog.text
    assert "is_file()" in caplog.text


# --- Finding 1 (Critical): flash() must be guarded like the health check ---
#
# The default injected `flash` is `write_sketch`, whose call chain bottoms
# out in `subprocess.run`. Its own documented contract is FlashError, but
# PermissionError (openocd loses its exec bit), OSError for ETXTBSY (a
# concurrent rootfs update mid-rewrite openocd), and OSError for ENOMEM
# (fork failing under memory pressure) all escape as bare OSError subclasses
# that are not FlashError. Because `flash` is an injected callable, the
# reconciler cannot rely on any particular implementation's exception
# discipline -- it must defend itself the same way it already does for the
# health check.


def test_flash_raising_permission_error_still_reaches_golden(tmp_path, caplog):
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    def flash(artifact, target):
        if artifact.path.name == "current.bin":
            raise PermissionError("openocd lost its exec bit")
        flashed.append(artifact.path.name)

    with caplog.at_level(logging.WARNING):
        result = reconcile(
            tmp_path, FakeHealth([False, True]), TARGET, flash=flash,
        )

    assert flashed == ["golden.bin"]
    assert result == ReconcileResult(healthy=True, action="reflashed", image="golden.bin")
    assert "current.bin" in caplog.text
    assert "flash()" in caplog.text


def test_flash_raising_several_non_flasherror_types_still_returns_a_result(tmp_path):
    _seed(tmp_path, "current.bin", "previous.bin", "golden.bin")

    def flash(artifact, target):
        name = artifact.path.name
        if name == "current.bin":
            raise PermissionError("no exec bit")
        if name == "previous.bin":
            raise OSError("ETXTBSY: text file busy")
        if name == "golden.bin":
            raise MemoryError("cannot allocate for fork")
        raise AssertionError(f"unexpected candidate {name}")

    result = reconcile(
        tmp_path, FakeHealth([False]), TARGET, flash=flash,
    )

    # Every candidate's flash blew up in a different, non-FlashError way.
    # reconcile() must still return a ReconcileResult, not propagate any of
    # them.
    assert result == ReconcileResult(healthy=False, action="exhausted")


# --- Finding 2 (Important): load() must be guarded like the health check ---
#
# `load_artifact` begins with `Path(path).read_bytes()`, which raises
# MemoryError -- not an OSError -- if an interrupted download left a
# multi-gigabyte current.bin on a memory-constrained Linux side.


def test_load_raising_memory_error_skips_candidate_and_tries_next(tmp_path):
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    def load(path):
        if path.name == "current.bin":
            raise MemoryError("cannot allocate 4GB")
        return load_artifact(path)

    result = reconcile(
        tmp_path, FakeHealth([False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
        load=load,
    )

    assert flashed == ["golden.bin"]
    assert result == ReconcileResult(healthy=True, action="reflashed", image="golden.bin")


def test_load_raising_oserror_is_distinct_from_artifacterror_and_still_skips(tmp_path):
    # Regression guard: OSError from `load` (e.g. the file vanishing between
    # is_file() and read_bytes()) must be handled the same way as
    # ArtifactError (a validation failure), not treated differently.
    _seed(tmp_path, "current.bin", "golden.bin")
    flashed = []

    def load(path):
        if path.name == "current.bin":
            raise OSError("file vanished after is_file() returned True")
        return load_artifact(path)

    result = reconcile(
        tmp_path, FakeHealth([False, True]), TARGET,
        flash=lambda artifact, target: flashed.append(artifact.path.name),
        load=load,
    )

    assert flashed == ["golden.bin"]
    assert result == ReconcileResult(healthy=True, action="reflashed", image="golden.bin")
