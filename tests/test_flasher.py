from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from unoq_ota import flasher
from unoq_ota.board import FlashTarget
from unoq_ota.flasher import FlashError, build_write_script, run_openocd


def test_write_script_wraps_flash_ops_in_catch():
    # Without catch, a thrown TCL error aborts before `shutdown` and OpenOCD
    # falls through to its server loop, holding the SWD lines forever.
    script = build_write_script(Path("/tmp/x.bin"), 0x08100000)
    assert script.count("catch") >= 2
    assert "shutdown" in script


def test_write_script_uses_the_given_address_not_a_default():
    script = build_write_script(Path("/tmp/x.bin"), 0x08100000)
    assert "0x08100000" in script
    assert "0x80F0000" not in script


def test_write_script_verifies_after_writing():
    script = build_write_script(Path("/tmp/x.bin"), 0x08100000)
    assert "write_image erase" in script
    assert "verify_image" in script


def test_run_openocd_raises_on_nonzero_exit(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="boom", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError, match="exit 1"):
        run_openocd("init; shutdown")


def test_run_openocd_raises_on_timeout(monkeypatch):
    # stm32u5x.cfg contains unbounded spin loops that never terminate on an
    # undervolted target, so the timeout is load-bearing, not decoration.
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="openocd", timeout=5)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError, match="timed out"):
        run_openocd("init; shutdown", timeout_s=5)


def test_run_openocd_raises_when_the_script_reported_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="WRITE-FAILED: cannot erase", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError, match="WRITE-FAILED"):
        run_openocd("init; shutdown")


def test_run_openocd_returns_output_on_success(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="WRITE-AND-VERIFY-OK", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert "OK" in run_openocd("init; shutdown")


def test_write_sketch_refuses_an_artifact_larger_than_the_partition(tmp_path, monkeypatch):
    from unoq_ota.artifact import SketchArtifact, SketchHeader

    artifact = SketchArtifact(
        path=tmp_path / "big.bin",
        header=SketchHeader(ver=1, length=999999, magic=0x2341, flags=0),
        size=999999,
        sha256="0" * 64,
    )
    target = FlashTarget(address=0x08100000, max_size=786432, core_version="1.0.0")

    with pytest.raises(FlashError, match="larger than the sketch partition"):
        flasher.write_sketch(artifact, target)
