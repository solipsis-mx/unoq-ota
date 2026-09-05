from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.conftest import make_artifact_bytes
from unoq_ota import flasher
from unoq_ota.board import FlashTarget
from unoq_ota.flasher import (
    FlashError,
    build_read_script,
    build_write_script,
    read_partition,
    read_resident_header,
    run_openocd,
)


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


def test_write_script_guards_the_init_preamble():
    # init/reset/halt are exactly the commands that throw when the target is
    # unresponsive or undervolted. Left uncaught, a throw here aborts the
    # script before shutdown and strands OpenOCD holding the SWD lines.
    script = build_write_script(Path("/tmp/x.bin"), 0x08100000)
    assert "INIT-FAILED" in script
    assert script.count("catch {init}") == 1
    assert script.count("catch {reset}") == 1
    assert script.count("catch {halt}") == 1
    assert "catch {flash info 0}" in script


def test_run_openocd_raises_when_the_preamble_reported_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="INIT-FAILED: target not halted", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError, match="INIT-FAILED"):
        run_openocd("init; shutdown")


def test_run_openocd_keeps_head_and_tail_of_a_long_error(monkeypatch):
    # A pure tail-truncation can discard an early fatal error in favour of
    # trailing boilerplate -- and this log may decide whether someone drives
    # out to a device.
    long_output = ("A" * 600) + "FATAL-MARKER-IN-MIDDLE" + ("B" * 600)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout=long_output, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError) as excinfo:
        run_openocd("init; shutdown")

    message = str(excinfo.value)
    assert "A" * 500 in message
    assert "B" * 500 in message
    assert "elided" in message


def test_run_openocd_passes_timeout_through_to_subprocess_run(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    run_openocd("init; shutdown", timeout_s=42)

    assert captured.get("timeout") == 42


def test_read_script_wraps_dump_image_in_catch_and_ends_in_shutdown():
    script = build_read_script(Path("/tmp/out.bin"), 0x08100000, 16)
    assert "catch" in script
    assert "dump_image" in script
    assert "0x08100000" in script
    assert script.rstrip().endswith("shutdown")


def test_read_script_guards_the_init_preamble():
    # Regression guard for fix 1: build_read_script must carry the same
    # INIT-FAILED guards as build_write_script.
    script = build_read_script(Path("/tmp/out.bin"), 0x08100000, 16)
    assert "INIT-FAILED" in script
    assert script.count("catch {init}") == 1
    assert script.count("catch {reset}") == 1
    assert script.count("catch {halt}") == 1


def test_read_partition_raises_when_the_dump_is_short(tmp_path, monkeypatch):
    dest = tmp_path / "out.bin"

    def fake_run(*args, **kwargs):
        # OpenOCD reports success but only wrote part of the requested bytes.
        dest.write_bytes(b"\x00" * 10)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="READ-OK", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError, match="16"):
        read_partition(dest, 0x08100000, 16)


def test_read_partition_raises_when_no_file_appears(tmp_path, monkeypatch):
    dest = tmp_path / "out.bin"

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="READ-OK", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(FlashError, match="not written"):
        read_partition(dest, 0x08100000, 16)


def test_read_partition_returns_the_path_on_a_correct_size_dump(tmp_path, monkeypatch):
    dest = tmp_path / "out.bin"
    body = make_artifact_bytes(body_len=16)[:16]

    def fake_run(*args, **kwargs):
        dest.write_bytes(body)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="READ-OK", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = read_partition(dest, 0x08100000, 16)

    assert result == dest
    assert result.read_bytes() == body


def test_read_resident_header_parses_the_header_from_the_dumped_bytes(tmp_path, monkeypatch):
    artifact_bytes = make_artifact_bytes(body_len=512)

    def fake_run(*args, **kwargs):
        Path("/tmp/unoq-ota-resident-header.bin").write_bytes(artifact_bytes[:16])
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="READ-OK", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    header = read_resident_header(0x08100000)

    assert header.ver == 1
    assert header.magic == 0x2341
