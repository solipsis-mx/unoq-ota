"""Driving the STM32 over SWD, via the OpenOCD already on the board.

Measured on real hardware (docs/bench-results.md): an erase + write + verify
of a ~79 KB sketch takes about 7.5 seconds, and reads run at roughly
13 KB/s. No root is required -- membership in the gpiod group is enough.

Two details are load-bearing rather than cosmetic:

* Every flash operation is wrapped in TCL `catch`. Without it a thrown error
  aborts the script before `shutdown`, and OpenOCD falls through into its
  server loop, holding the SWD lines and the lock indefinitely.
* Every invocation runs under a wall-clock timeout. stm32u5x.cfg's clock
  configuration contains unbounded spin loops that never terminate on an
  undervolted target.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from unoq_ota.artifact import SketchArtifact, SketchHeader, parse_header
from unoq_ota.board import FlashTarget

OPENOCD_BIN = "/opt/openocd/bin/openocd"
OPENOCD_ROOT = "/opt/openocd"
OPENOCD_CFG = "openocd_gpiod.cfg"

_PREAMBLE = "reset_config srst_only srst_push_pull\ninit\nreset\nhalt\n"


class FlashError(Exception):
    """A flash operation failed or could not be completed safely."""


def build_write_script(image: Path, address: int) -> str:
    addr = f"0x{address:08x}"
    return (
        _PREAMBLE
        + "flash info 0\n"
        + f'if {{[catch {{flash write_image erase {image} {addr} bin}} err]}} '
        + '{ echo "WRITE-FAILED: $err"; shutdown error }\n'
        + f'if {{[catch {{flash verify_image {image} {addr} bin}} err]}} '
        + '{ echo "VERIFY-FAILED: $err"; shutdown error }\n'
        + 'echo "WRITE-AND-VERIFY-OK"\n'
        + "reset\nshutdown\n"
    )


def build_read_script(dest: Path, address: int, length: int) -> str:
    addr = f"0x{address:08x}"
    return (
        _PREAMBLE
        + f'if {{[catch {{dump_image {dest} {addr} {length}}} err]}} '
        + '{ echo "READ-FAILED: $err"; shutdown error }\n'
        + 'echo "READ-OK"\n'
        + "reset\nshutdown\n"
    )


def run_openocd(script: str, timeout_s: float = 120.0) -> str:
    cmd = [OPENOCD_BIN, "-s", OPENOCD_ROOT, "-f", OPENOCD_CFG, "-c", script]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except subprocess.TimeoutExpired:
        raise FlashError(
            f"openocd timed out after {timeout_s}s; the target may be undervolted"
        )
    except FileNotFoundError:
        raise FlashError(f"openocd not found at {OPENOCD_BIN}")

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise FlashError(f"openocd exit {proc.returncode}: {output.strip()[-500:]}")
    for marker in ("WRITE-FAILED", "VERIFY-FAILED", "READ-FAILED"):
        if marker in output:
            raise FlashError(f"{marker} in openocd output: {output.strip()[-500:]}")
    return output


def write_sketch(
    artifact: SketchArtifact, target: FlashTarget, timeout_s: float = 120.0
) -> None:
    if artifact.size > target.max_size:
        raise FlashError(
            f"artifact is {artifact.size} bytes, larger than the sketch partition "
            f"({target.max_size} bytes)"
        )
    run_openocd(build_write_script(artifact.path, target.address), timeout_s=timeout_s)


def read_partition(
    dest: Path, address: int, length: int, timeout_s: float = 300.0
) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    run_openocd(build_read_script(dest, address, length), timeout_s=timeout_s)
    if not dest.is_file():
        raise FlashError(f"openocd reported success but {dest} was not written")
    return dest


def read_resident_header(address: int, timeout_s: float = 60.0) -> SketchHeader:
    """Read the header of whatever is currently flashed.

    Used to detect drift: current.bin is a belief, and it is wrong the moment
    anyone uses the IDE, App Lab, or a network upload.
    """
    tmp = Path("/tmp/unoq-ota-resident-header.bin")
    read_partition(tmp, address, 16, timeout_s=timeout_s)
    return parse_header(tmp.read_bytes())
