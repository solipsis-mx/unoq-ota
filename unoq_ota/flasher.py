"""Driving the STM32 over SWD, via the OpenOCD already on the board.

Measured on real hardware (docs/bench-results.md): an erase + write + verify
of a ~79 KB sketch takes about 7.5 seconds, and reads run at roughly
13 KB/s. No root is required -- membership in the gpiod group is enough.

Two details are load-bearing rather than cosmetic:

* Every flash operation -- including the `init`/`reset`/`halt` preamble,
  `flash info 0`, and the trailing `reset` that starts the new firmware --
  is wrapped in TCL `catch`. Without it a thrown error aborts the script
  before `shutdown`, and OpenOCD falls through into its server loop, holding
  the SWD lines and the lock indefinitely. These are exactly the commands
  that throw when the target is unresponsive or undervolted, so none of them
  can be left uncaught.
* Every invocation runs under a wall-clock timeout. stm32u5x.cfg's clock
  configuration contains unbounded spin loops that never terminate on an
  undervolted target.
"""

from __future__ import annotations

import contextlib
import logging
import subprocess
from pathlib import Path

from unoq_ota.artifact import SketchArtifact, SketchHeader, parse_header
from unoq_ota.board import FlashTarget

log = logging.getLogger(__name__)

OPENOCD_BIN = "/opt/openocd/bin/openocd"
OPENOCD_ROOT = "/opt/openocd"
OPENOCD_CFG = "openocd_gpiod.cfg"
ROUTER_UNIT = "arduino-router"

# reset_config is a configuration command, not a target operation -- it
# cannot itself throw from an unresponsive target, so it stays outside the
# catch guards. init/reset/halt are exactly the commands that throw when the
# target is unresponsive or undervolted, so each one is individually
# catch-guarded: a thrown error here must still reach `shutdown`, or OpenOCD
# falls through into its server loop holding the SWD lines.
_PREAMBLE = (
    "reset_config srst_only srst_push_pull\n"
    'if {[catch {init} err]} { echo "INIT-FAILED: $err"; shutdown error }\n'
    'if {[catch {reset} err]} { echo "INIT-FAILED: $err"; shutdown error }\n'
    'if {[catch {halt} err]} { echo "INIT-FAILED: $err"; shutdown error }\n'
)

_FAILURE_MARKERS = (
    "INIT-FAILED",
    "PROBE-FAILED",
    "WRITE-FAILED",
    "VERIFY-FAILED",
    "READ-FAILED",
    "RESET-FAILED",
)


class FlashError(Exception):
    """A flash operation failed or could not be completed safely."""


def _summarize(output: str) -> str:
    """Keep head and tail of a long OpenOCD log instead of only the tail.

    A pure tail-truncation can discard an early fatal error in favour of
    trailing boilerplate, and whoever reads this may be deciding whether to
    physically visit a device.
    """
    output = output.strip()
    if len(output) <= 1000:
        return output
    elided = len(output) - 1000
    return f"{output[:500]}\n...[{elided} chars elided]...\n{output[-500:]}"


# The trailing `reset` (after a successful write or read) starts the newly
# staged firmware, or restores normal execution after a read. It is exactly
# as capable of throwing on an unresponsive/undervolted target as the
# preamble's reset, so it gets the same catch guard -- with its own marker,
# RESET-FAILED, so a failed final reset doesn't read as a failed preamble in
# the logs. A write that succeeded but didn't reset is still a failure: the
# whole point of the reset is to start the new firmware, and if it didn't
# happen, the firmware is not running.
_TRAILING_RESET = (
    'if {[catch {reset} err]} { echo "RESET-FAILED: $err"; shutdown error }\n'
    "shutdown\n"
)


def build_write_script(image: Path, address: int) -> str:
    addr = f"0x{address:08x}"
    return (
        _PREAMBLE
        + 'if {[catch {flash info 0} err]} { echo "PROBE-FAILED: $err"; shutdown error }\n'
        + f'if {{[catch {{flash write_image erase {image} {addr} bin}} err]}} '
        + '{ echo "WRITE-FAILED: $err"; shutdown error }\n'
        + f'if {{[catch {{flash verify_image {image} {addr} bin}} err]}} '
        + '{ echo "VERIFY-FAILED: $err"; shutdown error }\n'
        + 'echo "WRITE-AND-VERIFY-OK"\n'
        + _TRAILING_RESET
    )


def build_read_script(dest: Path, address: int, length: int) -> str:
    addr = f"0x{address:08x}"
    return (
        _PREAMBLE
        + f'if {{[catch {{dump_image {dest} {addr} {length}}} err]}} '
        + '{ echo "READ-FAILED: $err"; shutdown error }\n'
        + 'echo "READ-OK"\n'
        + _TRAILING_RESET
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
    except OSError as exc:
        # subprocess.run's documented exceptions are TimeoutExpired and
        # FileNotFoundError, but exec() can fail in other OSError-shaped ways
        # this module doesn't control: the binary loses its exec bit
        # (PermissionError), it's mid-rewrite by a concurrent update
        # (ETXTBSY), or fork() fails under memory pressure (ENOMEM). Normalize
        # all of those to this function's one documented failure mode --
        # FlashError -- with the original message preserved, so every caller
        # (including the reconciler, which cannot control what its injected
        # `flash` callable raises) can rely on catching just FlashError here.
        raise FlashError(f"openocd could not be started: {exc}")

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise FlashError(f"openocd exit {proc.returncode}: {_summarize(output)}")
    for marker in _FAILURE_MARKERS:
        if marker in output:
            raise FlashError(f"{marker} in openocd output: {_summarize(output)}")
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
    actual = dest.stat().st_size
    if actual != length:
        raise FlashError(
            f"openocd reported success but {dest} is {actual} bytes, expected {length}"
        )
    return dest


def read_resident_header(address: int, timeout_s: float = 60.0) -> SketchHeader:
    """Read the header of whatever is currently flashed.

    Used to detect drift: current.bin is a belief, and it is wrong the moment
    anyone uses the IDE, App Lab, or a network upload.
    """
    tmp = Path("/tmp/unoq-ota-resident-header.bin")
    read_partition(tmp, address, 16, timeout_s=timeout_s)
    return parse_header(tmp.read_bytes())


def _running_dependents(run, unit: str, timeout: float = 15.0) -> list:
    """Services that pull `unit` in and are running right now.

    Discovered rather than listed: which units depend on the router is a
    property of the image on the device, not of this package, and hardcoding
    one image's unit names here would be wrong for every other integrator.

    Every failure mode -- no systemctl, a timeout, an unparsable answer --
    degrades to an empty list. Restoring nothing is exactly the behaviour
    this guard had before; being unable to enumerate dependents is not a
    reason to refuse to flash.
    """
    try:
        listed = run(
            ["systemctl", "list-dependencies", "--reverse", "--plain", "--no-pager", unit],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("could not list what depends on %s: %s", unit, exc)
        return []
    if getattr(listed, "returncode", 1) != 0:
        return []

    candidates = []
    for line in (getattr(listed, "stdout", "") or "").splitlines():
        name = line.strip().lstrip("\u25cf\u25cb\u2500\u2502\u251c\u2514 ").strip()
        # Targets are deliberately skipped: a propagated stop does not take
        # them down, and starting one would pull in far more than this guard
        # ever touched.
        if not name.endswith(".service"):
            continue
        if name in (unit, unit + ".service") or name in candidates:
            continue
        candidates.append(name)
    if not candidates:
        return []

    try:
        states = run(
            ["systemctl", "is-active", *candidates],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("could not check which dependents of %s are running: %s", unit, exc)
        return []
    # `is-active` exits non-zero when *any* argument is inactive, so its
    # return code says nothing useful here; the per-unit answers do.
    reported = (getattr(states, "stdout", "") or "").split()
    return [name for name, state in zip(candidates, reported) if state == "active"]


@contextlib.contextmanager
def router_stopped(run=subprocess.run, unit: str = ROUTER_UNIT):
    """Stop arduino-router for the duration of a flash, then restore it.

    That unit toggles GPIO 38 -- the SWD reset line -- in its ExecStopPost,
    and is Restart=always. If it restarts while we are erasing, systemd
    asserts reset on the target mid-write. Stopping it deliberately means the
    reset happens at a moment we choose, before OpenOCD's own preamble does
    its own reset/halt -- an extra, harmless assertion of a line that is
    about to be driven again anyway. Restart=always does not undo this: that
    policy governs the unit exiting on its own, not an administrative
    `systemctl stop`, so the unit stays down for the whole write window
    without systemd fighting us over it.

    Restarting is in a finally block: leaving the router down would cost the
    board its host communication, which is worse than a failed update.

    `run()` itself, not just its return code, is guarded: on a host with no
    `systemctl` at all (missing binary, broken PATH, a bench Mac) `run()`
    raises OSError before returning anything. Only the return-code failure
    was handled below originally, which is exactly the kind of asymmetric
    guard that turns "flashing anyway" into an uncaught crash on the one
    class of host most likely to hit it.

    Both calls also carry a wall-clock `timeout`, matching this module's own
    docstring promise that every invocation runs under one. `systemctl stop`
    blocks until the unit's `ExecStop`/`ExecStopPost` complete -- and
    `ExecStopPost` is the GPIO-38 toggle this guard exists because of -- so a
    wedged systemd or D-Bus would otherwise hang the agent inside the flash
    window indefinitely. `subprocess.TimeoutExpired` is not an `OSError`, so
    both except clauses below now catch it explicitly: adding the timeout
    alone would have opened a new escape path out of `run_once`, uncaught --
    exactly the crash-loop failure this project has hit before.
    """
    stopped = False
    restore = []
    try:
        # Recorded before the stop, because after it they are already down.
        restore = _running_dependents(run, unit)
        try:
            result = run(
                # `stop` alone is not enough on a stock image: a sibling unit
                # that Requires= this one and is Restart=always turns our stop
                # into "Job for ... canceled" -- systemd honouring the newer
                # start job. An irreversible stop job may not be cancelled that
                # way, which is the whole point of the guard: GPIO 38 (SWD
                # reset) must stay still for the duration of an erase.
                ["systemctl", "stop", "--job-mode=replace-irreversibly", unit],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning(
                "could not run systemctl to stop %s: %s; flashing anyway", unit, exc
            )
        else:
            stopped = getattr(result, "returncode", 1) == 0
            if not stopped:
                # systemctl's own line is the whole diagnosis -- an
                # authorisation refusal, an unknown unit and a unit that
                # refuses to stop all arrive here as the same return code,
                # and the operator reading this log has nothing else to go
                # on. Both streams are captured above; either may carry it.
                detail = " ".join(
                    part.strip()
                    for part in (
                        getattr(result, "stderr", "") or "",
                        getattr(result, "stdout", "") or "",
                    )
                    if part and part.strip()
                )
                log.warning(
                    "could not stop %s; flashing anyway%s",
                    unit,
                    f": {detail}" if detail else "",
                )
        yield stopped
    finally:
        if stopped:
            try:
                # Everything the stop propagated to comes back with it. Those
                # units were stopped by systemd, not by their own exit, so
                # `Restart=` does not bring them back and the board would be
                # left without whatever they provide -- host communication,
                # in the case this was written for.
                run(
                    ["systemctl", "start", unit, *restore],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                log.warning("could not restart %s after flashing: %s", unit, exc)
