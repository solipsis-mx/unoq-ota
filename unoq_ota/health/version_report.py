"""Health via the firmware's own version report.

Three assertions, and all three are needed:

    identity  -- the version reported is the version we flashed. An old image
                 that survived a failed flash otherwise looks like success.
    liveness  -- a report arrived at all.
    progress  -- seq advanced. Firmware wedged after its first line otherwise
                 reads as healthy.

Implementation note, from docs/bench-results.md: reading the MCU changes its
behaviour. Serial output is dropped unless a monitor is attached, and piping
the monitor through another process can swallow it entirely -- which looks
exactly like firmware that failed to boot. So output is always captured to a
file, never piped. For production, reporting over the router's packet protocol
is preferable to raw serial; see DESIGN.md.

The progress assertion checks more than "last seq > first seq": a device that
resets mid-window (5, 1, 8) or boot-loops (1, 2, 1, 2, ...) can still satisfy
that alone. It requires the sequence to never step backwards across the
collected reports *and* to show a net advance from first to last -- a single
backwards step anywhere in the window means the device restarted.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

HEALTH_RE = re.compile(r"^OTA-HEALTH\s+(\S+)\s+seq=(\d+)\s*$")
DEFAULT_MONITOR_CMD = ["arduino-app-cli", "monitor"]


def parse_health_line(line: str) -> tuple[str, int] | None:
    match = HEALTH_RE.match(line.strip())
    if not match:
        return None
    return match.group(1), int(match.group(2))


class VersionReportHealthCheck:
    def __init__(
        self,
        expected_version: str,
        monitor_cmd: list[str] | None = None,
        min_reports: int = 2,
    ) -> None:
        self.expected_version = expected_version
        self.monitor_cmd = list(monitor_cmd or DEFAULT_MONITOR_CMD)
        self.min_reports = min_reports

    def _collect(self, timeout_s: float) -> list[str]:
        """Run the monitor for timeout_s, capturing to a file.

        Never pipe: an interrupted pipe can discard everything buffered, and
        the result is indistinguishable from firmware that never booted.

        Any failure here -- the temp file can't be created, the monitor
        binary is missing, the log can't be read back -- is treated as "no
        reports collected" rather than left to raise. wait_healthy already
        maps zero reports to an unhealthy verdict, and this way a transient
        tooling failure and genuinely dead firmware fail the same, safe way
        (no false "healthy", and the caller sees a plain False instead of an
        exception from a plumbing detail it didn't ask about).
        """
        try:
            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as handle:
                log = Path(handle.name)
        except OSError:
            logger.warning(
                "health check: could not create temp file to capture monitor output",
                exc_info=True,
            )
            return []
        try:
            with log.open("w") as sink:
                proc = subprocess.Popen(self.monitor_cmd, stdout=sink, stderr=sink)
                try:
                    proc.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            return log.read_text(errors="replace").splitlines()
        except (OSError, ValueError):
            logger.warning(
                "health check: failed to run monitor command %r or read its captured output",
                self.monitor_cmd,
                exc_info=True,
            )
            return []
        finally:
            log.unlink(missing_ok=True)

    def wait_healthy(self, timeout_s: float) -> bool:
        reports = []
        for line in self._collect(timeout_s):
            parsed = parse_health_line(line)
            if parsed is not None:
                reports.append(parsed)

        matching = [seq for version, seq in reports if version == self.expected_version]
        if len(matching) < self.min_reports:
            return False
        return self._progressed(matching)

    @staticmethod
    def _progressed(seqs: list[int]) -> bool:
        """True if seqs never steps backwards and shows a net advance.

        A single backwards step anywhere in the window means the device
        restarted mid-check (or is boot-looping) and must read unhealthy --
        checking only the first and last sample lets a boot-looping counter
        (1, 2, 1, 2, ...) read healthy whenever the window happens to end
        higher than it started, which is roughly half the time.
        """
        for previous, current in zip(seqs, seqs[1:]):
            if current < previous:
                return False
        return seqs[-1] > seqs[0]
