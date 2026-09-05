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
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

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
            return log.read_text(errors="replace").splitlines()
        except (OSError, ValueError):
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
        return matching[-1] > matching[0]
