from __future__ import annotations

import subprocess
from pathlib import Path
from subprocess import TimeoutExpired

from unoq_ota.net import PROC_ROUTE, SYS_NET, default_route_iface, driver_of as _driver_of, iface_kind

DEFAULT_SIGNAL_CMD = ("mmcli", "--modem", "any", "--output-keyvalue")
DEFAULT_MIN_QUALITY = 20
PROBE_TIMEOUT_S = 5.0


def parse_signal_quality(keyvalue: str) -> int | None:
    for raw in keyvalue.splitlines():
        line = raw.strip()
        if "modem.generic.signal-quality.value" not in line:
            continue
        _, _, rest = line.partition(":")
        try:
            value = int(rest.strip())
        except ValueError:
            return None
        if 0 <= value <= 100:
            return value
        return None
    return None


class CellularSignalGate:
    def __init__(
        self,
        min_quality: int = DEFAULT_MIN_QUALITY,
        signal_cmd=None,
        timeout_s: float = PROBE_TIMEOUT_S,
        *,
        proc_path: Path = PROC_ROUTE,
        sys_net: Path = SYS_NET,
        run=subprocess.run,
        driver_of=_driver_of,
    ):
        self.min_quality = int(min_quality)
        self.signal_cmd = list(signal_cmd or DEFAULT_SIGNAL_CMD)
        self.timeout_s = timeout_s
        self.proc_path = proc_path
        self.sys_net = sys_net
        self._run = run
        self._driver_of = driver_of

    def may_flash(self):
        return True, "always allowed"

    def may_fetch(self):
        iface = default_route_iface(proc_path=self.proc_path)
        if iface is None:
            return True, "no default route"
        driver = self._driver_of(iface, sys_net=self.sys_net)
        kind = iface_kind(iface, driver)
        if kind != "cellular":
            return True, f"default route {iface} is {kind}"
        try:
            proc = self._run(
                self.signal_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except TimeoutExpired:
            return False, f"mmcli timed out after {self.timeout_s:.0f}s"
        except OSError as exc:
            return False, f"mmcli failed: {exc}"
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            detail = err[0] if err else f"exit {proc.returncode}"
            return False, f"mmcli failed: {detail}"
        quality = parse_signal_quality(proc.stdout or "")
        if quality is None:
            return False, "no signal-quality.value in mmcli"
        reason = f"quality={quality} min={self.min_quality}"
        return quality >= self.min_quality, reason
