"""Classify the Linux default route for a fetch gate."""
from __future__ import annotations

from pathlib import Path

PROC_ROUTE = Path("/proc/net/route")
SYS_NET = Path("/sys/class/net")

WIFI_PREFIXES = ("wlan", "mlan", "wifi")
CELLULAR_PREFIXES = ("wwan", "rmnet", "usb0")
CELLULAR_DRIVERS = frozenset(
    {
        "cdc_ether",
        "cdc_ncm",
        "cdc_mbim",
        "qmi_wwan",
        "rndis_host",
    }
)


def parse_default_routes(proc_text: str) -> list[tuple[str, int]]:
    """Return (iface, metric) for IPv4 default routes in /proc/net/route text."""
    out: list[tuple[str, int]] = []
    lines = proc_text.splitlines()
    if not lines:
        return out
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, _gateway, _flags, _ref, _use, metric = parts[:7]
        if dest != "00000000":
            continue
        try:
            out.append((iface, int(metric)))
        except ValueError:
            continue
    return out


def default_route_iface(
    proc_text: str | None = None, *, proc_path: Path = PROC_ROUTE
) -> str | None:
    """Lowest-metric IPv4 default-route device, or None if there isn't one."""
    if proc_text is None:
        try:
            proc_text = proc_path.read_text(encoding="ascii", errors="replace")
        except OSError:
            return None
    routes = parse_default_routes(proc_text)
    if not routes:
        return None
    iface, _metric = min(routes, key=lambda item: item[1])
    return iface


def driver_of(iface: str, *, sys_net: Path = SYS_NET) -> str | None:
    link = sys_net / iface / "device" / "driver"
    try:
        return link.resolve().name
    except OSError:
        return None


def iface_kind(iface: str, driver: str | None = None) -> str:
    """Return wifi, cellular, ethernet, or other."""
    name = iface.lower()
    if name.startswith(WIFI_PREFIXES):
        return "wifi"
    if name.startswith(CELLULAR_PREFIXES):
        return "cellular"
    drv = (driver or "").lower()
    if drv in CELLULAR_DRIVERS:
        return "cellular"
    if name.startswith(("eth", "enx", "ens", "enp", "eno")):
        return "ethernet"
    return "other"
