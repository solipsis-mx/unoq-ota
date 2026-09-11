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
    return [(iface, metric) for iface, metric, _gateway in parse_default_route_rows(proc_text)]


def ipv4_from_proc_hex(hex_le: str) -> str | None:
    """Decode a `/proc/net/route` little-endian IPv4 hex field to dotted-quad."""
    try:
        raw = int(hex_le, 16)
    except (TypeError, ValueError):
        return None
    return f"{raw & 0xFF}.{(raw >> 8) & 0xFF}.{(raw >> 16) & 0xFF}.{(raw >> 24) & 0xFF}"


def parse_default_route_rows(proc_text: str) -> list[tuple[str, int, str | None]]:
    """Return (iface, metric, gateway) for IPv4 default routes."""
    out: list[tuple[str, int, str | None]] = []
    lines = proc_text.splitlines()
    if not lines:
        return out
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gateway_hex, _flags, _ref, _use, metric = parts[:7]
        if dest != "00000000":
            continue
        try:
            metric_i = int(metric)
        except ValueError:
            continue
        gateway = ipv4_from_proc_hex(gateway_hex)
        if gateway == "0.0.0.0":
            gateway = None
        out.append((iface, metric_i, gateway))
    return out


def default_route_iface(
    proc_text: str | None = None, *, proc_path: Path = PROC_ROUTE
) -> str | None:
    """Lowest-metric IPv4 default-route device, or None if there isn't one."""
    row = _lowest_default(proc_text, proc_path=proc_path)
    if row is None:
        return None
    iface, _metric, _gateway = row
    return iface


def default_route_gateway(
    proc_text: str | None = None, *, proc_path: Path = PROC_ROUTE
) -> str | None:
    """Gateway of the lowest-metric IPv4 default route, if any."""
    row = _lowest_default(proc_text, proc_path=proc_path)
    if row is None:
        return None
    _iface, _metric, gateway = row
    return gateway


def _lowest_default(
    proc_text: str | None = None, *, proc_path: Path = PROC_ROUTE
) -> tuple[str, int, str | None] | None:
    if proc_text is None:
        try:
            proc_text = proc_path.read_text(encoding="ascii", errors="replace")
        except OSError:
            return None
    routes = parse_default_route_rows(proc_text)
    if not routes:
        return None
    return min(routes, key=lambda item: item[1])


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
