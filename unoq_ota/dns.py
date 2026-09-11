"""Fix libc DNS when wifi-down leaves LAN nameservers on a cellular default.

NetworkManager sometimes rewrites `/etc/resolv.conf` to the ECM gateway and
8.8.8.8 on wifi-off, and sometimes leaves CasaPR-style RFC1918 nameservers
that are no longer on-link. Writing *before* wifi-off is useless: NM overwrites
the file on disconnect. Call this *after* the default route is cellular.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

from unoq_ota.net import (
    PROC_ROUTE,
    SYS_NET,
    default_route_gateway,
    default_route_iface,
    driver_of,
    iface_kind,
)

log = logging.getLogger(__name__)

RESOLV_PATH = Path("/etc/resolv.conf")
PUBLIC_FALLBACK = "8.8.8.8"


def parse_nameservers(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.lower().startswith("nameserver"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            out.append(parts[1])
    return out


def nameserver_usable(ns: str, gateway: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(ns)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        return False
    if not addr.is_private:
        return True
    if gateway and ns == gateway:
        return True
    if gateway:
        try:
            gw = ipaddress.ip_address(gateway)
        except ValueError:
            return False
        if addr.version == 4 and gw.version == 4 and addr.packed[:3] == gw.packed[:3]:
            return True
    return False


def libc_dns_usable(nameservers: list[str], gateway: str | None) -> bool:
    return any(nameserver_usable(ns, gateway) for ns in nameservers)


def inject_resolv_text(existing: str, nameservers: list[str]) -> str:
    kept = [
        line
        for line in existing.splitlines()
        if not line.strip().lower().startswith("nameserver")
    ]
    injected = [f"nameserver {ns}" for ns in nameservers]
    body = kept + injected
    text = "\n".join(body)
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def ensure_libc_dns(
    *,
    resolv_path: Path = RESOLV_PATH,
    proc_path: Path = PROC_ROUTE,
    sys_net: Path = SYS_NET,
) -> str:
    """Rewrite resolv.conf when the default route is cellular and libc DNS is dead.

    Returns a short reason. Never raises: a PermissionError on write is logged
    so Jobs/MQTT can still try (systemd will retry).
    """
    iface = default_route_iface(proc_path=proc_path)
    if iface is None:
        return "skipped: no default route"
    driver = driver_of(iface, sys_net=sys_net)
    if iface_kind(iface, driver) != "cellular":
        return "unchanged: default route is not cellular"
    gateway = default_route_gateway(proc_path=proc_path)
    try:
        text = resolv_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("could not read %s: %s", resolv_path, exc)
        text = ""
    nameservers = parse_nameservers(text)
    if libc_dns_usable(nameservers, gateway):
        return "unchanged: libc DNS usable"
    planned = []
    if gateway:
        planned.append(gateway)
    if PUBLIC_FALLBACK not in planned:
        planned.append(PUBLIC_FALLBACK)
    new_text = inject_resolv_text(text, planned)
    try:
        resolv_path.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        log.warning("cannot write %s: %s", resolv_path, exc)
        return f"cannot write {resolv_path}: {exc}"
    reason = f"injected nameserver {' '.join(planned)}"
    log.info("%s into %s", reason, resolv_path)
    return reason


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="If the default route is cellular and /etc/resolv.conf "
        "still points at off-link LAN DNS, rewrite it to the default-route "
        "gateway plus 8.8.8.8. Call after wifi is down; writing before NM "
        "disconnects is overwritten."
    )
    parser.parse_args(argv)
    print(ensure_libc_dns())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
