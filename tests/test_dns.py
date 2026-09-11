"""Libc DNS after wifi-down: NM may leave LAN nameservers on a cellular default."""

from __future__ import annotations

import logging

from unoq_ota.dns import (
    PUBLIC_FALLBACK,
    ensure_libc_dns,
    inject_resolv_text,
    libc_dns_usable,
    parse_nameservers,
)

_CELLULAR_ROUTE = """\
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enxe6decdc549e4	00000000	01E1A8C0	0003	0	0	100	00000000	0	0	0
"""

_WIFI_ROUTE = """\
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0144A8C0	0003	0	0	50	00000000	0	0	0
"""

_STALE_LAN = "nameserver 192.168.1.254\nnameserver 192.168.68.1\n"
_ECM_OK = "nameserver 192.168.225.1\nnameserver 8.8.8.8\n"


def test_parse_nameservers_ignores_comments():
    text = "# generated\nnameserver 192.168.1.254\nsearch lan\nnameserver 8.8.8.8\n"
    assert parse_nameservers(text) == ["192.168.1.254", "8.8.8.8"]


def test_stale_lan_nameservers_are_unusable_on_cellular_gateway():
    assert libc_dns_usable(["192.168.1.254", "192.168.68.1"], "192.168.225.1") is False


def test_ecm_gateway_and_public_dns_are_usable():
    assert libc_dns_usable(["192.168.225.1", "8.8.8.8"], "192.168.225.1") is True


def test_wifi_lan_nameserver_matching_gateway_is_usable():
    assert libc_dns_usable(["192.168.68.1"], "192.168.68.1") is True


def test_empty_resolv_is_unusable():
    assert libc_dns_usable([], "192.168.225.1") is False


def test_inject_replaces_nameserver_lines_and_keeps_the_rest():
    text = inject_resolv_text(_STALE_LAN + "search lan\n", ["192.168.225.1", PUBLIC_FALLBACK])
    assert parse_nameservers(text) == ["192.168.225.1", PUBLIC_FALLBACK]
    assert "search lan" in text
    assert "192.168.1.254" not in text


def test_ensure_injects_after_wifi_off_leaves_lan_dns(tmp_path):
    resolv = tmp_path / "resolv.conf"
    proc = tmp_path / "route"
    resolv.write_text(_STALE_LAN)
    proc.write_text(_CELLULAR_ROUTE)
    sys_net = tmp_path / "sys"
    driver = sys_net / "enxe6decdc549e4" / "device" / "driver"
    driver.parent.mkdir(parents=True)
    cdc = tmp_path / "cdc_ether"
    cdc.mkdir()
    driver.symlink_to(cdc)

    reason = ensure_libc_dns(resolv_path=resolv, proc_path=proc, sys_net=sys_net)
    assert "injected" in reason
    assert parse_nameservers(resolv.read_text()) == ["192.168.225.1", PUBLIC_FALLBACK]


def test_ensure_does_not_rewrite_working_wifi_dns(tmp_path):
    resolv = tmp_path / "resolv.conf"
    proc = tmp_path / "route"
    resolv.write_text("nameserver 192.168.68.1\n")
    proc.write_text(_WIFI_ROUTE)
    original = resolv.read_text()

    reason = ensure_libc_dns(resolv_path=resolv, proc_path=proc, sys_net=tmp_path / "sys")
    assert "unchanged" in reason
    assert resolv.read_text() == original


def test_ensure_does_not_rewrite_when_nm_already_fixed_cellular_dns(tmp_path):
    resolv = tmp_path / "resolv.conf"
    proc = tmp_path / "route"
    resolv.write_text(_ECM_OK)
    proc.write_text(_CELLULAR_ROUTE)
    sys_net = tmp_path / "sys"
    driver = sys_net / "enxe6decdc549e4" / "device" / "driver"
    driver.parent.mkdir(parents=True)
    cdc = tmp_path / "cdc_ether"
    cdc.mkdir()
    driver.symlink_to(cdc)

    reason = ensure_libc_dns(resolv_path=resolv, proc_path=proc, sys_net=sys_net)
    assert "unchanged" in reason
    assert resolv.read_text() == _ECM_OK


def test_ensure_logs_and_continues_when_resolv_is_not_writable(tmp_path, caplog):
    import logging

    caplog.set_level(logging.WARNING)
    resolv = tmp_path / "resolv.conf"
    proc = tmp_path / "route"
    resolv.write_text(_STALE_LAN)
    resolv.chmod(0o444)
    proc.write_text(_CELLULAR_ROUTE)
    sys_net = tmp_path / "sys"
    driver = sys_net / "enxe6decdc549e4" / "device" / "driver"
    driver.parent.mkdir(parents=True)
    cdc = tmp_path / "cdc_ether"
    cdc.mkdir()
    driver.symlink_to(cdc)

    reason = ensure_libc_dns(resolv_path=resolv, proc_path=proc, sys_net=sys_net)
    assert "cannot write" in reason
    assert parse_nameservers(resolv.read_text()) == ["192.168.1.254", "192.168.68.1"]
    assert any("resolv.conf" in rec.getMessage() for rec in caplog.records)
