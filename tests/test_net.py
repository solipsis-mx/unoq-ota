from __future__ import annotations

from unoq_ota.net import default_route_iface, iface_kind, parse_default_routes

_BOTH = """\
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enxe6decdc549e4	00000000	01E1A8C0	0003	0	0	100	00000000	0	0	0
wlan0	00000000	0144A8C0	0003	0	0	50	00000000	0	0	0
"""


def test_lowest_metric_wins():
    assert default_route_iface(_BOTH) == "wlan0"


def test_parse_defaults_ignores_on_link_subnets():
    routes = parse_default_routes(_BOTH)
    assert routes == [("enxe6decdc549e4", 100), ("wlan0", 50)]


def test_cdc_ether_is_cellular_even_when_named_enx():
    assert iface_kind("enxe6decdc549e4", "cdc_ether") == "cellular"


def test_usb_ethernet_dock_is_unmetered():
    assert iface_kind("enx00e04c6802d9", "r8152") == "ethernet"


def test_usb0_prefix_is_cellular_before_rename():
    assert iface_kind("usb0", None) == "cellular"


def test_wlan_is_wifi_without_a_driver():
    assert iface_kind("wlan0", None) == "wifi"
