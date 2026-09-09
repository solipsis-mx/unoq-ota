from __future__ import annotations

from subprocess import CompletedProcess, TimeoutExpired

from unoq_ota.gates.always import AlwaysGate
from unoq_ota.gates.cellular_signal import CellularSignalGate, parse_signal_quality

_WIFI = """\
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0144A8C0	0003	0	0	50	00000000	0	0	0
"""

_LTE = """\
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enxf643e57c8cc2	00000000	01E1A8C0	0003	0	0	100	00000000	0	0	0
"""

_MMCLI_60 = "modem.generic.signal-quality.value\t: 60\n"


def test_always_gate_permits_flashing():
    allowed, reason = AlwaysGate().may_flash()
    assert allowed is True
    assert isinstance(reason, str) and reason


def test_always_gate_permits_fetch():
    allowed, reason = AlwaysGate().may_fetch()
    assert allowed is True
    assert reason


def test_parse_signal_quality_reads_mmcli_keyvalue():
    assert parse_signal_quality(_MMCLI_60) == 60
    assert parse_signal_quality("modem.generic.state : connected\n") is None
    assert parse_signal_quality("modem.generic.signal-quality.value : 101\n") is None


def test_wifi_default_allows_without_probe(tmp_path):
    called = []

    def run(*args, **kwargs):
        called.append(1)
        return CompletedProcess(args[0], 0, stdout=_MMCLI_60, stderr="")

    route = tmp_path / "route"
    route.write_text(_WIFI)
    gate = CellularSignalGate(proc_path=route, run=run, driver_of=lambda iface, **k: None)
    allowed, reason = gate.may_fetch()
    assert allowed is True
    assert called == []


def test_enx_cdc_ether_checks_quality(tmp_path):
    def run(*args, **kwargs):
        return CompletedProcess(args[0], 0, stdout=_MMCLI_60, stderr="")

    route = tmp_path / "route"
    route.write_text(_LTE)
    gate = CellularSignalGate(
        min_quality=20,
        proc_path=route,
        run=run,
        driver_of=lambda iface, **k: "cdc_ether",
    )
    allowed, reason = gate.may_fetch()
    assert allowed is True
    assert "quality=60" in reason
    assert "min=20" in reason


def test_enx_r8152_is_ethernet_no_probe(tmp_path):
    called = []

    def run(*args, **kwargs):
        called.append(1)
        return CompletedProcess(args[0], 0, stdout=_MMCLI_60, stderr="")

    route = tmp_path / "route"
    route.write_text(_LTE.replace("enxf643e57c8cc2", "enx00e04c6802d9"))
    gate = CellularSignalGate(
        proc_path=route,
        run=run,
        driver_of=lambda iface, **k: "r8152",
    )
    allowed, _ = gate.may_fetch()
    assert allowed is True
    assert called == []


def test_cellular_below_floor_refuses(tmp_path):
    def run(*args, **kwargs):
        return CompletedProcess(args[0], 0, stdout=_MMCLI_60, stderr="")

    route = tmp_path / "route"
    route.write_text(_LTE)
    gate = CellularSignalGate(
        min_quality=100,
        proc_path=route,
        run=run,
        driver_of=lambda iface, **k: "cdc_ether",
    )
    allowed, reason = gate.may_fetch()
    assert allowed is False
    assert "quality=60" in reason
    assert "min=100" in reason


def test_missing_quality_refuses(tmp_path):
    def run(*args, **kwargs):
        return CompletedProcess(args[0], 0, stdout="error: modem has no extended signal capabilities\n", stderr="")

    route = tmp_path / "route"
    route.write_text(_LTE)
    gate = CellularSignalGate(
        proc_path=route,
        run=run,
        driver_of=lambda iface, **k: "cdc_ether",
    )
    allowed, reason = gate.may_fetch()
    assert allowed is False
    assert "signal-quality" in reason


def test_mmcli_timeout_refuses(tmp_path):
    def run(*args, **kwargs):
        raise TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 5))

    route = tmp_path / "route"
    route.write_text(_LTE)
    gate = CellularSignalGate(
        proc_path=route,
        run=run,
        driver_of=lambda iface, **k: "cdc_ether",
    )
    allowed, reason = gate.may_fetch()
    assert allowed is False
    assert "timed out" in reason


def test_mmcli_nonzero_refuses(tmp_path):
    def run(*args, **kwargs):
        return CompletedProcess(args[0], 1, stdout="", stderr="error: couldn't find modem")

    route = tmp_path / "route"
    route.write_text(_LTE)
    gate = CellularSignalGate(
        proc_path=route,
        run=run,
        driver_of=lambda iface, **k: "cdc_ether",
    )
    allowed, reason = gate.may_fetch()
    assert allowed is False
    assert "mmcli failed" in reason


def test_no_default_route_allows_without_probe(tmp_path):
    called = []

    def run(*args, **kwargs):
        called.append(1)
        return CompletedProcess(args[0], 0, stdout=_MMCLI_60, stderr="")

    route = tmp_path / "route"
    route.write_text("Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT\n")
    gate = CellularSignalGate(proc_path=route, run=run, driver_of=lambda iface, **k: None)
    allowed, _ = gate.may_fetch()
    assert allowed is True
    assert called == []
