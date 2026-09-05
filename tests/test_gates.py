from __future__ import annotations

from unoq_ota.gates.always import AlwaysGate


def test_always_gate_permits_flashing():
    allowed, reason = AlwaysGate().may_flash()
    assert allowed is True
    assert isinstance(reason, str) and reason
