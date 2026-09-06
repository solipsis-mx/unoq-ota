from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_reconcile_unit_identifies_itself_in_the_journal():
    text = (ROOT / "systemd" / "unoq-ota-reconcile.service").read_text()
    assert "SyslogIdentifier=unoq-ota-reconcile" in text
    assert "StandardOutput=journal" in text
    assert "Environment=HOME=/home/arduino" in text


def test_agent_unit_identifies_itself_in_the_journal():
    text = (ROOT / "systemd" / "unoq-ota.service").read_text()
    assert "SyslogIdentifier=unoq-ota" in text
    assert "StandardOutput=journal" in text
    assert "EnvironmentFile=-/etc/unoq-ota/agent.env" in text


def test_units_document_the_core_root_override():
    """HOME=/home/arduino is a default for the stock image, not a requirement.

    Any other layout -- a different interactive account, a core installed
    system-wide -- must be reachable without editing the unit, so both units
    have to point the reader at UNOQ_OTA_CORE_ROOT in the environment file.
    """
    for name in ("unoq-ota-reconcile.service", "unoq-ota.service"):
        text = (ROOT / "systemd" / name).read_text()
        assert "UNOQ_OTA_CORE_ROOT" in text, name
