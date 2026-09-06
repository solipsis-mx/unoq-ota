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
