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


def test_timer_fires_daily_at_three_am_mexico_city():
    text = (ROOT / "systemd" / "unoq-ota.timer").read_text()
    assert "OnCalendar=*-*-* 03:00:00" in text
    assert "Timezone=America/Mexico_City" in text
    assert "Persistent=true" in text
    assert "RandomizedDelaySec=900" in text
    assert "Unit=unoq-ota.service" in text


def test_agent_unit_documents_once_no_flash_oneshot():
    text = (ROOT / "systemd" / "unoq-ota.service").read_text()
    assert "--once" in text
    assert "--no-flash" in text


def test_jobs_unit_is_a_long_running_listener():
    text = (ROOT / "systemd" / "unoq-ota-jobs.service").read_text()
    assert "Type=simple" in text
    assert "Restart=always" in text
    assert "User=root" in text
    assert "EnvironmentFile=-/etc/unoq-ota/agent.env" in text
    assert "ExecStart=/usr/local/bin/unoq-ota jobs" in text
    assert "solipsis" not in text.lower()
