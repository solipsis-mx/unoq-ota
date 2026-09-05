from __future__ import annotations

from unoq_ota.health.version_report import VersionReportHealthCheck, parse_health_line


def test_parses_a_health_line():
    assert parse_health_line("OTA-HEALTH test-1.0.0 seq=41") == ("test-1.0.0", 41)


def test_ignores_unrelated_output():
    assert parse_health_line("[boot] 1/4 something alive") is None
    assert parse_health_line("") is None
    assert parse_health_line("OTA-HEALTH malformed") is None


class _Check(VersionReportHealthCheck):
    def __init__(self, version, lines):
        super().__init__(version)
        self._lines = lines

    def _collect(self, timeout_s):
        return self._lines


def test_healthy_when_version_matches_and_seq_advances():
    check = _Check("1.0.0", ["OTA-HEALTH 1.0.0 seq=1", "OTA-HEALTH 1.0.0 seq=2"])
    assert check.wait_healthy(5) is True


def test_unhealthy_when_the_version_is_wrong():
    # An old image that survived a failed flash reports the old version. Without
    # the identity check that is indistinguishable from a successful update.
    check = _Check("2.0.0", ["OTA-HEALTH 1.0.0 seq=1", "OTA-HEALTH 1.0.0 seq=2"])
    assert check.wait_healthy(5) is False


def test_unhealthy_when_seq_never_advances():
    # Firmware wedged after its first report is not healthy.
    check = _Check("1.0.0", ["OTA-HEALTH 1.0.0 seq=7", "OTA-HEALTH 1.0.0 seq=7"])
    assert check.wait_healthy(5) is False


def test_unhealthy_on_silence():
    assert _Check("1.0.0", []).wait_healthy(5) is False


def test_unhealthy_on_a_single_report():
    assert _Check("1.0.0", ["OTA-HEALTH 1.0.0 seq=1"]).wait_healthy(5) is False
