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


def test_unhealthy_on_a_boot_loop():
    # Counter restarts every cycle. Comparing only first/last would read this
    # healthy whenever the window happens to end higher than it started.
    check = _Check(
        "1.0.0",
        [
            "OTA-HEALTH 1.0.0 seq=1",
            "OTA-HEALTH 1.0.0 seq=2",
            "OTA-HEALTH 1.0.0 seq=1",
            "OTA-HEALTH 1.0.0 seq=2",
        ],
    )
    assert check.wait_healthy(5) is False


def test_unhealthy_on_a_mid_window_reset():
    # First and last alone would read 8 > 5 as healthy, missing the reset.
    check = _Check(
        "1.0.0",
        ["OTA-HEALTH 1.0.0 seq=5", "OTA-HEALTH 1.0.0 seq=1", "OTA-HEALTH 1.0.0 seq=8"],
    )
    assert check.wait_healthy(5) is False


def test_healthy_on_a_clean_monotonic_run():
    check = _Check(
        "1.0.0",
        ["OTA-HEALTH 1.0.0 seq=1", "OTA-HEALTH 1.0.0 seq=2", "OTA-HEALTH 1.0.0 seq=3"],
    )
    assert check.wait_healthy(5) is True


def test_collect_runs_the_real_subprocess_path_and_parses_its_output():
    # Exercises the actual _collect implementation -- temp-file capture,
    # Popen, and read-back -- against a harmless local command instead of
    # the monitor. None of the tests above touch this path; they all
    # override _collect entirely.
    check = VersionReportHealthCheck(
        "test-1.0.0",
        monitor_cmd=[
            "printf",
            "OTA-HEALTH test-1.0.0 seq=1\nOTA-HEALTH test-1.0.0 seq=2\n",
        ],
    )
    lines = check._collect(5)
    parsed = [parse_health_line(line) for line in lines]
    assert [p for p in parsed if p is not None] == [
        ("test-1.0.0", 1),
        ("test-1.0.0", 2),
    ]
    assert check.wait_healthy(5) is True


def test_collect_returns_no_reports_when_the_command_is_silent():
    # A command that exits cleanly without printing anything -- the real
    # _collect path must come back empty, and wait_healthy must read
    # unhealthy, not raise.
    check = VersionReportHealthCheck("test-1.0.0", monitor_cmd=["true"])
    assert check._collect(5) == []
    assert check.wait_healthy(5) is False


def test_wait_alive_returns_the_version_that_progressed():
    check = _Check("ignored", ["OTA-HEALTH 1.4.0 seq=1", "OTA-HEALTH 1.4.0 seq=2"])
    assert check.wait_alive(5) == "1.4.0"


def test_wait_alive_returns_none_on_silence():
    assert _Check("ignored", []).wait_alive(5) is None


def test_wait_alive_returns_none_when_seq_does_not_advance():
    check = _Check("ignored", ["OTA-HEALTH 1.4.0 seq=7", "OTA-HEALTH 1.4.0 seq=7"])
    assert check.wait_alive(5) is None


def test_wait_alive_does_not_require_a_particular_identity():
    # The reconciler must accept whatever firmware is running, including
    # after an IDE upload the agent never heard of. Pinning expected_version
    # to "" made every real report look dead.
    check = VersionReportHealthCheck(expected_version=None)
    check._collect = lambda timeout_s: ["OTA-HEALTH ide-build seq=3", "OTA-HEALTH ide-build seq=4"]
    assert check.wait_alive(5) == "ide-build"
    assert check.wait_healthy(5) is False


def test_tcp_monitor_reads_health_lines_from_a_local_socket():
    import socket
    import threading
    import time

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        try:
            conn.sendall(b"OTA-HEALTH bench-wifi-1 seq=1\nOTA-HEALTH bench-wifi-1 seq=2\n")
            time.sleep(0.2)
        finally:
            conn.close()
            server.close()

    threading.Thread(target=serve, daemon=True).start()
    check = VersionReportHealthCheck(
        "bench-wifi-1", monitor_addr=("127.0.0.1", port)
    )
    assert check.wait_healthy(2) is True
