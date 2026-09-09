from types import SimpleNamespace

from unoq_ota.jobs_runner import (
    default_mqtt_client_id,
    handle_execution,
    run_jobs_loop,
)


def test_check_job_runs_one_cycle():
    calls = []
    status, detail = handle_execution({"operation": "check"}, lambda: calls.append("ran") or "idle")
    assert calls == ["ran"]
    assert status == "SUCCEEDED"


def test_unknown_operation_does_not_run_cycle():
    calls = []
    status, detail = handle_execution({"operation": "flash"}, lambda: calls.append("ran"))
    assert calls == []
    assert status == "FAILED"
    assert "unsupported" in detail


def test_cycle_exception_fails_the_job():
    def boom():
        raise RuntimeError("verify failed")

    status, detail = handle_execution({"operation": "check"}, boom)
    assert status == "FAILED"
    assert "verify failed" in detail


def test_run_jobs_loop_handles_each_execution_then_stops():
    calls = []
    updates = []

    class FakeClient:
        def __init__(self):
            self._jobs = [
                SimpleNamespace(job_id="j1", document={"operation": "check"}),
                SimpleNamespace(job_id="j2", document={"operation": "flash"}),
            ]

        def next_execution(self):
            return self._jobs.pop(0) if self._jobs else None

        def update_execution(self, job_id, status, detail):
            updates.append((job_id, status, detail))

    run_jobs_loop(FakeClient(), lambda: calls.append("ran") or "idle")

    assert calls == ["ran"]
    assert updates[0] == ("j1", "SUCCEEDED", "idle")
    assert updates[1][0] == "j2"
    assert updates[1][1] == "FAILED"
    assert "unsupported" in updates[1][2]


def test_default_mqtt_client_id_is_thing_dash_ota():
    assert default_mqtt_client_id("board-1") == "board-1-ota"
    assert default_mqtt_client_id("board-1") != "board-1"


def test_jobs_runner_does_not_import_awsiotsdk():
    import sys

    import unoq_ota.jobs_runner as jr  # noqa: F401

    assert not any(name == "awsiot" or name.startswith("awsiot.") for name in sys.modules)
