from types import SimpleNamespace

from unoq_ota.interfaces import Status
from unoq_ota.jobs_runner import (
    default_mqtt_client_id,
    handle_execution,
    run_jobs_loop,
)
from unoq_ota.state import Phase


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
    assert updates[0][0] == "j1"
    assert updates[0][1] == "IN_PROGRESS"
    assert updates[1] == ("j1", "SUCCEEDED", "idle")
    assert updates[2][0] == "j2"
    assert updates[2][1] == "IN_PROGRESS"
    assert updates[3][0] == "j2"
    assert updates[3][1] == "FAILED"
    assert "unsupported" in updates[3][2]


def test_default_mqtt_client_id_is_thing_dash_ota():
    assert default_mqtt_client_id("board-1") == "board-1-ota"
    assert default_mqtt_client_id("board-1") != "board-1"


def test_jobs_runner_does_not_import_awsiotsdk():
    import sys

    import unoq_ota.jobs_runner as jr  # noqa: F401

    assert not any(name == "awsiot" or name.startswith("awsiot.") for name in sys.modules)


def test_sdk_shaped_job_document_runs_the_cycle():
    """awsiot.iotjobs.JobExecutionData exposes job_document, not document."""
    calls = []
    updates = []

    class FakeClient:
        def __init__(self):
            self._jobs = [
                SimpleNamespace(
                    job_id="j-sdk",
                    job_document={"operation": "check"},
                    execution_number=3,
                )
            ]

        def start_next(self):
            return None

        def next_execution(self):
            return self._jobs.pop(0) if self._jobs else None

        def update_execution(self, job_id, status, detail):
            updates.append((job_id, status, detail))

    run_jobs_loop(FakeClient(), lambda: calls.append("ran") or "idle")

    assert calls == ["ran"]
    assert any(job_id == "j-sdk" and status == "SUCCEEDED" for job_id, status, _ in updates)


def test_loop_claims_at_connect_and_after_each_terminal_update():
    events = []

    class FakeClient:
        def __init__(self):
            self._jobs = [SimpleNamespace(job_id="j1", document={"operation": "check"})]

        def start_next(self):
            events.append("start_next")

        def next_execution(self):
            events.append("next")
            return self._jobs.pop(0) if self._jobs else None

        def update_execution(self, job_id, status, detail):
            events.append(("update", status))

    run_jobs_loop(FakeClient(), lambda: "idle")

    assert events == [
        "start_next",
        "next",
        ("update", "IN_PROGRESS"),
        ("update", "SUCCEEDED"),
        "start_next",
        "next",
    ]


def test_notify_next_claims_instead_of_offering_and_dedupes(monkeypatch):
    import sys
    from unoq_ota.jobs_runner import AwsJobsClient

    fake_iotjobs = _FakeIotJobs()
    fake_awsiot = SimpleNamespace(iotjobs=fake_iotjobs)
    monkeypatch.setitem(sys.modules, "awsiot", fake_awsiot)
    monkeypatch.setitem(sys.modules, "awsiot.iotjobs", fake_iotjobs)

    sdk = _RecordingSdk()
    client = AwsJobsClient(sdk, "board-1", qos=1)
    assert sdk.start_next_calls == 1

    sdk_exec = SimpleNamespace(
        job_id="j1",
        job_document={"operation": "check"},
        execution_number=1,
    )
    client._on_next_changed(SimpleNamespace(execution=sdk_exec))
    assert sdk.start_next_calls == 2
    assert client._pending.empty()

    client._on_start_next(SimpleNamespace(execution=sdk_exec))
    client._on_start_next(SimpleNamespace(execution=sdk_exec))
    assert client._pending.qsize() == 1

    got = client.next_execution()
    assert got.job_id == "j1"
    assert got.document == {"operation": "check"}
    assert got.execution_number == 1
    assert client._pending.empty()

    client.update_execution("j1", "SUCCEEDED", "idle")
    assert sdk.start_next_calls == 3
    assert sdk.updates[-1][0] == "SUCCEEDED"


def test_rejected_phase_fails_the_job():
    status, detail = handle_execution({"operation": "check"}, lambda: Phase.REJECTED)
    assert status == "FAILED"
    assert "rejected" in detail.lower()


def test_idle_after_rejected_status_fails_the_job():
    result = SimpleNamespace(
        value="idle",
        reported_status=Status.REJECTED,
        detail="download failed: timeout",
    )
    status, detail = handle_execution({"operation": "check"}, lambda: result)
    assert status == "FAILED"
    assert "download failed" in detail


def test_verified_status_succeeds():
    result = SimpleNamespace(
        value="idle",
        reported_status=Status.VERIFIED,
        detail="verified, not applied",
    )
    status, detail = handle_execution({"operation": "check"}, lambda: result)
    assert status == "SUCCEEDED"


def test_wrap_run_cycle_maps_rejected_report_to_failed_job():
    from unoq_ota.jobs_runner import wrap_run_cycle

    class Src:
        def report(self, update, status, detail):
            self.last = (status, detail)

    src = Src()

    def run_once():
        src.report(None, Status.REJECTED, "download failed: timeout")
        return Phase.IDLE

    status, detail = handle_execution({"operation": "check"}, wrap_run_cycle(run_once, src))
    assert status == "FAILED"
    assert "download failed" in detail


def test_wrap_run_cycle_resets_report_between_cycles():
    """REJECTED then idle skip must not inherit the prior report."""
    from unoq_ota.jobs_runner import wrap_run_cycle

    class Src:
        def report(self, update, status, detail):
            pass

    src = Src()
    calls = []

    def run_once():
        calls.append("ran")
        if len(calls) == 1:
            src.report(None, Status.REJECTED, "download failed: timeout")
        return Phase.IDLE

    run_cycle = wrap_run_cycle(run_once, src)

    status1, detail1 = handle_execution({"operation": "check"}, run_cycle)
    assert status1 == "FAILED"
    assert "download failed" in detail1

    status2, detail2 = handle_execution({"operation": "check"}, run_cycle)
    assert status2 == "SUCCEEDED"
    assert detail2 == "idle"


class _FakeFuture:
    def result(self):
        return None


class _FakeIotJobs:
    class NextJobExecutionChangedSubscriptionRequest:
        def __init__(self, thing_name):
            self.thing_name = thing_name

    class StartNextPendingJobExecutionSubscriptionRequest:
        def __init__(self, thing_name):
            self.thing_name = thing_name

    class StartNextPendingJobExecutionRequest:
        def __init__(self, thing_name):
            self.thing_name = thing_name

    class UpdateJobExecutionRequest:
        def __init__(self, thing_name, job_id, status, status_details):
            self.thing_name = thing_name
            self.job_id = job_id
            self.status = status
            self.status_details = status_details

    class JobStatus:
        IN_PROGRESS = "IN_PROGRESS"
        SUCCEEDED = "SUCCEEDED"
        FAILED = "FAILED"


class _RecordingSdk:
    def __init__(self):
        self.start_next_calls = 0
        self.updates = []
        self._on_changed = None
        self._on_start = None

    def subscribe_to_next_job_execution_changed_events(self, request, qos, callback):
        self._on_changed = callback
        return (_FakeFuture(), _FakeFuture())

    def subscribe_to_start_next_pending_job_execution_accepted(self, request, qos, callback):
        self._on_start = callback
        return (_FakeFuture(), _FakeFuture())

    def publish_start_next_pending_job_execution(self, request, qos):
        self.start_next_calls += 1
        return _FakeFuture()

    def publish_update_job_execution(self, request, qos):
        self.updates.append((request.status, request.job_id))
        return _FakeFuture()
