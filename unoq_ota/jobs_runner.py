"""IoT Jobs poke: parse a document, run one cycle, report SUCCEEDED/FAILED.

MQTT connect/subscribe stays behind a `JobsClient` protocol so unit tests
never import `awsiotsdk`. The real AWS client is built only when the
`jobs` CLI is invoked.
"""

from __future__ import annotations

import logging
import queue
from types import SimpleNamespace
from typing import Callable, Optional, Protocol

from unoq_ota.jobs_doc import JobDocumentError, parse_job_operation

log = logging.getLogger(__name__)

# connect().result() with no timeout kept a jobs listener "active" with no
# MQTT socket; systemd Restart=always never fired. Bound wait so a hung
# connect exits and the unit can recycle.
MQTT_CONNECT_TIMEOUT_S = 30.0


def ensure_plausible_clock(now=None) -> None:
    """Refuse Jobs MQTT when the clock cannot validate TLS or signatures.

    A 1970-epoch CLOCK_REALTIME makes CRT mTLS fail (cert NotBefore) or hang.
    Raise PreflightError *before* importing awsiotsdk so systemd Restart=always
    can retry after NTP. Do not prove this by setting the clock on a live board.
    """
    from unoq_ota.preflight import check_clock

    check_clock(now=now)


def ensure_libc_dns() -> str:
    """Rewrite libc DNS after wifi-down if LAN nameservers are off-link.

    Imported lazily so unit tests can monkeypatch this name on jobs_runner
    without importing awsiotsdk.
    """
    from unoq_ota.dns import ensure_libc_dns as _ensure

    return _ensure()


class JobExecution(Protocol):
    job_id: str
    document: object
    execution_number: object


class JobsClient(Protocol):
    """Injectable Jobs control plane. AWS names in comments only.

    `start_next` is StartNextPendingJobExecution (claim).
    `next_execution` is a claimed execution (StartNext accepted).
    `update_execution` is UpdateJobExecution.
    """

    def start_next(self) -> None:
        """Claim the next queued job, or no-op if none is pending."""

    def next_execution(self) -> Optional[JobExecution]:
        """Return the next claimed execution, or None to stop the loop."""

    def update_execution(self, job_id: str, status: str, detail: str) -> None:
        """Report IN_PROGRESS, SUCCEEDED, or FAILED for `job_id`."""


def default_mqtt_client_id(thing_name: str) -> str:
    """Second MQTT connection; must not equal the telemetry id `{thing}`."""
    return f"{thing_name}-ota"


def require_distinct_mqtt_client_id(thing_name: str, client_id: str) -> str:
    """Refuse a clientId that would knock the telemetry connection off the broker."""
    if client_id == thing_name:
        raise ValueError(
            f"mqtt client_id {client_id!r} must not equal the thing name "
            "(that id is already used by telemetry; a second connection would evict it)"
        )
    return client_id


def adapt_execution(raw) -> Optional[SimpleNamespace]:
    """Normalize SDK (`job_document`) and protocol (`document`) executions."""
    if raw is None:
        return None
    job_id = getattr(raw, "job_id", None)
    if not job_id:
        return None
    document = getattr(raw, "document", None)
    if document is None:
        document = getattr(raw, "job_document", None)
    return SimpleNamespace(
        job_id=job_id,
        document=document,
        execution_number=getattr(raw, "execution_number", None),
    )


def wrap_run_cycle(run_once: Callable[[], object], source) -> Callable[[], object]:
    """Capture the last `source.report` so Jobs can map status and detail.

    `Agent.run_once` often returns `Phase.IDLE` after reporting
    `Status.REJECTED` or `Status.VERIFIED`. The wrapper does not
    change flash or commit paths.
    """
    last = {"status": None, "detail": ""}
    original = source.report

    def report(update, status, detail):
        last["status"] = status
        last["detail"] = detail
        return original(update, status, detail)

    source.report = report

    def run_cycle():
        last["status"] = None
        last["detail"] = ""
        phase = run_once()
        return SimpleNamespace(
            value=getattr(phase, "value", phase),
            phase=phase,
            reported_status=last["status"],
            detail=last["detail"],
        )

    return run_cycle


def _enum_value(value) -> object:
    return getattr(value, "value", value)


def _status_from_cycle(result) -> tuple[str, str]:
    phase = _enum_value(getattr(result, "value", result))
    reported = _enum_value(getattr(result, "reported_status", None))
    extra = getattr(result, "detail", None)
    extra_s = str(extra) if extra else ""
    if phase == "rejected" or reported == "rejected":
        if extra_s:
            return "FAILED", extra_s
        return "FAILED", "" if phase is None else str(phase)
    if reported == "waiting_for_gate":
        return "FAILED", extra_s or str(reported)
    if reported == "verified":
        return "SUCCEEDED", extra_s or "verified, not applied"
    if reported == "committed":
        return "SUCCEEDED", extra_s or str(phase)
    if reported in (None, "") and phase in (None, "idle"):
        return "SUCCEEDED", extra_s or "up to date"
    return "FAILED", extra_s or ("" if phase is None else str(phase))


def handle_execution(document, run_cycle: Callable[[], object]) -> tuple[str, str]:
    try:
        parse_job_operation(document)
    except JobDocumentError as exc:
        return "FAILED", str(exc)
    try:
        result = run_cycle()
    except Exception as exc:
        return "FAILED", str(exc)
    return _status_from_cycle(result)


def run_jobs_loop(client: JobsClient, run_cycle: Callable[[], object]) -> None:
    start_next = getattr(client, "start_next", None)
    if callable(start_next):
        start_next()
    while True:
        execution = adapt_execution(client.next_execution())
        if execution is None:
            return
        log.info("job %s: running check", execution.job_id)
        client.update_execution(execution.job_id, "IN_PROGRESS", "running check")
        status, detail = handle_execution(execution.document, run_cycle)
        log.info("job %s: %s %s", execution.job_id, status, detail)
        client.update_execution(execution.job_id, status, detail)
        if callable(start_next):
            start_next()


def wait_mqtt_connected(connection, timeout_s: float = MQTT_CONNECT_TIMEOUT_S) -> None:
    """Block until the CRT MQTT future completes, or raise so systemd can restart."""
    log.info("MQTT connecting (timeout %.0fs)", timeout_s)
    try:
        connection.connect().result(timeout=timeout_s)
    except TimeoutError as exc:
        raise TimeoutError(f"MQTT connect timed out after {timeout_s:.0f}s") from exc
    log.info("MQTT connected")


def build_aws_jobs_client(
    endpoint: str,
    cert_filepath: str,
    pri_key_filepath: str,
    ca_filepath: str,
    thing_name: str,
    client_id: str,
):
    """Construct the awsiotsdk Jobs client. Imported only at call time."""
    require_distinct_mqtt_client_id(thing_name, client_id)
    ensure_plausible_clock()
    ensure_libc_dns()
    try:
        from awscrt import mqtt
        from awsiot import iotjobs, mqtt_connection_builder
    except ImportError as exc:
        raise RuntimeError(
            "jobs requires awsiotsdk; install with: pip install 'unoq-ota[aws]'"
        ) from exc

    connection = mqtt_connection_builder.mtls_from_path(
        endpoint=endpoint,
        cert_filepath=cert_filepath,
        pri_key_filepath=pri_key_filepath,
        ca_filepath=ca_filepath,
        client_id=client_id,
        clean_session=True,
        keep_alive_secs=30,
    )
    wait_mqtt_connected(connection)
    return AwsJobsClient(iotjobs.IotJobsClient(connection), thing_name, mqtt.QoS.AT_LEAST_ONCE)


class AwsJobsClient:
    """Blocking wrapper around awsiot.iotjobs.IotJobsClient.

    Subscribes to NextJobExecutionChanged and StartNextPendingJobExecution
    accepted. Notify-next is a wake-up to StartNext (claim); only the
    accepted claimed execution is offered to the loop. Topic strings are
    formed by the SDK from the thing name; this module never embeds account IDs.
    """

    def __init__(self, sdk_client, thing_name: str, qos) -> None:
        from awsiot import iotjobs

        self._sdk = sdk_client
        self._thing_name = thing_name
        self._qos = qos
        self._pending: queue.Queue = queue.Queue()
        self._offered: set[str] = set()

        changed = self._sdk.subscribe_to_next_job_execution_changed_events(
            request=iotjobs.NextJobExecutionChangedSubscriptionRequest(thing_name=thing_name),
            qos=qos,
            callback=self._on_next_changed,
        )
        accepted = self._sdk.subscribe_to_start_next_pending_job_execution_accepted(
            request=iotjobs.StartNextPendingJobExecutionSubscriptionRequest(thing_name=thing_name),
            qos=qos,
            callback=self._on_start_next,
        )
        # subscribe_* returns (subscribe_future, unsubscribe_future)
        if isinstance(changed, tuple):
            changed[0].result()
        if isinstance(accepted, tuple):
            accepted[0].result()

        self.start_next()

    def start_next(self) -> None:
        from awsiot import iotjobs

        self._sdk.publish_start_next_pending_job_execution(
            request=iotjobs.StartNextPendingJobExecutionRequest(thing_name=self._thing_name),
            qos=self._qos,
        )

    def _offer(self, execution) -> None:
        adapted = adapt_execution(execution)
        if adapted is None:
            return
        if adapted.job_id in self._offered:
            return
        self._offered.add(adapted.job_id)
        self._pending.put(adapted)

    def _on_next_changed(self, event) -> None:
        execution = getattr(event, "execution", None)
        if execution is not None and getattr(execution, "job_id", None):
            self.start_next()

    def _on_start_next(self, response) -> None:
        self._offer(getattr(response, "execution", None))

    def next_execution(self) -> Optional[JobExecution]:
        return self._pending.get()

    def update_execution(self, job_id: str, status: str, detail: str) -> None:
        from awsiot import iotjobs

        request = iotjobs.UpdateJobExecutionRequest(
            thing_name=self._thing_name,
            job_id=job_id,
            status=getattr(iotjobs.JobStatus, status),
            status_details={"detail": detail[:1024]},
        )
        self._sdk.publish_update_job_execution(request, self._qos).result()
        if status in {"SUCCEEDED", "FAILED"}:
            self.start_next()
