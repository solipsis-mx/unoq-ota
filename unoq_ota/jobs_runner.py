"""IoT Jobs poke: parse a document, run one cycle, report SUCCEEDED/FAILED.

MQTT connect/subscribe stays behind a `JobsClient` protocol so unit tests
never import `awsiotsdk`. The real AWS client is built only when the
`jobs` CLI is invoked.
"""

from __future__ import annotations

import logging
import queue
from typing import Callable, Optional, Protocol

from unoq_ota.jobs_doc import JobDocumentError, parse_job_operation

log = logging.getLogger(__name__)


class JobExecution(Protocol):
    job_id: str
    document: object


class JobsClient(Protocol):
    """Injectable Jobs control plane. AWS names in comments only.

    `next_execution` is StartNextPendingJobExecution / NextJobExecutionChanged.
    `update_execution` is UpdateJobExecution.
    """

    def next_execution(self) -> Optional[JobExecution]:
        """Return the next pending execution, or None to stop the loop."""

    def update_execution(self, job_id: str, status: str, detail: str) -> None:
        """Report SUCCEEDED or FAILED for `job_id`."""


def default_mqtt_client_id(thing_name: str) -> str:
    """Second MQTT connection; must not equal the telemetry id `{thing}`."""
    return f"{thing_name}-ota"


def handle_execution(document, run_cycle: Callable[[], object]) -> tuple[str, str]:
    try:
        parse_job_operation(document)
    except JobDocumentError as exc:
        return "FAILED", str(exc)
    try:
        result = run_cycle()
    except Exception as exc:
        return "FAILED", str(exc)
    detail = getattr(result, "value", result)
    return "SUCCEEDED", "" if detail is None else str(detail)


def run_jobs_loop(client: JobsClient, run_cycle: Callable[[], object]) -> None:
    while True:
        execution = client.next_execution()
        if execution is None:
            return
        log.info("job %s: running check", execution.job_id)
        status, detail = handle_execution(execution.document, run_cycle)
        log.info("job %s: %s %s", execution.job_id, status, detail)
        client.update_execution(execution.job_id, status, detail)


def build_aws_jobs_client(
    endpoint: str,
    cert_filepath: str,
    pri_key_filepath: str,
    ca_filepath: str,
    thing_name: str,
    client_id: str,
):
    """Construct the awsiotsdk Jobs client. Imported only at call time."""
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
    connection.connect().result()
    return AwsJobsClient(iotjobs.IotJobsClient(connection), thing_name, mqtt.QoS.AT_LEAST_ONCE)


class AwsJobsClient:
    """Blocking wrapper around awsiot.iotjobs.IotJobsClient.

    Subscribes to NextJobExecutionChanged and StartNextPendingJobExecution
    accepted, then claims any already-queued job. Topic strings are formed
    by the SDK from the thing name; this module never embeds account IDs.
    """

    def __init__(self, sdk_client, thing_name: str, qos) -> None:
        from awsiot import iotjobs

        self._sdk = sdk_client
        self._thing_name = thing_name
        self._qos = qos
        self._pending: queue.Queue = queue.Queue()

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

        self._sdk.publish_start_next_pending_job_execution(
            request=iotjobs.StartNextPendingJobExecutionRequest(thing_name=thing_name),
            qos=qos,
        )

    def _offer(self, execution) -> None:
        if execution is not None and getattr(execution, "job_id", None):
            self._pending.put(execution)

    def _on_next_changed(self, event) -> None:
        self._offer(getattr(event, "execution", None))

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
