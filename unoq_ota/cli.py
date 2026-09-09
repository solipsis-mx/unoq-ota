"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from unoq_ota.agent import Agent
from unoq_ota.artifact import load_artifact
from unoq_ota.board import resolve_flash_target
from unoq_ota.events import JOURNAL_NAME, EventLog
from unoq_ota.flasher import read_partition
from unoq_ota.gates.always import AlwaysGate
from unoq_ota.health.version_report import VersionReportHealthCheck
from unoq_ota.jobs_runner import (
    build_aws_jobs_client,
    default_mqtt_client_id,
    run_jobs_loop,
    wrap_run_cycle,
)
from unoq_ota.keyring import load_keyring
from unoq_ota.preflight import MAX_PAYLOAD_BYTES
from unoq_ota.reconciler import reconcile
from unoq_ota.sources.http_manifest import HttpManifestSource, download
from unoq_ota.sources.local import LocalFileSource
from unoq_ota.sources.reporting import ReportingSource
from unoq_ota.sources.s3_presigned import S3Error, S3PresignedSource, download_s3
from unoq_ota.state import DEFAULT_STATE_DIR, StateError, StateStore

log = logging.getLogger(__name__)


def _load_public_keys(keys_dir: Path) -> dict:
    """Load Ed25519 public keys from `<key_id>.public.b64` files.

    Thin wrapper around `unoq_ota.keyring.load_keyring`, kept as its own
    function (rather than calling `load_keyring` at the `_run` call site)
    only to add the one behaviour that is specific to `run` rather than to
    the keyring concept in general: a keyring that loaded zero usable keys
    is worth its own warning here, because an agent constructed with an
    empty one rejects every manifest it is ever offered, and that is a much
    easier failure to miss in a log than "directory not found" is.
    """
    keys = load_keyring(keys_dir)
    if not keys:
        log.warning("no usable keys loaded from %s; every manifest will be rejected", keys_dir)
    return keys


def _fetch(
    url: str,
    dest: Path,
    source_dir: Path | None,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    s3_client=None,
) -> None:
    """Fetch an artifact named by a manifest's `artifact.url`.

    An http(s) URL is downloaded with `unoq_ota.sources.http_manifest`'s own
    size-capped, cleans-up-on-failure `download()`. An `s3://` URI is
    presigned at fetch time and then streamed through the same downloader.
    A `file://` URL or a bare path is treated as local -- resolved against
    `source_dir` when relative -- which is what makes `LocalFileSource`
    usable for bench and air-gapped setups where the artifact sits next to
    `manifest.json` rather than behind a URL. Anything else (e.g. `ftp://`)
    is an explicit configuration mistake: silently treating it as a local
    path used to fail safely -- "download failed", from a `FileNotFoundError`
    on a path that was never a path -- but hid the real cause, so it is
    rejected here instead.
    """
    scheme = urlsplit(url).scheme
    if scheme in ("http", "https"):
        download(url, dest, max_bytes=max_bytes)
        return
    if scheme == "s3":
        # Mint a short-lived GET at fetch time so the signed manifest can
        # name an s3:// object identity instead of a URL that expires.
        download_s3(url, dest, max_bytes=max_bytes, client=s3_client)
        return
    if scheme not in ("", "file"):
        raise ValueError(
            f"unsupported URL scheme {scheme!r} in artifact url {url!r} "
            "(expected http, https, s3, file, or a bare path)"
        )
    raw_path = url[len("file://") :] if scheme == "file" else url
    src = Path(raw_path)
    if not src.is_absolute() and source_dir is not None:
        src = source_dir / src
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())


def _resolve_device_id(args) -> str:
    return getattr(args, "device_id", None) or socket.gethostname()


def _event_log(args) -> EventLog:
    report_url = getattr(args, "report_url", None) or None
    return EventLog(
        Path(args.state_dir) / JOURNAL_NAME,
        device_id=_resolve_device_id(args),
        report_url=report_url,
    )


def _print_status(args) -> int:
    store = StateStore(Path(args.state_dir) / "state.json")
    state = store.load()
    events = _event_log(args)
    payload = {
        "device": events.device_id,
        "phase": state.phase.value,
        "version": state.version,
        "committed_version": state.committed_version,
        "previous_version": state.previous_version,
        "sequence": state.sequence,
        "poisoned": state.poisoned,
        "last_event": events.last(),
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return 0
    last = payload["last_event"]
    print(f"device={payload['device']}")
    print(f"phase={payload['phase']}")
    print(f"version={payload['version']}")
    print(f"committed_version={payload['committed_version']}")
    print(f"sequence={payload['sequence']}")
    if last:
        print(f"last_event={last.get('kind')} {last.get('status') or last.get('action')} {last.get('detail') or last.get('image') or ''}".rstrip())
    else:
        print("last_event=")
    return 0


def _host_hooks(args):
    """Optional systemd restart + liveness for a host payload.

    Site-specific: the operator names the unit. This package never assumes
    what Linux software sits next to the sketch.
    """
    unit = getattr(args, "host_unit", None)
    if not unit:
        return None, None

    def restart():
        subprocess.run(["systemctl", "restart", unit], check=False, timeout=120)

    def healthy():
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", "--quiet", unit],
                check=False,
                timeout=30,
            )
            return proc.returncode == 0
        except OSError:
            return False

    return restart, healthy


def _build_agent(args, source_parser: argparse.ArgumentParser) -> Agent:
    """Wire a source, the gate, health checks and the store into an Agent.

    This is the composition root: the only place anything in this package
    decides where updates come from and what "healthy" means for a given
    deployment. Everything else -- Agent, the sources, the health check --
    stays deployment-agnostic.
    """
    target = resolve_flash_target(getattr(args, "core_root", None))
    public_keys = _load_public_keys(args.keys_dir)
    # Shared with the Agent's own internal StateStore, which is created at
    # the same `state_dir / "state.json"` path (see unoq_ota/agent.py). This
    # instance exists only so `is_poisoned` can be handed to the source as
    # its `poisoned` predicate -- without it, a source defaults to
    # `lambda version: False`, and a version that already failed its health
    # check and was poisoned keeps being offered and re-downloaded forever.
    store = StateStore(Path(args.state_dir) / "state.json")

    # One number, two places: the cap the fetch enforces while writing a
    # payload and the room the disk preflight reserves for one. They are the
    # same policy, and a site whose host tarball is bigger than the default
    # has to be able to raise both together.
    max_payload = getattr(args, "max_payload_bytes", None) or MAX_PAYLOAD_BYTES
    s3_client = None
    s3_region = getattr(args, "s3_region", None)

    if args.source == "local":
        if not args.source_dir:
            source_parser.error("--source local requires --source-dir")
        source = LocalFileSource(args.source_dir, poisoned=store.is_poisoned)
        fetch = lambda url, dest: _fetch(url, dest, args.source_dir, max_payload)  # noqa: E731
    elif args.source == "s3":
        if not args.manifest_url:
            source_parser.error("--source s3 requires --manifest-url (an s3:// URI)")
        try:
            from unoq_ota.sources.s3_presigned import default_client

            s3_client = default_client(s3_region)
            source = S3PresignedSource(
                args.manifest_url,
                poisoned=store.is_poisoned,
                jitter_s=args.jitter,
                s3_client=s3_client,
                region=s3_region,
            )
        except S3Error as exc:
            source_parser.error(str(exc))
        except ValueError as exc:
            source_parser.error(str(exc))
        fetch = lambda url, dest: _fetch(  # noqa: E731
            url, dest, None, max_payload, s3_client=s3_client
        )
    else:
        if not args.manifest_url:
            source_parser.error("--source http requires --manifest-url")
        source = HttpManifestSource(
            args.manifest_url, poisoned=store.is_poisoned, jitter_s=args.jitter
        )
        fetch = lambda url, dest: _fetch(url, dest, None, max_payload)  # noqa: E731

    source = ReportingSource(source, _event_log(args))
    host_restart, host_health = _host_hooks(args)
    host_dir = getattr(args, "host_dir", None)

    return Agent(
        state_dir=args.state_dir,
        source=source,
        gate=AlwaysGate(),
        health_factory=lambda version: VersionReportHealthCheck(expected_version=version),
        target=target,
        public_keys=public_keys,
        fetch=fetch,
        host_dir=host_dir,
        host_restart=host_restart,
        host_health=host_health,
        host_max_bytes=max_payload,
        no_flash=args.no_flash,
    )


def _run(args, run_parser: argparse.ArgumentParser) -> int:
    agent = _build_agent(args, run_parser)
    while True:
        phase = agent.run_once()
        log.info("cycle complete: phase=%s", phase.value)
        if args.once:
            return 0
        time.sleep(args.poll_interval)


def _jobs(args, jobs_parser: argparse.ArgumentParser) -> int:
    """Listen for IoT Jobs and run one verify-only cycle per poke."""
    missing = []
    if not getattr(args, "iot_endpoint", None):
        missing.append("--iot-endpoint (or UNOQ_OTA_IOT_ENDPOINT)")
    if not getattr(args, "iot_cert", None):
        missing.append("--iot-cert (or UNOQ_OTA_IOT_CERT)")
    if not getattr(args, "iot_key", None):
        missing.append("--iot-key (or UNOQ_OTA_IOT_KEY)")
    if not getattr(args, "iot_ca", None):
        missing.append("--iot-ca (or UNOQ_OTA_IOT_CA)")
    if not getattr(args, "thing_name", None):
        missing.append("--thing-name (or UNOQ_OTA_IOT_THING)")
    if missing:
        jobs_parser.error("jobs requires " + ", ".join(missing))

    args.no_flash = True
    agent = _build_agent(args, jobs_parser)
    thing_name = args.thing_name
    client_id = args.mqtt_client_id or default_mqtt_client_id(thing_name)
    client = build_aws_jobs_client(
        endpoint=args.iot_endpoint,
        cert_filepath=str(args.iot_cert),
        pri_key_filepath=str(args.iot_key),
        ca_filepath=str(args.iot_ca),
        thing_name=thing_name,
        client_id=client_id,
    )
    run_jobs_loop(client, wrap_run_cycle(agent.run_once, agent.source))
    return 0


def _dispatch(args, run_parser: argparse.ArgumentParser, jobs_parser: argparse.ArgumentParser | None = None) -> int:
    if args.command == "target":
        print(resolve_flash_target(args.core_root))
        return 0

    if args.command == "validate":
        artifact = load_artifact(args.artifact)
        print(f"OK  size={artifact.size}  sha256={artifact.sha256}")
        return 0

    if args.command == "backup":
        target = resolve_flash_target(args.core_root)
        read_partition(args.out, target.address, args.length)
        print(f"dumped {args.length} bytes to {args.out}")
        return 0

    if args.command == "status":
        return _print_status(args)

    if args.command == "reconcile":
        target = resolve_flash_target(args.core_root)
        health = VersionReportHealthCheck()
        result = reconcile(args.state_dir, health, target)
        _event_log(args).record(
            kind="reconcile",
            action=result.action,
            image=result.image,
            healthy=result.healthy,
        )
        print(f"healthy={result.healthy} action={result.action} image={result.image}")
        return 0 if result.healthy else 1

    if args.command == "run":
        return _run(args, run_parser)

    if args.command == "jobs":
        return _jobs(args, jobs_parser or run_parser)

    return 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="unoq-ota")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--report-url",
        default=os.environ.get("UNOQ_OTA_REPORT_URL"),
        help="POST each OTA event as JSON (also reads UNOQ_OTA_REPORT_URL)",
    )
    parser.add_argument(
        "--core-root",
        type=Path,
        default=(
            Path(os.environ["UNOQ_OTA_CORE_ROOT"])
            if os.environ.get("UNOQ_OTA_CORE_ROOT")
            else None
        ),
        help=(
            "Arduino installation holding the zephyr core: the core directory, "
            "an .arduino15 directory, or the home directory that owns one "
            "(default: $HOME/.arduino15/..., also reads UNOQ_OTA_CORE_ROOT)"
        ),
    )
    parser.add_argument(
        "--device-id",
        default=os.environ.get("UNOQ_OTA_DEVICE_ID"),
        help="identity in journal and reports (default: hostname, or UNOQ_OTA_DEVICE_ID)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("reconcile", help="recover the MCU if it is not healthy")
    status = sub.add_parser("status", help="print agent state and the last journal event")
    status.add_argument("--json", action="store_true")
    sub.add_parser("target", help="print the resolved flash target")

    backup = sub.add_parser("backup", help="dump the resident sketch to a file")
    backup.add_argument("--out", type=Path, required=True)
    backup.add_argument("--length", type=int, default=786432)

    validate = sub.add_parser("validate", help="check an artifact without flashing")
    validate.add_argument("artifact", type=Path)

    source_parent = argparse.ArgumentParser(add_help=False)
    source_parent.add_argument("--source", choices=("local", "http", "s3"), required=True)
    source_parent.add_argument(
        "--source-dir", type=Path, default=None, help="directory holding manifest.json (local source)"
    )
    source_parent.add_argument(
        "--manifest-url",
        default=None,
        help="URL to poll for manifest.json (http source) or s3://bucket/key (s3 source)",
    )
    source_parent.add_argument(
        "--s3-region",
        default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        help="AWS region for the s3 source (also reads AWS_REGION)",
    )
    source_parent.add_argument(
        "--keys-dir", type=Path, required=True, help="directory of <key_id>.public.b64 trusted keys"
    )
    source_parent.add_argument(
        "--jitter", type=float, default=30.0, help="max random delay before an http poll (seconds)"
    )
    source_parent.add_argument(
        "--host-dir",
        type=Path,
        default=None,
        help="directory to unpack host_payload into (default: <state-dir>/host)",
    )
    source_parent.add_argument(
        "--max-payload-bytes",
        type=int,
        default=MAX_PAYLOAD_BYTES,
        help=(
            "largest artifact or host_payload this agent will download, and the "
            f"room reserved for one in the disk preflight (default: {MAX_PAYLOAD_BYTES})"
        ),
    )
    source_parent.add_argument(
        "--host-unit",
        default=None,
        help="systemd unit to restart after applying host_payload, then require active",
    )

    run = sub.add_parser(
        "run",
        parents=[source_parent],
        help="continuously fetch, verify and apply updates",
    )
    run.add_argument("--poll-interval", type=float, default=300.0, help="seconds between checks")
    run.add_argument("--once", action="store_true", help="run a single cycle and exit")
    run.add_argument(
        "--no-flash", action="store_true", help="verify only; never flash"
    )

    jobs = sub.add_parser(
        "jobs",
        parents=[source_parent],
        help="listen for IoT Jobs and run one verify-only cycle per poke",
    )
    jobs.add_argument(
        "--iot-endpoint",
        default=os.environ.get("UNOQ_OTA_IOT_ENDPOINT"),
        help="AWS IoT data endpoint (also reads UNOQ_OTA_IOT_ENDPOINT)",
    )
    jobs.add_argument(
        "--iot-cert",
        type=Path,
        default=os.environ.get("UNOQ_OTA_IOT_CERT"),
        help="device certificate path (also reads UNOQ_OTA_IOT_CERT)",
    )
    jobs.add_argument(
        "--iot-key",
        type=Path,
        default=os.environ.get("UNOQ_OTA_IOT_KEY"),
        help="device private key path (also reads UNOQ_OTA_IOT_KEY)",
    )
    jobs.add_argument(
        "--iot-ca",
        type=Path,
        default=os.environ.get("UNOQ_OTA_IOT_CA"),
        help="Amazon root CA path (also reads UNOQ_OTA_IOT_CA)",
    )
    jobs.add_argument(
        "--thing-name",
        default=os.environ.get("UNOQ_OTA_IOT_THING"),
        help="IoT thing name (also reads UNOQ_OTA_IOT_THING)",
    )
    jobs.add_argument(
        "--mqtt-client-id",
        default=os.environ.get("UNOQ_OTA_MQTT_CLIENT_ID"),
        help="MQTT clientId (default: {thing}-ota, also reads UNOQ_OTA_MQTT_CLIENT_ID)",
    )

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        return _dispatch(args, run, jobs)
    except StateError as exc:
        # The one condition where the agent's own state is present but
        # unreadable. It is an ownership problem on the device, not a bug to
        # hand back as a stack trace.
        log.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
