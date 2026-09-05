"""Command-line entry point."""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from urllib.parse import urlsplit

from unoq_ota.agent import Agent
from unoq_ota.artifact import load_artifact
from unoq_ota.board import resolve_flash_target
from unoq_ota.flasher import read_partition
from unoq_ota.gates.always import AlwaysGate
from unoq_ota.health.version_report import VersionReportHealthCheck
from unoq_ota.keyring import load_keyring
from unoq_ota.reconciler import reconcile
from unoq_ota.sources.http_manifest import HttpManifestSource, download
from unoq_ota.sources.local import LocalFileSource
from unoq_ota.state import DEFAULT_STATE_DIR, StateStore

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


def _fetch(url: str, dest: Path, source_dir: Path | None) -> None:
    """Fetch an artifact named by a manifest's `artifact.url`.

    An http(s) URL is downloaded with `unoq_ota.sources.http_manifest`'s own
    size-capped, cleans-up-on-failure `download()`. A `file://` URL or a bare
    path is treated as local -- resolved against `source_dir` when relative
    -- which is what makes `LocalFileSource` usable for bench and air-gapped
    setups where the artifact sits next to `manifest.json` rather than behind
    a URL. Anything else (e.g. `s3://...`) is an explicit configuration
    mistake: silently treating it as a local path used to fail safely --
    "download failed", from a `FileNotFoundError` on a path that was never a
    path -- but hid the real cause, so it is rejected here instead.
    """
    scheme = urlsplit(url).scheme
    if scheme in ("http", "https"):
        download(url, dest)
        return
    if scheme not in ("", "file"):
        raise ValueError(
            f"unsupported URL scheme {scheme!r} in artifact url {url!r} "
            "(expected http, https, file, or a bare path)"
        )
    raw_path = url[len("file://") :] if scheme == "file" else url
    src = Path(raw_path)
    if not src.is_absolute() and source_dir is not None:
        src = source_dir / src
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())


def _run(args, run_parser: argparse.ArgumentParser) -> int:
    """Wire a source, the gate, health checks and the store into an Agent.

    This is the composition root: the only place anything in this package
    decides where updates come from and what "healthy" means for a given
    deployment. Everything else -- Agent, the sources, the health check --
    stays deployment-agnostic.
    """
    target = resolve_flash_target()
    public_keys = _load_public_keys(args.keys_dir)
    # Shared with the Agent's own internal StateStore, which is created at
    # the same `state_dir / "state.json"` path (see unoq_ota/agent.py). This
    # instance exists only so `is_poisoned` can be handed to the source as
    # its `poisoned` predicate -- without it, a source defaults to
    # `lambda version: False`, and a version that already failed its health
    # check and was poisoned keeps being offered and re-downloaded forever.
    store = StateStore(Path(args.state_dir) / "state.json")

    if args.source == "local":
        if not args.source_dir:
            run_parser.error("--source local requires --source-dir")
        source = LocalFileSource(args.source_dir, poisoned=store.is_poisoned)
        fetch = lambda url, dest: _fetch(url, dest, args.source_dir)  # noqa: E731
    else:
        if not args.manifest_url:
            run_parser.error("--source http requires --manifest-url")
        source = HttpManifestSource(
            args.manifest_url, poisoned=store.is_poisoned, jitter_s=args.jitter
        )
        fetch = lambda url, dest: _fetch(url, dest, None)  # noqa: E731

    agent = Agent(
        state_dir=args.state_dir,
        source=source,
        gate=AlwaysGate(),
        health_factory=lambda version: VersionReportHealthCheck(expected_version=version),
        target=target,
        public_keys=public_keys,
        fetch=fetch,
    )

    while True:
        phase = agent.run_once()
        log.info("cycle complete: phase=%s", phase.value)
        if args.once:
            return 0
        time.sleep(args.poll_interval)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="unoq-ota")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("reconcile", help="recover the MCU if it is not healthy")
    sub.add_parser("target", help="print the resolved flash target")

    backup = sub.add_parser("backup", help="dump the resident sketch to a file")
    backup.add_argument("--out", type=Path, required=True)
    backup.add_argument("--length", type=int, default=786432)

    validate = sub.add_parser("validate", help="check an artifact without flashing")
    validate.add_argument("artifact", type=Path)

    run = sub.add_parser("run", help="continuously fetch, verify and apply updates")
    run.add_argument("--source", choices=("local", "http"), required=True)
    run.add_argument(
        "--source-dir", type=Path, default=None, help="directory holding manifest.json (local source)"
    )
    run.add_argument(
        "--manifest-url", default=None, help="URL to poll for manifest.json (http source)"
    )
    run.add_argument(
        "--keys-dir", type=Path, required=True, help="directory of <key_id>.public.b64 trusted keys"
    )
    run.add_argument("--poll-interval", type=float, default=300.0, help="seconds between checks")
    run.add_argument(
        "--jitter", type=float, default=30.0, help="max random delay before an http poll (seconds)"
    )
    run.add_argument("--once", action="store_true", help="run a single cycle and exit")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if args.command == "target":
        print(resolve_flash_target())
        return 0

    if args.command == "validate":
        artifact = load_artifact(args.artifact)
        print(f"OK  size={artifact.size}  sha256={artifact.sha256}")
        return 0

    if args.command == "backup":
        target = resolve_flash_target()
        read_partition(args.out, target.address, args.length)
        print(f"dumped {args.length} bytes to {args.out}")
        return 0

    if args.command == "reconcile":
        target = resolve_flash_target()
        health = VersionReportHealthCheck(expected_version="")
        result = reconcile(args.state_dir, health, target)
        print(f"healthy={result.healthy} action={result.action} image={result.image}")
        return 0 if result.healthy else 1

    if args.command == "run":
        return _run(args, run)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
