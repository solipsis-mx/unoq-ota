"""Unconditional boot-time recovery. This is what makes bricking impossible.

The MCU cannot recover itself. A corrupt sketch does not fall back to a shell
-- the shell is compiled out -- and erased flash makes the loader spin forever
on a wait-for-app flag. What saves the board is that Linux holds the SWD lines
and something on Linux unconditionally tries again.

That "something" is this module, and its guarantees hold only because it
depends on nothing that a failed update can damage: it does not read
state.json, it does not need the network, and it treats every candidate image
as untrusted until validated.

That guarantee extends to the collaborators `reconcile()` calls, too:
this function is built to never propagate an exception. The real
`HealthCheck` shells out to a subprocess and reads a temp file, and a
pathological filesystem can make `Path.is_file()` raise -- either one
blowing up must be treated as "not healthy" / "candidate absent", not as
a reason to give up on the remaining candidates. `golden.bin` is the last
resort and must always get its turn. Every exception swallowed for this
reason is logged at warning level, naming the candidate and the
operation that failed, so a silently-broken recovery path doesn't survive
to production.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from unoq_ota.artifact import ArtifactError, load_artifact
from unoq_ota.board import FlashTarget
from unoq_ota.flasher import FlashError, write_sketch
from unoq_ota.interfaces import HealthCheck

_LOG = logging.getLogger(__name__)

CANDIDATES = ("current.bin", "previous.bin", "golden.bin")


@dataclass(frozen=True)
class ReconcileResult:
    healthy: bool
    action: str
    image: str | None = None


def _is_healthy(health: HealthCheck, timeout_s: float, *, context: str) -> bool:
    """Run one health check, treating any exception as "not healthy".

    A health check that raises is not evidence the board is fine -- it is
    exactly the kind of failure this module exists to survive. The real
    `HealthCheck` shells out to a subprocess and reads a temp file, so
    `subprocess` errors, `OSError`, and decoding failures are all live
    possibilities; there is no fixed set of exception types to name here,
    so this deliberately catches broadly.
    """
    try:
        return health.wait_healthy(timeout_s)
    except Exception as exc:  # noqa: BLE001 - see docstring above
        _LOG.warning("%s: health check raised %r, treating as unhealthy", context, exc)
        return False


def reconcile(
    state_dir: Path,
    health: HealthCheck,
    target: FlashTarget,
    *,
    initial_timeout_s: float = 30.0,
    post_flash_timeout_s: float = 30.0,
    flash=write_sketch,
    load=load_artifact,
) -> ReconcileResult:
    state_dir = Path(state_dir)

    if _is_healthy(health, initial_timeout_s, context="initial check"):
        return ReconcileResult(healthy=True, action="none")

    for name in CANDIDATES:
        path = state_dir / name
        try:
            candidate_present = path.is_file()
        except OSError as exc:
            _LOG.warning("%s: is_file() raised %r, treating as absent", name, exc)
            continue
        if not candidate_present:
            continue
        try:
            artifact = load(path)
        except (ArtifactError, OSError) as exc:
            _LOG.warning("%s: load() raised %r, skipping candidate", name, exc)
            continue
        try:
            flash(artifact, target)
        except FlashError as exc:
            _LOG.warning("%s: flash() raised %r, skipping candidate", name, exc)
            continue
        if _is_healthy(health, post_flash_timeout_s, context=f"{name}: post-flash check"):
            return ReconcileResult(healthy=True, action="reflashed", image=name)

    return ReconcileResult(healthy=False, action="exhausted")
