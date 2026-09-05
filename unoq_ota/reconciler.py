"""Unconditional boot-time recovery. This is what makes bricking impossible.

The MCU cannot recover itself. A corrupt sketch does not fall back to a shell
-- the shell is compiled out -- and erased flash makes the loader spin forever
on a wait-for-app flag. What saves the board is that Linux holds the SWD lines
and something on Linux unconditionally tries again.

That "something" is this module, and its guarantees hold only because it
depends on nothing that a failed update can damage: it does not read
state.json, it does not need the network, and it treats every candidate image
as untrusted until validated.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from unoq_ota.artifact import ArtifactError, load_artifact
from unoq_ota.board import FlashTarget
from unoq_ota.flasher import FlashError, write_sketch
from unoq_ota.interfaces import HealthCheck

CANDIDATES = ("current.bin", "previous.bin", "golden.bin")


@dataclass(frozen=True)
class ReconcileResult:
    healthy: bool
    action: str
    image: str | None = None


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

    if health.wait_healthy(initial_timeout_s):
        return ReconcileResult(healthy=True, action="none")

    for name in CANDIDATES:
        path = state_dir / name
        if not path.is_file():
            continue
        try:
            artifact = load(path)
        except (ArtifactError, OSError):
            continue
        try:
            flash(artifact, target)
        except FlashError:
            continue
        if health.wait_healthy(post_flash_timeout_s):
            return ReconcileResult(healthy=True, action="reflashed", image=name)

    return ReconcileResult(healthy=False, action="exhausted")
