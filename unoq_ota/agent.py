"""The update state machine.

State is written before each hardware-touching transition, so a crash resumes
rather than corrupts. Attempt caps and the poison list are not defensive
extras: without them a version that reliably fails its health check produces
flash -> unhealthy -> roll back -> get offered again, forever, with the device
dead through every cycle and flash endurance burning down.

Exception discipline: `verify.py` documents that its public functions raise
only `VerificationError` for malformed manifest/artifact input, and
`artifact.py` documents `load_artifact` as raising only `ArtifactError` --
but `load_artifact` starts with `Path.read_bytes()`, which is capable of
raising a plain `OSError` (a candidate file vanishes or a permission changes
between fetch and load) or even `MemoryError` on a very large file, neither
of which is `ArtifactError`. `unoq_ota/reconciler.py` calls this out
explicitly and defends against it with a broad catch around the identical
`load`/`flash` calls; this module follows the same discipline for the same
reason: a version whose only sin was an unlucky read must not be able to
escape as an uncaught exception. An escaped exception here is worse than a
missed poison -- a supervised agent process just restarts and retries the
same update forever, never reaching the poison list that exists to stop
exactly that loop.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Callable

from unoq_ota.artifact import ArtifactError, load_artifact
from unoq_ota.flasher import FlashError, write_sketch
from unoq_ota.interfaces import Status
from unoq_ota.state import MAX_ATTEMPTS, Phase, StateStore
from unoq_ota.verify import VerificationError

log = logging.getLogger(__name__)

HEALTH_TIMEOUT_S = 30.0

# Same three names, same order, as unoq_ota.reconciler.CANDIDATES -- this is
# the agent's own best-effort, same-boot rollback attempt. The reconciler is
# the one that runs unconditionally at boot and is the actual anti-bricking
# guarantee; this loop exists so a bad flash can often be corrected without
# waiting for a reboot.
ROLLBACK_CANDIDATES = ("current.bin", "previous.bin", "golden.bin")


class Agent:
    def __init__(
        self,
        state_dir: Path,
        source,
        gate,
        health_factory: Callable[[str], object],
        target,
        public_keys: dict | None = None,
        flash=write_sketch,
        load=load_artifact,
        fetch=None,
        verify: Callable[[dict, Path, int], None] | None = None,
    ):
        self.state_dir = Path(state_dir)
        self.source = source
        self.gate = gate
        self.health_factory = health_factory
        self.target = target
        self.public_keys = public_keys or {}
        self._flash = flash
        self._load = load
        self._fetch = fetch
        self._verify = verify or self._default_verify
        self.store = StateStore(self.state_dir / "state.json")

    def _default_verify(self, manifest: dict, path: Path, last_sequence: int) -> None:
        """Bind the keyring and the staged artifact into one verify_manifest call.

        `verify_manifest` (unoq_ota/verify.py) now verifies the artifact's
        bytes itself when given `artifact_path`, running signature ->
        validity window -> sequence -> digest in that fixed order against
        the file actually staged on disk. Passing `artifact_path=path` here
        is required, not optional: the module's own docstring warns in block
        capitals that omitting it leaves the artifact bytes unverified, and
        a manifest can pass every other check while being paired with a
        tampered or truncated file.

        A separate `verify_digest()` call afterwards was considered and
        deliberately not added: with `artifact_path` supplied,
        `verify_manifest`'s last step *is* `verify_digest` against the same
        expected hash. Calling it again would re-read the file and recompute
        the same sha256 a second time for no additional guarantee.
        """
        from unoq_ota.verify import verify_manifest

        verify_manifest(manifest, self.public_keys, last_sequence, artifact_path=Path(path))

    def _set(self, phase: Phase, version: str | None = None) -> None:
        state = self.store.load()
        state.phase = phase
        if version is not None:
            state.version = version
        self.store.save(state)

    def run_once(self) -> Phase:
        update = self.source.check()
        if update is None:
            return Phase.IDLE

        if self.store.attempts_for(update.version) >= MAX_ATTEMPTS:
            self.store.poison(update.version)
            self.source.report(
                update, Status.REJECTED, f"exceeded {MAX_ATTEMPTS} attempts"
            )
            self._set(Phase.REJECTED, update.version)
            return Phase.REJECTED

        self.state_dir.mkdir(parents=True, exist_ok=True)
        staged = self.state_dir / "staged.bin"

        # ---- fetch -------------------------------------------------------
        self._set(Phase.DOWNLOADING, update.version)
        self.source.report(update, Status.DOWNLOADING, "fetching artifact")
        try:
            self._fetch(update.manifest["artifact"]["url"], staged)
        except Exception as exc:
            log.warning("download failed: %s", exc)
            self.source.report(update, Status.REJECTED, f"download failed: {exc}")
            self._set(Phase.IDLE)
            return Phase.IDLE

        # ---- verify ------------------------------------------------------
        self._set(Phase.VERIFYING, update.version)
        try:
            self._verify(update.manifest, staged, self.store.load().sequence)
            artifact = self._load(staged)
        except (VerificationError, ArtifactError) as exc:
            self.store.poison(update.version)
            self.source.report(update, Status.REJECTED, str(exc))
            self._set(Phase.REJECTED, update.version)
            return Phase.REJECTED
        except Exception as exc:
            # Deliberately broader than the documented contracts above: an
            # unexpected error here (a permission change on `staged`, an
            # OOM'd read, ...) is a transient/infrastructure failure, not
            # evidence the *firmware* is bad. Unlike a genuine verification
            # failure it is not necessarily reproducible, so it is reported
            # and retried rather than poisoned -- mirroring how a download
            # failure above is handled.
            log.warning("unexpected error verifying %s: %s", update.version, exc)
            self.source.report(update, Status.REJECTED, f"verify/load error: {exc}")
            self._set(Phase.IDLE)
            return Phase.IDLE

        # ---- gate --------------------------------------------------------
        self._set(Phase.STAGED, update.version)
        allowed, reason = self.gate.may_flash()
        if not allowed:
            self.source.report(update, Status.WAITING_FOR_GATE, reason)
            return Phase.STAGED

        # ---- flash -------------------------------------------------------
        self.store.record_attempt(update.version)
        self._set(Phase.FLASHING, update.version)
        self.source.report(update, Status.FLASHING, "writing sketch partition")
        try:
            self._flash(artifact, self.target)
        except FlashError as exc:
            self.source.report(update, Status.REJECTED, f"flash failed: {exc}")
            self._set(Phase.IDLE)
            return Phase.IDLE

        # ---- health ------------------------------------------------------
        self._set(Phase.HEALTH_CHECK, update.version)
        if self.health_factory(update.version).wait_healthy(HEALTH_TIMEOUT_S):
            current = self.state_dir / "current.bin"
            if current.is_file():
                shutil.copy2(current, self.state_dir / "previous.bin")
            shutil.copy2(staged, current)
            state = self.store.load()
            state.sequence = update.sequence
            state.phase = Phase.COMMITTED
            state.version = update.version
            self.store.save(state)
            self.source.report(update, Status.COMMITTED, "healthy")
            return Phase.COMMITTED

        # ---- rollback ----------------------------------------------------
        self._set(Phase.ROLLING_BACK, update.version)
        self.store.poison(update.version)
        for name in ROLLBACK_CANDIDATES:
            candidate = self.state_dir / name
            if not candidate.is_file():
                continue
            try:
                self._flash(self._load(candidate), self.target)
            except Exception as exc:
                # Broad on purpose, matching unoq_ota.reconciler's own
                # handling of this identical candidate list: `load` and
                # `flash` are injected callables whose exception discipline
                # this loop cannot constrain (the default `load_artifact`
                # alone can raise OSError/MemoryError beyond its documented
                # ArtifactError, see the module docstring above). Every
                # candidate must get its turn; one unusable image is not a
                # reason to give up on the rest.
                log.warning("rollback candidate %s unusable: %s", name, exc)
                continue
            # Rollback restores a *different* version than the one this
            # health_factory was built to assert the identity of, so the
            # version-identity health check cannot meaningfully be re-run
            # here. Successfully writing a known-good image is the success
            # condition this loop can verify; confirming the device is
            # actually healthy again is the reconciler's job, run
            # unconditionally at next boot against exactly this same
            # candidate list.
            self.source.report(update, Status.ROLLED_BACK, f"restored {name}")
            self._set(Phase.ROLLED_BACK, update.version)
            return Phase.ROLLED_BACK

        self.source.report(update, Status.ROLLED_BACK, "no usable rollback image")
        self._set(Phase.ROLLED_BACK, update.version)
        return Phase.ROLLED_BACK
