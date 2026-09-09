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

Health-check discipline follows the same rule, one level further:
`health_factory` is caller-injected (unoq_ota/interfaces.py), so this module
cannot constrain what a concrete `HealthCheck` raises either. Both the
factory call and `wait_healthy()` itself are wrapped by `_is_healthy` below,
mirroring `unoq_ota.reconciler._is_healthy` exactly -- an escaped exception
here must never be allowed to skip the rollback block, because skipping it
leaves the device running unconfirmed firmware with no further attempt to
recover in-band.

One fact reframes the rollback path below: this module runs on the Linux
side, and a dead MCU does not reboot the Linux side that hosts it. So
"the reconciler will catch it next boot" is not a safety net for a device
that is dead right now -- nothing causes the boot. The window is unbounded,
which is why this loop tries to recover in-band at all, and why its rollback
report is careful never to claim more confidence than a byte-level flash
plus an identity check can actually support.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Callable, ContextManager

from unoq_ota.artifact import ArtifactError, load_artifact
from unoq_ota.flasher import FlashError, router_stopped as _real_router_stopped, write_sketch
from unoq_ota.host import HostError, apply_host_tree, rollback_host_tree
from unoq_ota.interfaces import Status
from unoq_ota.preflight import MAX_PAYLOAD_BYTES
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
STAGED_NAMES = ("staged.bin", "staged-host.tar.gz")


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
        # Injectable for the same reason `flash`/`load`/`fetch` are: the real
        # `router_stopped` shells out to `systemctl` on its default `run`
        # argument, and this class's own tests must never risk that call
        # reaching a real systemd -- on a bench Mac it has nothing to run
        # against, and on the actual target it would stop and restart a real
        # service. A fake here is a no-op context manager, not a stub of
        # `run`, because callers of `run_once` have no reason to know
        # `router_stopped` is implemented in terms of `subprocess.run` at all.
        router_stopped: Callable[[], ContextManager[object]] = _real_router_stopped,
        apply_host=None,
        rollback_host=None,
        host_restart: Callable[[], None] | None = None,
        host_health: Callable[[], bool] | None = None,
        host_dir: Path | None = None,
        host_max_bytes: int = MAX_PAYLOAD_BYTES,
        no_flash: bool = False,
    ):
        if fetch is None:
            # A missing `fetch` is a construction mistake, not a runtime
            # condition: left as None, every call falls into `self._fetch(...)`
            # raising `TypeError`, which the broad `except Exception` around
            # the fetch step (below) reports as "download failed". That reads
            # exactly like a permanently unreachable network, forever, and
            # hides a wiring bug behind a plausible-looking transient failure.
            raise TypeError("Agent requires a `fetch` callable; it has no usable default")
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
        self._router_stopped = router_stopped
        self._apply_host = apply_host or apply_host_tree
        self._rollback_host = rollback_host or rollback_host_tree
        self._host_restart = host_restart
        self._host_health = host_health
        self.host_dir = Path(host_dir) if host_dir is not None else self.state_dir / "host"
        self.host_max_bytes = host_max_bytes
        self.no_flash = no_flash
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

        verify_manifest(
            manifest,
            self.public_keys,
            last_sequence,
            artifact_path=Path(path),
            host_payload_path=(
                self.state_dir / "staged-host.tar.gz"
                if isinstance(manifest.get("host_payload"), dict)
                else None
            ),
            target=self.target,
        )

    def _try_store(self, fn, context: str) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a full disk must not abort the cycle
            log.warning("%s: %s", context, exc)

    def _set(
        self,
        phase: Phase,
        version: str | None = None,
        *,
        clear_version: bool = False,
    ) -> None:
        def write():
            state = self.store.load()
            state.phase = phase
            # The offset and partition size this agent flashes with come from
            # whichever Arduino core is installed, so the answer to "which
            # core said that?" belongs in the same file as the rest of the
            # story. Recorded on every transition rather than only at commit:
            # a core upgrade between cycles is exactly the case worth seeing.
            state.core_version = getattr(self.target, "core_version", None)
            if clear_version:
                state.version = None
            elif version is not None:
                state.version = version
            self.store.save(state)

        self._try_store(write, f"persist phase {phase.value}")

    def _wait_alive(self, version: str, timeout_s: float, *, context: str) -> str | None:
        """Return the version that is alive, or None. Exceptions are not-alive."""
        try:
            check = self.health_factory(version)
            wait_alive = getattr(check, "wait_alive", None)
            if callable(wait_alive):
                reported = wait_alive(timeout_s)
                return reported if isinstance(reported, str) and reported else None
            return version if check.wait_healthy(timeout_s) else None
        except Exception as exc:  # noqa: BLE001 - same discipline as _is_healthy
            log.warning("%s: health check raised %r, treating as not alive", context, exc)
            return None

    def _expected_image_version(self, name: str) -> str | None:
        state = self.store.load()
        return {
            "current.bin": state.committed_version,
            "previous.bin": state.previous_version,
        }.get(name)

    def _is_healthy(self, version: str, timeout_s: float, *, context: str) -> bool:
        """Run one health check, treating any exception as "not healthy".

        Both the `health_factory(version)` call and `wait_healthy()` sit
        inside the same guard: `health_factory` is caller-injected, so its
        exception discipline cannot be constrained here, and either half
        raising must be treated identically to a clean `False` return --
        never as a reason to skip whatever check comes next.
        """
        try:
            return self.health_factory(version).wait_healthy(timeout_s)
        except Exception as exc:  # noqa: BLE001 - see docstring above
            log.warning("%s: health check raised %r, treating as unhealthy", context, exc)
            return False

    def _atomic_copy(self, src: Path, dst: Path) -> None:
        """Copy `src` to `dst` via temp-file + os.replace.

        Mirrors `StateStore.save` (state.py): write to a temp file in the
        same directory, fsync, then atomically rename into place. `dst` here
        is `current.bin` or `previous.bin` -- the first two names both this
        agent's own rollback loop and `reconciler.py`'s boot-time recovery
        reach for -- so a crash or ENOSPC mid-write must never be able to
        leave a truncated file at that path for either of them to pick up.
        """
        dst = Path(dst)
        fd, tmp = tempfile.mkstemp(dir=str(dst.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(Path(src).read_bytes())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, dst)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _host_block(self, update) -> dict | None:
        block = getattr(update, "manifest", {}).get("host_payload")
        return block if isinstance(block, dict) else None

    def _apply_host_if_present(self, update) -> bool:
        """Swap the host tree. False means roll the MCU back too.

        MCU flash has already succeeded. A host failure must not commit:
        the two sides would disagree. Rollback of the host tree is attempted
        here; the caller then rolls the MCU.
        """
        if self._host_block(update) is None:
            return True
        live = self.host_dir
        archive = self.state_dir / "staged-host.tar.gz"
        try:
            self._apply_host(archive, live)
            if self._host_restart is not None:
                self._host_restart()
            if self._host_health is not None and not self._host_health():
                raise HostError("host health check failed")
            return True
        except Exception as exc:  # noqa: BLE001 - host apply is injected
            log.warning("host apply failed for %s: %s", update.version, exc)
            try:
                self._rollback_host(live)
            except Exception as rollback_exc:  # noqa: BLE001
                log.warning("host rollback failed: %s", rollback_exc)
            return False

    def _unlink_staged(self) -> None:
        """Drop leftover staged files so they cannot bait the reconciler."""
        for name in STAGED_NAMES:
            (self.state_dir / name).unlink(missing_ok=True)

    def run_once(self) -> Phase:
        update = self.source.check()
        if update is None:
            return Phase.IDLE

        # Cheap, local, and first: a poisoned version must never reach the
        # network. Before this check `is_poisoned` had no production caller
        # anywhere in the module, so a poisoned-but-not-yet-capped version
        # (see the verify-failure branch below) would download, verify, and
        # get rejected again on every single cycle, forever, over whatever
        # link the device has.
        poisoned = self.store.is_poisoned(update.version)
        if poisoned or self.store.attempts_for(update.version) >= MAX_ATTEMPTS:
            self._try_store(
                lambda: self.store.poison(update.version),
                f"poison already-capped {update.version}",
            )
            reason = "version is poisoned" if poisoned else f"exceeded {MAX_ATTEMPTS} attempts"
            self.source.report(update, Status.REJECTED, reason)
            self._set(Phase.REJECTED, update.version)
            return Phase.REJECTED

        state = self.store.load()
        watermark = max(state.sequence, state.last_verified_sequence)
        if update.sequence <= watermark:
            log.info(
                "up to date (sequence %s <= watermark %s)",
                update.sequence,
                watermark,
            )
            self._unlink_staged()
            self.source.report(update, Status.VERIFIED, "up to date")
            return Phase.IDLE

        self.state_dir.mkdir(parents=True, exist_ok=True)

        # ---- preflight -----------------------------------------------------
        # Imported here, not at module scope, because the agent guard tests
        # monkeypatch these names on the `unoq_ota.preflight` module object
        # (`monkeypatch.setattr(preflight_module, "check_clock", ...)`) and
        # rely on this function-local import re-reading that attribute on
        # every call. A module-level `from unoq_ota.preflight import
        # check_clock` would bind its own name once at import time, and a
        # future "cleanup" to that form would silently decouple this from
        # those tests -- they would keep passing while patching a name
        # nothing here reads.
        from unoq_ota.preflight import PreflightError, check_clock, check_disk_space, detect_drift

        try:
            check_clock()
            # The bound is the sketch partition's own size (`self.target`,
            # known from the board), not the manifest's declared size. A
            # served manifest can declare an arbitrary `artifact.size`, and
            # using that attacker-chosen value here would let an inflated
            # size make this check fail forever -- landing in the
            # PreflightError branch below, which by design never poisons and
            # never counts an attempt, so nothing would ever cap the retries.
            # The partition size cannot be smaller than what a legitimate
            # artifact needs and needs no manifest at all, so it closes that
            # off without touching the disk check's own before-the-download
            # purpose. `write_sketch` (flasher.py) separately checks the
            # verified artifact's *actual* size against this same bound right
            # before flashing, so no additional re-check of the manifest's
            # declared size is added after verification -- that later check
            # already covers the trusted-data case with a stronger signal
            # (the real bytes) than the manifest's own claim about them.
            #
            # A coupled host tarball is staged next to state.json before it
            # is unpacked, so it needs room here too. The reserve is
            # `self.host_max_bytes` -- the cap the fetch is allowed to
            # write -- and deliberately *not* the manifest's declared
            # `host_payload.size`, for the same reason the sketch bound
            # above ignores `artifact.size`: a served manifest can claim any
            # number, and an inflated one would park every cycle in the
            # PreflightError branch below, which never counts an attempt and
            # never poisons, so nothing would ever stop the loop.
            host_bytes = self.host_max_bytes if self._host_block(update) is not None else 0
            check_disk_space(self.state_dir, self.target.max_size + host_bytes)
            if host_bytes:
                # --host-dir routinely names a different filesystem from
                # --state-dir (an app tree under /opt, state under /var), and
                # free space on one says nothing about the other. The unpacked
                # tree is larger than the tarball it came from and the previous
                # tree is kept alongside it for rollback; both are absorbed by
                # check_disk_space's own margin rather than guessed at with a
                # compression ratio this package cannot know.
                check_disk_space(self.host_dir, host_bytes)
        except PreflightError as exc:
            # Not the update's fault: do not count an attempt and do not
            # poison. Unlike the fetch/verify failure branches below, no
            # version-scoped phase has been recorded for this cycle yet, so
            # there is nothing to revert -- but the store's *own* phase can
            # still be stale from a previous cycle (e.g. a crash mid-STAGED),
            # and returning IDLE here while state.json disagrees would be
            # exactly the "inconsistent guard" this module's docstring warns
            # against. `_set` keeps the two in agreement.
            self.source.report(update, Status.WAITING_FOR_GATE, str(exc))
            self._set(Phase.IDLE, clear_version=True)
            return Phase.IDLE

        staged = self.state_dir / "staged.bin"

        # ---- fetch -------------------------------------------------------
        self._set(Phase.DOWNLOADING, update.version)
        self.source.report(update, Status.DOWNLOADING, "fetching artifact")
        try:
            self._fetch(update.manifest["artifact"]["url"], staged)
        except Exception as exc:
            log.warning("download failed: %s", exc)
            self.source.report(update, Status.REJECTED, f"download failed: {exc}")
            self._set(Phase.IDLE, clear_version=True)
            return Phase.IDLE

        host_block = self._host_block(update)
        if host_block is not None:
            host_url = host_block.get("url")
            if not isinstance(host_url, str) or not host_url:
                self.source.report(update, Status.REJECTED, "manifest host_payload has no url")
                self._set(Phase.IDLE, clear_version=True)
                return Phase.IDLE
            try:
                self._fetch(host_url, self.state_dir / "staged-host.tar.gz")
            except Exception as exc:
                log.warning("host payload download failed: %s", exc)
                self.source.report(update, Status.REJECTED, f"host download failed: {exc}")
                self._set(Phase.IDLE, clear_version=True)
                return Phase.IDLE

        # ---- verify ------------------------------------------------------
        self._set(Phase.VERIFYING, update.version)
        try:
            self._verify(update.manifest, staged, self.store.load().sequence)
            artifact = self._load(staged)
        except (VerificationError, ArtifactError) as exc:
            poisonable = isinstance(exc, ArtifactError) or getattr(exc, "poisonable", False)
            if not poisonable:
                log.warning("unsigned or transient verify failure for %s: %s", update.version, exc)
                self.source.report(update, Status.REJECTED, str(exc))
                self._set(Phase.IDLE, clear_version=True)
                return Phase.IDLE
            self._try_store(
                lambda: self.store.record_attempt(update.version),
                f"record attempt for {update.version}",
            )
            self._try_store(
                lambda: self.store.poison(update.version),
                f"poison {update.version}",
            )
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
            self._set(Phase.IDLE, clear_version=True)
            return Phase.IDLE

        if self.no_flash:
            self._unlink_staged()
            state = self.store.load()
            state.last_verified_sequence = update.sequence
            state.last_verified_version = update.version
            self.store.save(state)
            self.source.report(update, Status.VERIFIED, "verified, not applied")
            self._set(Phase.IDLE, clear_version=True)
            return Phase.IDLE

        # ---- gate --------------------------------------------------------
        self._set(Phase.STAGED, update.version)
        allowed, reason = self.gate.may_flash()
        if not allowed:
            self.source.report(update, Status.WAITING_FOR_GATE, reason)
            return Phase.STAGED

        # ---- flash -------------------------------------------------------
        believed = self.state_dir / "current.bin"
        if detect_drift(believed if believed.is_file() else None, self.target.address):
            if believed.is_file():
                log.warning(
                    "resident firmware disagrees with current.bin; discarding believed image"
                )
                try:
                    believed.unlink()
                except OSError as exc:
                    log.warning("could not discard drifted current.bin: %s", exc)

        self._try_store(
            lambda: self.store.record_attempt(update.version),
            f"record flash attempt for {update.version}",
        )
        self._set(Phase.FLASHING, update.version)
        self.source.report(update, Status.FLASHING, "writing sketch partition")
        try:
            # arduino-router's ExecStopPost toggles the SWD reset line and
            # the unit is Restart=always -- if it restarts mid-erase, systemd
            # asserts reset on the target mid-write. Stopping it for the
            # window (and always restarting, even on failure) means that
            # reset happens at a moment this call chooses, not one systemd
            # picks for us.
            with self._router_stopped():
                self._flash(artifact, self.target)
        except FlashError as exc:
            self.source.report(update, Status.REJECTED, f"flash failed: {exc}")
            self._set(Phase.IDLE, clear_version=True)
            return Phase.IDLE

        # ---- health --------------------------------------------------------
        self._set(Phase.HEALTH_CHECK, update.version)
        mcu_ok = self._is_healthy(
            update.version, HEALTH_TIMEOUT_S, context=f"{update.version}: post-flash check"
        )
        host_ok = self._apply_host_if_present(update) if mcu_ok else True
        if mcu_ok and host_ok:
            current = self.state_dir / "current.bin"
            try:
                had_current = current.is_file()
                if had_current:
                    self._atomic_copy(current, self.state_dir / "previous.bin")
                self._atomic_copy(staged, current)
            except Exception as exc:
                # Non-atomic, unguarded copies here used to be able to
                # truncate `current.bin` -- the first candidate both this
                # module's own rollback loop and the reconciler reach for --
                # and to escape `run_once` after the device was already
                # running the new, uncommitted firmware. `_atomic_copy`
                # guarantees `current.bin` itself is never left partial; this
                # guard additionally ensures a failure here is reported and
                # retried rather than raised, so the same update is simply
                # re-offered next cycle instead of crashing the process.
                log.warning("commit-path copy failed for %s: %s", update.version, exc)
                self.source.report(update, Status.REJECTED, f"commit copy failed: {exc}")
                self._set(Phase.IDLE, clear_version=True)
                return Phase.IDLE
            state = self.store.load()
            if had_current:
                state.previous_version = state.committed_version
            state.committed_version = update.version
            state.sequence = update.sequence
            state.phase = Phase.COMMITTED
            state.version = update.version
            self._try_store(
                lambda: self.store.save(state),
                f"persist commit for {update.version}",
            )
            self.source.report(update, Status.COMMITTED, "healthy")
            return Phase.COMMITTED

        # ---- rollback ----------------------------------------------------
        self._set(Phase.ROLLING_BACK, update.version)
        try:
            self.store.poison(update.version)
        except Exception as exc:
            # A state-write failure must not be allowed to abort rollback.
            # The board may be physically unreachable and is, right now,
            # running firmware that just failed its own health check; the
            # loop below is the only thing that can still fix that in-band,
            # today, without waiting for a reboot that nothing will trigger.
            # Losing the poison record costs a possible re-offer of this
            # version later -- an inconvenience. Skipping rollback because of
            # it could cost the board.
            log.warning("failed to persist poison record for %s: %s", update.version, exc)

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

            reported = self._wait_alive(
                update.version, HEALTH_TIMEOUT_S, context=f"rollback: {name}"
            )
            if reported is None:
                log.warning("rollback candidate %s: MCU not alive, trying next", name)
                continue
            if reported == update.version:
                log.warning(
                    "rollback candidate %s: device still reports %s, treating as failed",
                    name,
                    update.version,
                )
                continue
            expected = self._expected_image_version(name)
            if expected is not None and reported != expected:
                log.warning(
                    "rollback candidate %s: reported %s, expected %s, trying next",
                    name,
                    reported,
                    expected,
                )
                continue

            self.source.report(
                update,
                Status.ROLLED_BACK,
                f"restored {name} running {reported}",
            )
            self._set(Phase.ROLLED_BACK, clear_version=True)
            return Phase.ROLLED_BACK

        # No candidate restored anything -- the device is still running the
        # firmware that just failed its health check, with no in-band fix
        # available. This must not be reported as ROLLED_BACK: nothing was
        # rolled back. The reconciler is still the backstop at next boot,
        # but there is no boot pending on a device that is simply still
        # running (rather than crashed), so that backstop has not engaged
        # yet either.
        self.source.report(update, Status.REJECTED, "no usable rollback image was available")
        self._set(Phase.REJECTED, clear_version=True)
        return Phase.REJECTED
