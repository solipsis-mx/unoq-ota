"""Extension points for unoq-ota.

These three Protocols are the entire customisation surface. Everything that
varies between deployments -- where updates come from, when a device may be
interrupted, and what "working" means for your firmware -- lives behind one of
them, so adding your own never requires forking this package.

Flashing is deliberately *not* an interface: there is exactly one way to write
the STM32 on this board. See unoq_ota.flasher.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class Status(str, Enum):
    """Progress reported back to whoever published the update."""

    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    STAGED = "staged"
    WAITING_FOR_GATE = "waiting_for_gate"
    FLASHING = "flashing"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


@dataclass(frozen=True)
class Update:
    """A verified-on-arrival description of an available update.

    `sequence` is a monotonic counter enforced on-device: a correctly signed
    but older manifest must be rejected, or an attacker can replay a known-bad
    firmware that was legitimately published once.
    """

    version: str
    sequence: int
    manifest: dict
    raw_manifest: bytes


class UpdateSource(Protocol):
    """Where updates come from."""

    def check(self) -> Update | None:
        """Return an available update, or None. Must not raise on transient
        network failure -- return None and let the agent back off."""
        ...

    def report(self, update: Update, status: Status, detail: str) -> None:
        """Report progress. Best-effort: a device with no connectivity must
        still be able to complete or roll back an update."""
        ...


class Gate(Protocol):
    """Whether the device may be interrupted right now.

    Staging and verification ignore the gate; only the flash step blocks, so a
    device may sit ready-to-flash indefinitely.

    The flash erases before it programs, and a reset inside that window leaves
    the MCU running nothing until the reconciler recovers it. For anything
    battery-powered or vehicle-mounted, the useful predicate is "supply is
    stable and expected to remain so", which is *not* the same as "the device
    looks idle" -- an idle vehicle is one about to be started.
    """

    def may_flash(self) -> tuple[bool, str]:
        """Return (allowed, human-readable reason). The reason is reported
        upstream while waiting, so make it diagnosable."""
        ...


class HealthCheck(Protocol):
    """Whether the firmware now on the device is actually working.

    This gates rollback, so a check that cannot fail makes rollback
    unreachable. Assert identity *and* liveness *and* forward progress --
    never merely that some bytes arrived, since most firmware emits something
    on a timer whether or not it is doing its job.
    """

    def wait_healthy(self, timeout_s: float) -> bool: ...
