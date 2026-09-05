"""Checks that run before an update is allowed to proceed."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from unoq_ota.artifact import parse_header
from unoq_ota.flasher import read_resident_header

log = logging.getLogger(__name__)


class PreflightError(Exception):
    """The device is not in a fit state to take an update right now."""


def check_clock(now: Optional[datetime] = None, floor_year: int = 2020) -> None:
    """Refuse to verify signatures against an implausible clock.

    Boards with cellular modems frequently start at an epoch default until
    they get time from the network. In that state both signature validity
    windows and TLS certificate checks misbehave, so defer rather than fail.

    The floor is a year, but the thing actually being judged is an instant,
    not a wall-clock display: a device can have a perfectly correct clock
    and still carry an unusual UTC offset that puts the *local* year on the
    wrong side of a year boundary from the underlying UTC instant. Two
    offsets pull in opposite directions here, and it matters which one
    motivates this normalisation:

    * A *negative* offset (local time behind UTC) is the case this rescues.
      Just before UTC's New Year, a zone like UTC-11 still reads the old
      year locally even though the UTC instant has already rolled over --
      e.g. 2025-12-31 23:30-11:00 is 2026-01-01 09:30 UTC. Compared naively
      against a 2026 floor, that correct clock would be wrongly rejected;
      normalising to UTC first accepts it, as it should.
    * A *positive* offset (local time ahead of UTC) pulls the other way and
      makes the check *stricter*, not lenient: local wall-clock time can
      cross into the new year while the UTC instant has not yet. Normalising
      judges that instant honestly, which can turn a naive accept into a
      correct reject -- it is not a case this normalisation "saves".

    An aware `now` is normalised to UTC before comparing so the floor is
    judged against the same instant a signature validity window would be
    judged against. A naive `now` has no offset to normalise and is compared
    as given.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc)
    if now.year < floor_year:
        raise PreflightError(
            f"system clock reads {now.isoformat()}, which is implausible; "
            "deferring until time is synchronised"
        )


def check_disk_space(path: Path, needed_bytes: int, margin_bytes: int = 50_000_000) -> None:
    """Refuse to start an update that could fill the filesystem.

    state.json's crash-safety depends on an atomic rename, which fails on a
    full filesystem -- silently taking the recovery story with it.
    """
    path = Path(path)
    probe = path if path.exists() else path.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError as exc:
        # Neither `path` nor its parent exists (e.g. a state dir whose
        # grandparent was never created). `shutil.disk_usage` raises
        # `FileNotFoundError` in that case, which is an `OSError` -- and an
        # uncaught one here would escape this module's one documented
        # failure mode, past both of `run_once`'s preflight `except`
        # clauses, as a bare crash instead of a deferral.
        raise PreflightError(f"could not check disk space for {probe}: {exc}")
    required = needed_bytes + margin_bytes
    if free < required:
        raise PreflightError(
            f"insufficient disk space: {free} bytes free, need {required}"
        )


def detect_drift(believed: Optional[Path], address: int, read_header=read_resident_header) -> bool:
    """True when the resident firmware disagrees with what we think we flashed.

    current.bin is a belief, and it is wrong as soon as anyone uses the IDE,
    App Lab, or a network upload. Rolling back to an image that was never on
    the device is worse than not rolling back at all, so re-baseline instead.

    A failed resident read (the SWD link is busy, the target is undervolted,
    ...) proves nothing about whether the two images actually match -- it
    only proves the comparison could not be made. Treating "could not check"
    as "no drift" would let a transport hiccup mask real drift, so a read
    failure is treated the same as "no believed image": assume drift and let
    the caller re-establish its belief rather than trust a comparison that
    never actually happened.
    """
    if believed is None or not Path(believed).is_file():
        return True
    try:
        expected = parse_header(Path(believed).read_bytes())
        resident = read_header(address)
    except Exception as exc:
        log.warning("could not compare resident firmware: %s", exc)
        return True
    return (expected.length, expected.magic) != (resident.length, resident.magic)
