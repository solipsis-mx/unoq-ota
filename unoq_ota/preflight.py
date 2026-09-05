"""Checks that run before an update is allowed to proceed."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from unoq_ota.artifact import parse_header
from unoq_ota.flasher import read_resident_header

log = logging.getLogger(__name__)


class PreflightError(Exception):
    """The device is not in a fit state to take an update right now."""


def check_clock(now: datetime = None, floor_year: int = 2020) -> None:
    """Refuse to verify signatures against an implausible clock.

    Boards with cellular modems frequently start at an epoch default until
    they get time from the network. In that state both signature validity
    windows and TLS certificate checks misbehave, so defer rather than fail.

    The floor is a year, but the thing actually being judged is an instant,
    not a wall-clock display: a device can have a perfectly correct clock
    and still carry an unusual UTC offset that puts the *local* year on the
    wrong side of a year boundary (e.g. just after midnight on Jan 1 in a
    UTC+14 zone, while UTC itself still reads Dec 31 of the prior year). An
    aware `now` is normalised to UTC before comparing so the floor is judged
    against the same instant a signature validity window would be judged
    against. A naive `now` has no offset to normalise and is compared as
    given.
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
    free = shutil.disk_usage(probe).free
    required = needed_bytes + margin_bytes
    if free < required:
        raise PreflightError(
            f"insufficient disk space: {free} bytes free, need {required}"
        )


def detect_drift(believed: Path, address: int, read_header=read_resident_header) -> bool:
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
