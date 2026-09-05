from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unoq_ota.artifact import SketchHeader
from unoq_ota.keyring import load_keyring
from unoq_ota.preflight import (
    PreflightError,
    check_clock,
    check_disk_space,
    detect_drift,
)


def _write_pubkey(directory, key_id):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (directory / f"{key_id}.public.b64").write_text(base64.b64encode(raw).decode())
    return key


def test_loads_several_keys_so_rotation_does_not_need_a_site_visit(tmp_path):
    _write_pubkey(tmp_path, "k1")
    _write_pubkey(tmp_path, "k2")

    keys = load_keyring(tmp_path)

    assert set(keys) == {"k1", "k2"}


def test_missing_keyring_directory_yields_no_keys(tmp_path):
    assert load_keyring(tmp_path / "absent") == {}


def test_ignores_unreadable_key_files(tmp_path):
    _write_pubkey(tmp_path, "good")
    (tmp_path / "bad.public.b64").write_text("!!! not base64 !!!")

    assert set(load_keyring(tmp_path)) == {"good"}


def test_clock_rejects_an_implausible_epoch_default():
    # Cellular modems commonly boot at an epoch default until they get network
    # time. Signature windows and TLS both silently misbehave in that state.
    with pytest.raises(PreflightError, match="clock"):
        check_clock(now=datetime(1980, 1, 6, tzinfo=timezone.utc))


def test_clock_accepts_a_plausible_time():
    check_clock(now=datetime(2026, 9, 4, tzinfo=timezone.utc))


def test_clock_normalisation_rescues_a_negative_offset_across_new_year():
    # A correct clock reported at UTC-11 just before New Year. Unnormalised
    # this reads as 2025 (the wrong side of a 2026 floor) and is wrongly
    # rejected; normalised to UTC it is 2026-01-01 and must not raise.
    #
    # This is the direction normalisation actually rescues -- deleting the
    # two UTC-normalisation lines in check_clock makes this test fail, unlike
    # the positive-offset test this replaces, which mutation testing proved
    # stayed green either way (both the naive year and the normalised year
    # landed on the same side of that test's floor).
    just_before_new_year_far_west = datetime(
        2025, 12, 31, 23, 30, tzinfo=timezone(timedelta(hours=-11))
    )
    check_clock(now=just_before_new_year_far_west, floor_year=2026)


def test_clock_normalisation_is_stricter_for_a_positive_offset_across_new_year():
    # The opposite direction: a positive offset can make local wall-clock
    # time read as the new year while the underlying UTC instant has not
    # rolled over yet. Normalisation must judge that instant honestly and
    # reject it, even though the naive (unnormalised) local year would pass.
    just_after_new_year_far_east = datetime(
        2020, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=14))
    )
    with pytest.raises(PreflightError, match="clock"):
        check_clock(now=just_after_new_year_far_east, floor_year=2020)


def test_disk_check_rejects_insufficient_space(tmp_path):
    with pytest.raises(PreflightError, match="disk"):
        check_disk_space(tmp_path, needed_bytes=10**15)


def test_disk_check_passes_for_a_small_artifact(tmp_path):
    check_disk_space(tmp_path, needed_bytes=1024, margin_bytes=0)


def test_disk_check_raises_preflight_error_when_path_and_parent_are_both_missing(tmp_path):
    # `check_disk_space` probes `path` if it exists, else `path.parent`. If
    # neither exists (e.g. a state dir whose grandparent was never created),
    # `shutil.disk_usage` raises a bare `FileNotFoundError`. Left uncaught,
    # that escapes as a plain `OSError` -- caught by neither of `run_once`'s
    # preflight `except` clauses in agent.py -- instead of the one
    # documented failure mode this module promises its callers.
    missing = tmp_path / "no-such-parent" / "no-such-child" / "state.json"
    with pytest.raises(PreflightError, match="disk"):
        check_disk_space(missing, needed_bytes=1024)


def test_no_drift_when_resident_matches_the_believed_image(tmp_path):
    believed = tmp_path / "current.bin"
    believed.write_bytes(b"\x00" * 7 + bytes([1]) + (1234).to_bytes(4, "little")
                         + (0x2341).to_bytes(2, "little") + b"\x00\x00")

    header = SketchHeader(ver=1, length=1234, magic=0x2341, flags=0)

    assert detect_drift(believed, 0x08100000, read_header=lambda addr: header) is False


def test_drift_when_resident_length_differs(tmp_path):
    # current.bin is a belief. It is wrong the moment anyone uses the IDE,
    # App Lab, or a network upload -- and rolling back to fiction is worse
    # than not rolling back.
    believed = tmp_path / "current.bin"
    believed.write_bytes(b"\x00" * 7 + bytes([1]) + (1234).to_bytes(4, "little")
                         + (0x2341).to_bytes(2, "little") + b"\x00\x00")

    header = SketchHeader(ver=1, length=9999, magic=0x2341, flags=0)

    assert detect_drift(believed, 0x08100000, read_header=lambda addr: header) is True


def test_drift_when_there_is_no_believed_image(tmp_path):
    header = SketchHeader(ver=1, length=1234, magic=0x2341, flags=0)

    assert detect_drift(None, 0x08100000, read_header=lambda addr: header) is True


def test_drift_assumed_when_the_resident_read_itself_fails(tmp_path):
    # A failed SWD read proves nothing about whether the resident firmware
    # matches current.bin -- it only proves we could not check. Treating
    # "could not check" the same as "definitely matches" would let a
    # transport hiccup mask real drift, so this must come back True, not
    # False, exactly like the no-believed-image case above.
    believed = tmp_path / "current.bin"
    believed.write_bytes(b"\x00" * 7 + bytes([1]) + (1234).to_bytes(4, "little")
                         + (0x2341).to_bytes(2, "little") + b"\x00\x00")

    def boom(address):
        raise RuntimeError("SWD read failed")

    assert detect_drift(believed, 0x08100000, read_header=boom) is True
