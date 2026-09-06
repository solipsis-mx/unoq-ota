from __future__ import annotations

import os

import pytest

from unoq_ota.board import BoardError, default_core_root, resolve_flash_target


def _write_core(root, version, address="0x08100000", max_size="786432"):
    core = root / "packages" / "arduino" / "hardware" / "zephyr" / version
    core.mkdir(parents=True)
    (core / "boards.txt").write_text(
        "unoq.name=Arduino UNO Q\n"
        f"unoq.upload.address={address}\n"
        f"unoq.upload.maximum_size={max_size}\n"
        # A decoy from a different board that must not be picked up.
        "ventunoq.upload.address=0x80F0000\n"
        "ventunoq.upload.maximum_size=1966080\n"
    )
    return core


def test_reads_the_offset_from_boards_txt(tmp_path):
    _write_core(tmp_path, "1.0.0")

    target = resolve_flash_target(tmp_path / "packages" / "arduino" / "hardware" / "zephyr")

    assert target.address == 0x08100000
    assert target.max_size == 786432
    assert target.core_version == "1.0.0"


def test_ignores_other_boards_entries(tmp_path):
    # ventunoq.upload.address is 0x80F0000 -- the value the stale
    # arduino-flash.sh hardcodes. Picking it up would write the sketch into
    # the wrong partition.
    _write_core(tmp_path, "1.0.0")

    target = resolve_flash_target(tmp_path / "packages" / "arduino" / "hardware" / "zephyr")

    assert target.address != 0x080F0000


def test_picks_the_newest_core_when_several_are_installed(tmp_path):
    root = tmp_path / "packages" / "arduino" / "hardware" / "zephyr"
    _write_core(tmp_path, "0.56.0")
    _write_core(tmp_path, "1.0.0")

    assert resolve_flash_target(root).core_version == "1.0.0"


def test_errors_clearly_when_no_core_is_installed(tmp_path):
    root = tmp_path / "packages" / "arduino" / "hardware" / "zephyr"
    root.mkdir(parents=True)

    with pytest.raises(BoardError, match="no Arduino zephyr core"):
        resolve_flash_target(root)


def test_errors_when_boards_txt_lacks_the_key(tmp_path):
    root = tmp_path / "packages" / "arduino" / "hardware" / "zephyr"
    core = root / "1.0.0"
    core.mkdir(parents=True)
    (core / "boards.txt").write_text("unoq.name=Arduino UNO Q\n")

    with pytest.raises(BoardError, match="unoq.upload.address"):
        resolve_flash_target(root)


# ---------------------------------------------------------------------------
# Where the core root comes from when the caller does not name one.
#
# `User=root` makes `Path.home()` `/root`, but the Zephyr core is installed
# under the interactive account's home. Operators need to point the agent at
# that installation without an `Environment=HOME=` hack that hardcodes one
# distribution's user, so the default must be resolved per call (not frozen
# at import time) and an explicit root must accept the paths an operator
# actually has to hand.
# ---------------------------------------------------------------------------


def test_default_core_root_follows_home_at_call_time(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))

    assert default_core_root() == (
        tmp_path / ".arduino15" / "packages" / "arduino" / "hardware" / "zephyr"
    )


def test_resolves_against_the_current_home_when_no_core_root_is_given(tmp_path, monkeypatch):
    home = tmp_path / "someone"
    _write_core(home / ".arduino15", "1.0.0")
    monkeypatch.setenv("HOME", str(home))

    assert resolve_flash_target().core_version == "1.0.0"


def test_accepts_an_arduino15_directory_as_the_core_root(tmp_path):
    _write_core(tmp_path, "1.0.0")

    assert resolve_flash_target(tmp_path).core_version == "1.0.0"


def test_accepts_a_home_directory_as_the_core_root(tmp_path):
    _write_core(tmp_path / ".arduino15", "1.0.0")

    assert resolve_flash_target(tmp_path).core_version == "1.0.0"


def test_error_names_the_paths_that_were_tried(tmp_path):
    with pytest.raises(BoardError) as excinfo:
        resolve_flash_target(tmp_path)

    message = str(excinfo.value)
    assert str(tmp_path) in message
    assert "packages/arduino/hardware/zephyr" in message


def test_skips_entries_it_is_not_allowed_to_stat(tmp_path):
    # Found on hardware: pointing --core-root at a home directory walks
    # everything in it, and a home normally contains at least one directory
    # this process may not read (lost+found is root-owned, mode 700).
    # `Path.is_file()` does not swallow EACCES, so an unreadable neighbour
    # crashed the lookup instead of being passed over.
    blocked = tmp_path / "lost+found"
    blocked.mkdir(mode=0o000)
    _write_core(tmp_path / ".arduino15", "1.0.0")

    try:
        if os.access(blocked, os.R_OK):
            pytest.skip("this user can read a mode-000 directory; the case cannot be staged")
        assert resolve_flash_target(tmp_path).core_version == "1.0.0"
    finally:
        blocked.chmod(0o700)


def test_does_not_re_expand_a_path_that_is_already_a_core_root(tmp_path):
    # The default root already ends in packages/arduino/hardware/zephyr, so
    # blindly appending the same subpath again produced candidates like
    # .../zephyr/packages/arduino/hardware/zephyr -- paths that can never
    # exist, in the one message an operator has to read to fix the problem.
    root = tmp_path / "packages" / "arduino" / "hardware" / "zephyr"
    root.mkdir(parents=True)

    with pytest.raises(BoardError) as excinfo:
        resolve_flash_target(root)

    assert "zephyr/packages/arduino" not in str(excinfo.value)
