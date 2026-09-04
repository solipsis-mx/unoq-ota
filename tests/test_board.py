from __future__ import annotations

import pytest

from unoq_ota.board import BoardError, resolve_flash_target


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
