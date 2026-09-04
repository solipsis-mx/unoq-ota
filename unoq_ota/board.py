"""Where the sketch partition lives, according to the board itself.

Never hardcode the flash offset. /opt/openocd/bin/arduino-flash.sh hardcodes
0x80F0000, which is a *different* Arduino board's sketch address -- on the
UNO Q that lands in the boot animation partition. Nothing in the real upload
path calls that script; the IDE uses boards.txt, and so do we.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_CORE_ROOT = Path.home() / ".arduino15" / "packages" / "arduino" / "hardware" / "zephyr"

ADDRESS_KEY = "unoq.upload.address"
MAX_SIZE_KEY = "unoq.upload.maximum_size"


class BoardError(Exception):
    """The board's Arduino installation could not be interrogated."""


@dataclass(frozen=True)
class FlashTarget:
    address: int
    max_size: int
    core_version: str


def _version_key(name: str) -> tuple:
    parts = []
    for chunk in name.split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return tuple(parts)


def find_core_dir(core_root: Path) -> Path:
    if not core_root.is_dir():
        raise BoardError(f"no Arduino zephyr core directory at {core_root}")
    candidates = [d for d in core_root.iterdir() if d.is_dir() and (d / "boards.txt").is_file()]
    if not candidates:
        raise BoardError(f"no Arduino zephyr core installed under {core_root}")
    return max(candidates, key=lambda d: _version_key(d.name))


def _read_property(boards_txt: Path, key: str) -> str:
    for line in boards_txt.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            return value.strip()
    raise BoardError(f"{key} not found in {boards_txt}")


def resolve_flash_target(core_root: Path | None = None) -> FlashTarget:
    root = Path(core_root) if core_root is not None else DEFAULT_CORE_ROOT
    core = find_core_dir(root)
    boards_txt = core / "boards.txt"
    address = int(_read_property(boards_txt, ADDRESS_KEY), 0)
    max_size = int(_read_property(boards_txt, MAX_SIZE_KEY), 0)
    return FlashTarget(address=address, max_size=max_size, core_version=core.name)
