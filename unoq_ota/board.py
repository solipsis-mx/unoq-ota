"""Where the sketch partition lives, according to the board itself.

Never hardcode the flash offset. /opt/openocd/bin/arduino-flash.sh hardcodes
0x80F0000, which is a *different* Arduino board's sketch address -- on the
UNO Q that lands in the boot animation partition. Nothing in the real upload
path calls that script; the IDE uses boards.txt, and so do we.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ARDUINO15 = ".arduino15"
CORE_SUBPATH = Path("packages") / "arduino" / "hardware" / "zephyr"


def default_core_root() -> Path:
    """The stock install location, resolved from HOME on every call.

    Deliberately a function, not a module constant: this used to be computed
    once at import time, which froze whatever HOME the process started with.
    Under systemd `User=root` that is `/root`, while the core lives in the
    interactive account's home, so a unit had to set `Environment=HOME=` to a
    hardcoded account name to make an import-time constant come out right.
    """
    return Path.home() / ARDUINO15 / CORE_SUBPATH


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


def _candidate_roots(root: Path) -> list:
    """The shapes an operator might reasonably name as "the core root".

    A path can be handed to this package by a flag, an environment variable
    or a systemd drop-in, and the person writing it has three equally
    plausible things in front of them: the directory the versioned cores
    actually live in, the `.arduino15` sketchbook data directory, or just
    the home directory of the account that ran `arduino-cli core install`.
    Accepting all three costs two `is_dir()` calls and removes the class of
    bug where the agent reports no core installed on a board that plainly
    has one.
    """
    if root.parts[-len(CORE_SUBPATH.parts) :] == CORE_SUBPATH.parts:
        # Already the core directory itself -- the shape `default_core_root`
        # returns. Appending the subpath again invents paths that cannot
        # exist and puts them in the one message an operator reads to work
        # out where the core actually is.
        return [root]
    return [root, root / CORE_SUBPATH, root / ARDUINO15 / CORE_SUBPATH]


def _holds_boards_txt(entry: Path) -> bool:
    """True for a directory that looks like an installed core.

    Both calls can raise: a home directory contains neighbours this process
    is not allowed to stat (`lost+found` is root-owned and mode 700), and
    `Path.is_file()` deliberately does not swallow `EACCES`. An unreadable
    neighbour says nothing about whether a core is installed, so it is
    passed over rather than allowed to end the search.
    """
    try:
        return entry.is_dir() and (entry / "boards.txt").is_file()
    except OSError:
        return False


def find_core_dir(core_root: Path) -> Path:
    tried = []
    for candidate in _candidate_roots(Path(core_root)):
        tried.append(candidate)
        try:
            entries = list(candidate.iterdir())
        except OSError:
            # Missing, not a directory, or unreadable (the core belongs to
            # another account and this process is not root). None of those
            # says anything about the remaining candidates, so keep looking
            # and let the failure below name every path that was tried.
            continue
        installed = [d for d in entries if _holds_boards_txt(d)]
        if installed:
            return max(installed, key=lambda d: _version_key(d.name))
    paths = ", ".join(str(p) for p in tried)
    raise BoardError(f"no Arduino zephyr core installed under any of: {paths}")


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
    root = Path(core_root) if core_root is not None else default_core_root()
    core = find_core_dir(root)
    boards_txt = core / "boards.txt"
    address = int(_read_property(boards_txt, ADDRESS_KEY), 0)
    max_size = int(_read_property(boards_txt, MAX_SIZE_KEY), 0)
    return FlashTarget(address=address, max_size=max_size, core_version=core.name)
