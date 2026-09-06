"""Reading and validating UNO Q sketch artifacts.

A sketch artifact is an ELF whose sketch header is packed into the unused
e_ident padding bytes (7-14), which is why the header sits at offset 7.

Validity requires three things, and the third is the one that matters:

    header.ver == 1
    header.magic == 0x2341
    e_shoff + e_shnum*e_shentsize == header.len == file size

The magic number only proves the first 16 bytes arrived. The section-header
identity proves the *whole file* did. Without it, a truncated artifact passes
every check, flashes cleanly, and leaves the loader idle and silent -- it
parses the ELF straight out of flash, fails, returns from main(), and nothing
else is running. There is no error message and no shell.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

HEADER_OFFSET = 7
SKETCH_MAGIC = 0x2341

FLAG_DEBUG = 0x01
FLAG_LINKED = 0x02
FLAG_IMMEDIATE = 0x04
FLAG_WAIT_FOR_APP = 0x08


class ArtifactError(Exception):
    """The artifact is not safe to flash."""


@dataclass(frozen=True)
class SketchHeader:
    ver: int
    length: int
    magic: int
    flags: int


@dataclass(frozen=True)
class SketchArtifact:
    path: Path
    header: SketchHeader
    size: int
    sha256: str


def parse_header(data: bytes) -> SketchHeader:
    if len(data) < HEADER_OFFSET + 8:
        raise ArtifactError(f"file too small to hold a sketch header: {len(data)} bytes")
    ver = data[HEADER_OFFSET]
    (length,) = struct.unpack_from("<I", data, 8)
    (magic,) = struct.unpack_from("<H", data, 12)
    flags = data[14]
    return SketchHeader(ver=ver, length=length, magic=magic, flags=flags)


def load_artifact(path: Path) -> SketchArtifact:
    """Load and fully validate an artifact. Raises ArtifactError if unsafe."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ArtifactError(f"could not read artifact at {path}: {exc}") from exc
    size = len(data)

    if size < 52:
        raise ArtifactError(f"file too small to be an ELF: {size} bytes")

    header = parse_header(data)

    if header.ver != 1:
        raise ArtifactError(f"unsupported sketch header version {header.ver}, expected 1")
    if header.magic != SKETCH_MAGIC:
        raise ArtifactError(
            f"bad sketch magic 0x{header.magic:04x}, expected 0x{SKETCH_MAGIC:04x}"
        )
    if header.flags & FLAG_WAIT_FOR_APP:
        raise ArtifactError(
            "artifact sets wait_for_app; the loader would block forever waiting "
            "for a backup-SRAM magic that nothing writes outside an IDE upload"
        )
    if header.length != size:
        if header.length > size:
            raise ArtifactError(
                f"artifact is truncated: declared length {header.length} but file is only {size} bytes"
            )
        else:
            raise ArtifactError(
                f"declared length {header.length} disagrees with file size {size}"
            )

    (shoff,) = struct.unpack_from("<I", data, 32)
    shentsize, shnum = struct.unpack_from("<HH", data, 46)
    table_end = shoff + shnum * shentsize
    if table_end != size:
        raise ArtifactError(
            f"artifact is truncated or corrupt: section header table ends at "
            f"{table_end} but file is {size} bytes"
        )

    return SketchArtifact(
        path=Path(path),
        header=header,
        size=size,
        sha256=hashlib.sha256(data).hexdigest(),
    )
