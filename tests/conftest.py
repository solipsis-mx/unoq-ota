from __future__ import annotations

import struct


def make_artifact_bytes(
    body_len: int = 512,
    ver: int = 1,
    magic: int = 0x2341,
    flags: int = 0x00,
    shnum: int = 4,
    shentsize: int = 40,
    declared_len: int | None = None,
    truncate_to: int | None = None,
) -> bytes:
    """Build a synthetic sketch artifact.

    Layout matches a real one: ELF magic, sketch header in e_ident padding,
    and a section header table that ends exactly at end-of-file.
    """
    table_size = shnum * shentsize
    total = body_len + table_size
    shoff = body_len

    buf = bytearray(total)
    buf[0:4] = b"\x7fELF"
    buf[4:7] = bytes([1, 1, 1])
    buf[7] = ver
    struct.pack_into("<I", buf, 8, total if declared_len is None else declared_len)
    struct.pack_into("<H", buf, 12, magic)
    buf[14] = flags
    struct.pack_into("<HH", buf, 16, 1, 0x28)   # e_type=ET_REL, e_machine=EM_ARM
    struct.pack_into("<I", buf, 32, shoff)      # e_shoff
    struct.pack_into("<HH", buf, 46, shentsize, shnum)

    data = bytes(buf)
    if truncate_to is not None:
        data = data[:truncate_to]
    return data
