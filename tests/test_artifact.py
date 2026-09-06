from __future__ import annotations

import hashlib

import pytest

from tests.conftest import make_artifact_bytes
from unoq_ota.artifact import (
    ArtifactError,
    FLAG_WAIT_FOR_APP,
    SKETCH_MAGIC,
    load_artifact,
    parse_header,
)


def test_parses_a_valid_header():
    header = parse_header(make_artifact_bytes())
    assert header.ver == 1
    assert header.magic == SKETCH_MAGIC
    assert header.flags == 0x00


def test_accepts_a_well_formed_artifact(tmp_path):
    data = make_artifact_bytes()
    path = tmp_path / "good.elf-zsk.bin"
    path.write_bytes(data)

    artifact = load_artifact(path)

    assert artifact.size == len(data)
    assert artifact.header.length == len(data)
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()


def test_rejects_a_truncated_body_even_though_the_header_is_intact(tmp_path):
    # The failure that matters: header survives, body does not. The loader
    # would accept this and then sit idle with nothing running.
    path = tmp_path / "truncated.elf-zsk.bin"
    path.write_bytes(make_artifact_bytes(truncate_to=300))

    with pytest.raises(ArtifactError, match="truncated"):
        load_artifact(path)


def test_rejects_a_bad_magic(tmp_path):
    path = tmp_path / "bad.elf-zsk.bin"
    path.write_bytes(make_artifact_bytes(magic=0x1234))

    with pytest.raises(ArtifactError, match="magic"):
        load_artifact(path)


def test_rejects_an_unknown_header_version(tmp_path):
    path = tmp_path / "v9.elf-zsk.bin"
    path.write_bytes(make_artifact_bytes(ver=9))

    with pytest.raises(ArtifactError, match="version"):
        load_artifact(path)


def test_rejects_wait_for_app_flag(tmp_path):
    # This flag makes the loader block forever on a magic value in backup SRAM
    # that nothing outside an IDE upload ever writes.
    path = tmp_path / "waits.elf-zsk.bin"
    path.write_bytes(make_artifact_bytes(flags=FLAG_WAIT_FOR_APP))

    with pytest.raises(ArtifactError, match="wait_for_app"):
        load_artifact(path)


def test_rejects_a_declared_length_that_disagrees_with_the_file(tmp_path):
    path = tmp_path / "liar.elf-zsk.bin"
    path.write_bytes(make_artifact_bytes(declared_len=999999))

    with pytest.raises(ArtifactError, match="length"):
        load_artifact(path)


def test_rejects_a_file_too_short_to_hold_a_header(tmp_path):
    path = tmp_path / "tiny.elf-zsk.bin"
    path.write_bytes(b"\x7fELF")

    with pytest.raises(ArtifactError, match="too small"):
        load_artifact(path)


def test_missing_file_raises_artifact_error_not_file_not_found(tmp_path):
    missing = tmp_path / "no-such.bin"
    with pytest.raises(ArtifactError, match="could not read") as excinfo:
        load_artifact(missing)
    assert isinstance(excinfo.value.__cause__, FileNotFoundError)
