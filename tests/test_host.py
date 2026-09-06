from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from unoq_ota.host import HostError, apply_host_tree, rollback_host_tree


def _targz(path: Path, files: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_apply_replaces_the_live_tree_and_keeps_the_previous_one(tmp_path):
    live = tmp_path / "host"
    live.mkdir()
    (live / "old.txt").write_text("old")
    archive = _targz(tmp_path / "payload.tar.gz", {"app.py": b"print(1)\n"})

    apply_host_tree(archive, live)

    assert (live / "app.py").read_bytes() == b"print(1)\n"
    assert not (live / "old.txt").exists()
    assert (tmp_path / "host.previous" / "old.txt").read_text() == "old"


def test_rollback_restores_the_previous_tree(tmp_path):
    live = tmp_path / "host"
    live.mkdir()
    (live / "old.txt").write_text("old")
    apply_host_tree(_targz(tmp_path / "a.tar.gz", {"new.txt": b"new"}), live)
    rollback_host_tree(live)
    assert (live / "old.txt").read_text() == "old"
    assert not (live / "new.txt").exists()


def test_apply_refuses_a_member_that_escapes_the_install_dir(tmp_path):
    live = tmp_path / "host"
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="../outside.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"nope"))

    with pytest.raises(HostError, match="escapes"):
        apply_host_tree(archive, live)
    assert not (tmp_path / "outside.txt").exists()
    assert not live.exists() or not any(live.iterdir())


def test_apply_refuses_symlinks_in_the_payload(tmp_path):
    live = tmp_path / "host"
    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)

    with pytest.raises(HostError, match="links"):
        apply_host_tree(archive, live)
