from __future__ import annotations

import json

from unoq_ota.interfaces import Status
from unoq_ota.sources.local import LocalFileSource


def _manifest(version="1.0.0", sequence=1):
    return {
        "schema": 1,
        "version": version,
        "sequence": sequence,
        "artifact": {"url": "file:///tmp/x.bin", "size": 10, "sha256": "0" * 64},
        "signature": {"alg": "ed25519", "key_id": "k1", "sig": ""},
    }


def test_returns_none_when_the_directory_is_empty(tmp_path):
    assert LocalFileSource(tmp_path).check() is None


def test_returns_none_when_the_directory_does_not_exist(tmp_path):
    assert LocalFileSource(tmp_path / "nope").check() is None


def test_reads_a_manifest(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest()))

    update = LocalFileSource(tmp_path).check()

    assert update is not None
    assert update.version == "1.0.0"
    assert update.sequence == 1


def test_skips_a_poisoned_version(tmp_path):
    # A version that failed its health check must not be offered again, or the
    # device loops: flash, fail, roll back, get offered the same thing.
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest(version="bad")))

    source = LocalFileSource(tmp_path, poisoned=lambda v: v == "bad")

    assert source.check() is None


def test_ignores_a_corrupt_manifest(tmp_path):
    (tmp_path / "manifest.json").write_text("{ not json")

    assert LocalFileSource(tmp_path).check() is None


def test_report_does_not_raise(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest()))
    source = LocalFileSource(tmp_path)
    update = source.check()

    source.report(update, Status.COMMITTED, "done")   # must not raise
