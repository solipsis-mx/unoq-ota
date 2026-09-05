from __future__ import annotations

import json
from pathlib import Path

import pytest

from unoq_ota.interfaces import Status
from unoq_ota.sources.http_manifest import HttpManifestSource, download
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


# ---------------------------------------------------------------------------
# B1: LocalFileSource.check() must return None, never raise, when the
# filesystem probe itself fails (a root-owned or chmod 000 manifest.json can
# make Path.is_file() propagate PermissionError instead of returning False).
# Monkeypatched rather than chmod'd so this can't behave differently on a
# CI runner or under a different umask.
# ---------------------------------------------------------------------------


def test_check_returns_none_when_the_manifest_probe_raises_permission_error(tmp_path, monkeypatch):
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest()))

    def _raise(self):
        raise PermissionError("permission denied")

    monkeypatch.setattr(Path, "is_file", _raise)

    assert LocalFileSource(tmp_path).check() is None


def test_check_returns_none_when_the_manifest_read_raises_permission_error(tmp_path, monkeypatch):
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest()))

    def _raise(self):
        raise PermissionError("permission denied")

    monkeypatch.setattr(Path, "read_bytes", _raise)

    assert LocalFileSource(tmp_path).check() is None


def test_check_returns_none_on_deeply_nested_json_that_would_recursionerror(tmp_path):
    # Sibling of B1: a RecursionError is a RuntimeError subclass, not in the
    # old (OSError, ValueError, KeyError, TypeError) tuple, and can be
    # triggered by attacker-influenced content alone -- no flaky disk needed.
    # This is the more relevant threat model, since the design treats every
    # source as untrusted.
    nested = ("[" * 200000) + ("]" * 200000)
    (tmp_path / "manifest.json").write_text(nested)

    assert LocalFileSource(tmp_path).check() is None


def test_local_check_returns_none_when_poisoned_predicate_raises(tmp_path):
    # The poison list is caller-supplied and in practice reads persisted
    # state from disk -- exactly the I/O the rest of check() is guarded
    # against. It is also the load-bearing guard against a
    # flash -> fail health -> roll back -> re-offer loop, so a failure in it
    # must degrade like any other transient failure, not raise out of check().
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest()))

    def _explodes(version):
        raise OSError("poison-list store unavailable")

    source = LocalFileSource(tmp_path, poisoned=_explodes)

    assert source.check() is None


# ---------------------------------------------------------------------------
# Fakes for HttpManifestSource / download -- no real network.
# ---------------------------------------------------------------------------


class _FakeManifestResponse:
    def __init__(self, content=b"", exc=None):
        self.content = content
        self._exc = exc

    def raise_for_status(self):
        if self._exc:
            raise self._exc


class _FakeManifestSession:
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc

    def get(self, url, timeout=None):
        if self._exc:
            raise self._exc
        return self._response


def test_http_manifest_source_reads_a_manifest():
    session = _FakeManifestSession(
        _FakeManifestResponse(content=json.dumps(_manifest()).encode())
    )
    source = HttpManifestSource("http://example.invalid/manifest.json", session=session, jitter_s=0)

    update = source.check()

    assert update is not None
    assert update.version == "1.0.0"
    assert update.sequence == 1


def test_http_manifest_source_returns_none_on_fetch_failure():
    session = _FakeManifestSession(exc=ConnectionError("no route to host"))
    source = HttpManifestSource("http://example.invalid/manifest.json", session=session, jitter_s=0)

    assert source.check() is None


# ---------------------------------------------------------------------------
# B2: the jitter sleep must never let a nonsensical jitter_s escape check()
# as a bare ValueError -- guarded in check(), and rejected loudly where the
# mistake is actually made: construction.
# ---------------------------------------------------------------------------


def test_construction_rejects_a_negative_jitter():
    with pytest.raises(ValueError, match="jitter"):
        HttpManifestSource("http://example.invalid/manifest.json", jitter_s=-5)


def test_construction_rejects_a_non_numeric_jitter():
    with pytest.raises(ValueError, match="jitter"):
        HttpManifestSource("http://example.invalid/manifest.json", jitter_s="soon")


def test_construction_rejects_an_infinite_jitter():
    # float('inf') passes a plain isinstance + `< 0` check, and
    # random.uniform(0, inf) doesn't raise -- only time.sleep(inf) does, and
    # only once check() actually gets there. Left unguarded, the source
    # would silently stop returning updates forever, logging the same
    # "manifest fetch failed" message as an ordinary network outage.
    with pytest.raises(ValueError, match="jitter"):
        HttpManifestSource("http://example.invalid/manifest.json", jitter_s=float("inf"))


def test_construction_rejects_a_nan_jitter():
    # NaN compares False to everything, so `jitter_s < 0` is also False --
    # same silent-death failure mode as infinity.
    with pytest.raises(ValueError, match="jitter"):
        HttpManifestSource("http://example.invalid/manifest.json", jitter_s=float("nan"))


def test_check_survives_a_jitter_value_gone_bad_after_construction(monkeypatch):
    # Defence in depth: even if jitter_s is mutated to something nonsensical
    # after construction, check() must degrade like any other transient
    # failure (log + return None) instead of raising out of the poll loop.
    session = _FakeManifestSession(
        _FakeManifestResponse(content=json.dumps(_manifest()).encode())
    )
    source = HttpManifestSource("http://example.invalid/manifest.json", session=session, jitter_s=0)
    source.jitter_s = -5

    assert source.check() is None


def test_http_check_returns_none_when_poisoned_predicate_raises():
    # Same guard as LocalFileSource: the poison-list call is caller-supplied
    # state (typically read from disk) and must not be able to make check()
    # raise, in this source too.
    session = _FakeManifestSession(
        _FakeManifestResponse(content=json.dumps(_manifest()).encode())
    )

    def _explodes(version):
        raise OSError("poison-list store unavailable")

    source = HttpManifestSource(
        "http://example.invalid/manifest.json",
        session=session,
        jitter_s=0,
        poisoned=_explodes,
    )

    assert source.check() is None


# ---------------------------------------------------------------------------
# B3: download() must never leave a truncated file at `dest` behind, on any
# failure path -- not just the max-bytes-exceeded branch.
# ---------------------------------------------------------------------------


class _FakeStreamResponse:
    def __init__(self, chunks, status_exc=None):
        self._chunks = chunks
        self._status_exc = status_exc

    def raise_for_status(self):
        if self._status_exc:
            raise self._status_exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def iter_content(self, chunk_size):
        for chunk in self._chunks:
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk


class _FakeStreamSession:
    def __init__(self, response):
        self._response = response

    def get(self, url, stream=True, timeout=None):
        return self._response


def test_download_writes_the_response_body(tmp_path):
    dest = tmp_path / "artifact.bin"
    session = _FakeStreamSession(_FakeStreamResponse([b"hello", b" world"]))

    result = download("http://example.invalid/artifact.bin", dest, session=session)

    assert result == dest
    assert dest.read_bytes() == b"hello world"


def test_download_removes_partial_file_on_mid_stream_failure(tmp_path):
    # Reproduces the reported defect: 2000 bytes written, then the connection
    # drops mid-transfer.
    dest = tmp_path / "artifact.bin"
    chunks = [b"a" * 1000, b"b" * 1000, ConnectionError("connection dropped")]
    session = _FakeStreamSession(_FakeStreamResponse(chunks))

    with pytest.raises(ConnectionError):
        download("http://example.invalid/artifact.bin", dest, session=session)

    assert not dest.exists()


def test_download_removes_partial_file_when_size_cap_exceeded(tmp_path):
    dest = tmp_path / "artifact.bin"
    session = _FakeStreamSession(_FakeStreamResponse([b"a" * 10, b"b" * 10]))

    with pytest.raises(ValueError, match="exceeded"):
        download("http://example.invalid/artifact.bin", dest, session=session, max_bytes=15)

    assert not dest.exists()


def test_download_removes_partial_file_on_bad_status(tmp_path):
    dest = tmp_path / "artifact.bin"
    session = _FakeStreamSession(
        _FakeStreamResponse([b"should-not-be-written"], status_exc=ConnectionError("HTTP 500"))
    )

    with pytest.raises(ConnectionError):
        download("http://example.invalid/artifact.bin", dest, session=session)

    assert not dest.exists()


def test_download_propagates_original_exception_when_unlink_also_fails(tmp_path, monkeypatch):
    # The cleanup unlink must never be able to supersede the original
    # failure. Here the original cause is a ConnectionError from a dropped
    # connection, and Path.unlink is made to fail too (e.g. a PermissionError
    # on a locked-down directory) -- the ConnectionError must still be what
    # the caller sees, not the PermissionError from cleanup.
    dest = tmp_path / "artifact.bin"
    chunks = [b"a" * 10, ConnectionError("connection dropped")]
    session = _FakeStreamSession(_FakeStreamResponse(chunks))

    def _raise(self, missing_ok=False):
        raise PermissionError("cannot remove partial file")

    monkeypatch.setattr(Path, "unlink", _raise)

    with pytest.raises(ConnectionError):
        download("http://example.invalid/artifact.bin", dest, session=session)
