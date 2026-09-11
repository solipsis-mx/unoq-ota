"""S3PresignedSource: mint a GET URL at fetch time instead of baking one in.

A presigned URL pasted into a systemd unit expires and then every poll is a
403. This source holds an s3:// URI and credentials from the standard AWS
chain, and signs a short-lived GET for each check() / download. Tests inject
a fake S3 client -- nothing here talks to AWS.
"""

from __future__ import annotations

import json

import pytest

from unoq_ota.interfaces import Status
from unoq_ota.sources.http_manifest import HttpManifestSource
from unoq_ota.sources.s3_presigned import (
    DEFAULT_EXPIRES_S,
    S3Error,
    S3PresignedSource,
    default_client,
    download_s3,
    parse_s3_uri,
    presign_get,
)


def _manifest(version="1.0.0", sequence=1):
    return {
        "schema": 1,
        "version": version,
        "sequence": sequence,
        "artifact": {"url": "s3://example-bucket/a.bin", "size": 10, "sha256": "0" * 64},
        "signature": {"alg": "ed25519", "key_id": "k1", "sig": ""},
    }


class _FakeBody:
    def __init__(self, data: bytes):
        self._buf = data
        self._off = 0

    def read(self, amt=None):
        if amt is None:
            chunk = self._buf[self._off :]
            self._off = len(self._buf)
            return chunk
        chunk = self._buf[self._off : self._off + amt]
        self._off += len(chunk)
        return chunk


class FakeS3Client:
    def __init__(self, url="https://example.invalid/presigned", exc=None, body=b""):
        self.url = url
        self.exc = exc
        self.body = body
        self.calls = []

    def generate_presigned_url(self, ClientMethod, Params=None, ExpiresIn=None, HttpMethod=None):
        self.calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": Params,
                "ExpiresIn": ExpiresIn,
                "HttpMethod": HttpMethod,
            }
        )
        if self.exc is not None:
            raise self.exc
        return self.url

    def get_object(self, Bucket, Key):
        self.calls.append({"op": "get_object", "Bucket": Bucket, "Key": Key})
        if self.exc is not None:
            raise self.exc
        return {"Body": _FakeBody(self.body), "ContentLength": len(self.body)}


class _FakeManifestResponse:
    def __init__(self, content=b"", status=200):
        self.content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")


class _FakeManifestSession:
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.urls = []

    def get(self, url, timeout=None, stream=None):
        self.urls.append(url)
        if self._exc:
            raise self._exc
        return self._response


# ---------------------------------------------------------------------------
# parse_s3_uri
# ---------------------------------------------------------------------------


def test_parse_s3_uri_splits_bucket_and_key():
    assert parse_s3_uri("s3://updates/manifest.json") == ("updates", "manifest.json")


def test_parse_s3_uri_keeps_key_slashes():
    assert parse_s3_uri("s3://updates/fw/v1/manifest.json") == (
        "updates",
        "fw/v1/manifest.json",
    )


def test_parse_s3_uri_rejects_a_non_s3_scheme():
    with pytest.raises(ValueError, match="s3://"):
        parse_s3_uri("https://example.invalid/manifest.json")


def test_parse_s3_uri_rejects_a_missing_key():
    with pytest.raises(ValueError, match="key"):
        parse_s3_uri("s3://updates")


def test_parse_s3_uri_rejects_an_empty_bucket():
    with pytest.raises(ValueError, match="bucket"):
        parse_s3_uri("s3:///manifest.json")


def test_parse_s3_uri_rejects_a_query_string():
    with pytest.raises(ValueError, match="query"):
        parse_s3_uri("s3://updates/manifest.json?X-Amz-Signature=1")


# ---------------------------------------------------------------------------
# presign_get / download_s3
# ---------------------------------------------------------------------------


def test_presign_get_asks_for_a_short_lived_get_object(monkeypatch):
    client = FakeS3Client()

    url = presign_get("updates", "manifest.json", client=client)

    assert url == "https://example.invalid/presigned"
    assert client.calls == [
        {
            "ClientMethod": "get_object",
            "Params": {"Bucket": "updates", "Key": "manifest.json"},
            "ExpiresIn": DEFAULT_EXPIRES_S,
            "HttpMethod": "GET",
        }
    ]


def test_presign_get_without_botocore_names_the_extra(monkeypatch):
    import unoq_ota.sources.s3_presigned as mod

    def boom():
        raise ImportError("simulated missing botocore")

    monkeypatch.setattr(mod, "_botocore_session", boom)

    with pytest.raises(S3Error, match=r"unoq-ota\[s3\]"):
        presign_get("updates", "manifest.json")


def test_download_s3_get_objects_then_writes_the_file(tmp_path):
    client = FakeS3Client(body=b"payload")
    dest = tmp_path / "out.bin"

    download_s3("s3://updates/a.bin", dest, client=client, max_bytes=123)

    assert dest.read_bytes() == b"payload"
    assert client.calls == [{"op": "get_object", "Bucket": "updates", "Key": "a.bin"}]


# ---------------------------------------------------------------------------
# S3PresignedSource.check
# ---------------------------------------------------------------------------


def test_construction_rejects_a_non_s3_manifest_url():
    with pytest.raises(ValueError, match="s3://"):
        S3PresignedSource("https://example.invalid/manifest.json")


def test_construction_rejects_a_negative_jitter():
    with pytest.raises(ValueError, match="jitter"):
        S3PresignedSource("s3://updates/manifest.json", jitter_s=-5)


def test_check_get_objects_the_manifest():
    client = FakeS3Client(body=json.dumps(_manifest()).encode())
    source = S3PresignedSource(
        "s3://updates/manifest.json",
        s3_client=client,
        jitter_s=0,
    )

    update = source.check()

    assert update is not None
    assert update.version == "1.0.0"
    assert update.sequence == 1
    assert client.calls == [
        {"op": "get_object", "Bucket": "updates", "Key": "manifest.json"}
    ]


def test_check_returns_none_when_get_object_fails():
    client = FakeS3Client(exc=RuntimeError("ExpiredToken"))
    source = S3PresignedSource(
        "s3://updates/manifest.json",
        s3_client=client,
        jitter_s=0,
    )

    assert source.check() is None


def test_check_returns_none_on_fetch_failure():
    client = FakeS3Client(exc=ConnectionError("no route to host"))
    source = S3PresignedSource(
        "s3://updates/manifest.json",
        s3_client=client,
        jitter_s=0,
    )

    assert source.check() is None


def test_check_skips_a_poisoned_version():
    client = FakeS3Client(body=json.dumps(_manifest(version="bad")).encode())
    source = S3PresignedSource(
        "s3://updates/manifest.json",
        poisoned=lambda v: v == "bad",
        s3_client=client,
        jitter_s=0,
    )

    assert source.check() is None


def test_check_returns_none_when_poisoned_predicate_raises():
    client = FakeS3Client(body=json.dumps(_manifest()).encode())
    source = S3PresignedSource(
        "s3://updates/manifest.json",
        poisoned=lambda v: (_ for _ in ()).throw(OSError("state.json unreadable")),
        s3_client=client,
        jitter_s=0,
    )

    assert source.check() is None


def test_report_does_not_raise():
    client = FakeS3Client(body=json.dumps(_manifest()).encode())
    source = S3PresignedSource(
        "s3://updates/manifest.json",
        s3_client=client,
        jitter_s=0,
    )
    update = source.check()

    source.report(update, Status.COMMITTED, "done")


def test_jitter_validation_matches_the_http_source():
    # Same constructor rules, so an operator cannot get a silent-death
    # inf/nan jitter by switching --source s3.
    with pytest.raises(ValueError, match="jitter"):
        HttpManifestSource("http://example.invalid/m.json", jitter_s=float("inf"))
    with pytest.raises(ValueError, match="jitter"):
        S3PresignedSource("s3://updates/m.json", jitter_s=float("inf"))


def test_s3_default_client_uses_the_http_read_timeout(monkeypatch):
    from unoq_ota.sources.http_manifest import DEFAULT_TIMEOUT_S

    seen = {}

    class FakeSession:
        def create_client(self, service, **kwargs):
            seen["service"] = service
            seen.update(kwargs)
            return object()

    monkeypatch.setattr(
        "unoq_ota.sources.s3_presigned._botocore_session", lambda: FakeSession()
    )
    default_client(region="us-east-2")

    assert seen["service"] == "s3"
    connect_s, read_s = DEFAULT_TIMEOUT_S
    assert seen["config"].connect_timeout == connect_s
    assert seen["config"].read_timeout == read_s
