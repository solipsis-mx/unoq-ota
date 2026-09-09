"""An s3:// manifest polled by minting a short-lived GET URL each cycle.

A presigned HTTPS URL pasted into a unit file expires, after which every poll
is a 403. This source keeps the object identity (`s3://bucket/key`) and signs
at fetch time from the standard AWS credential chain. Artifact URLs in the
manifest can be `s3://` as well -- `download_s3` mints a GET for those too.

Requires `pip install unoq-ota[s3]` (botocore). Tests inject a fake client;
nothing here talks to AWS on its own.
"""

from __future__ import annotations

import logging
import os
import random
import time
from pathlib import Path
from urllib.parse import urlsplit

from unoq_ota.preflight import MAX_PAYLOAD_BYTES
from unoq_ota.sources.http_manifest import HttpManifestSource, download, require_jitter_s

log = logging.getLogger(__name__)

DEFAULT_EXPIRES_S = 300


class S3Error(Exception):
    """botocore missing, or a presign that callers must see as a hard error."""


def parse_s3_uri(uri: str) -> tuple[str, str]:
    """Return `(bucket, key)` from `s3://bucket/key`.

    The key may contain slashes. A missing bucket or key is a configuration
    mistake and raises ValueError rather than becoming a confusing 404 later.
    """
    parts = urlsplit(uri)
    if parts.scheme != "s3":
        raise ValueError(
            f"expected an s3:// URI, got {uri!r} "
            "(a presigned https URL expires; pass the object identity instead)"
        )
    bucket = parts.netloc
    key = parts.path.lstrip("/")
    if not bucket:
        raise ValueError(f"s3 URI is missing a bucket: {uri!r}")
    if not key:
        raise ValueError(f"s3 URI is missing a key: {uri!r}")
    if parts.query or parts.fragment:
        raise ValueError(f"s3 URI must not carry a query or fragment: {uri!r}")
    return bucket, key


def _botocore_session():
    import botocore.session

    return botocore.session.get_session()


def default_client(region: str | None = None):
    """Build an S3 client from the standard AWS credential chain."""
    try:
        session = _botocore_session()
    except ImportError as exc:
        raise S3Error(
            "S3 source requires botocore; install with: pip install 'unoq-ota[s3]'"
        ) from exc
    region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    return session.create_client("s3", **kwargs)


def presign_get(
    bucket: str,
    key: str,
    expires_in: int = DEFAULT_EXPIRES_S,
    *,
    client=None,
    region: str | None = None,
) -> str:
    """Mint a GET URL for one object. `client` is injected by tests."""
    s3 = client or default_client(region)
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=int(expires_in),
        HttpMethod="GET",
    )


def download_s3(
    uri: str,
    dest: Path,
    *,
    client=None,
    session=None,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    expires_in: int = DEFAULT_EXPIRES_S,
    region: str | None = None,
) -> Path:
    """Presign `s3://bucket/key` and stream it through the HTTP downloader."""
    bucket, key = parse_s3_uri(uri)
    url = presign_get(
        bucket, key, expires_in=expires_in, client=client, region=region
    )
    return download(url, dest, session=session, max_bytes=max_bytes)


class S3PresignedSource:
    """Like HttpManifestSource, but the poll target is an s3:// object identity.

    Jitter runs *before* presign so a stampede delay cannot eat the URL's
    TTL. check() never raises on transient failure -- same contract as the
    other sources.
    """

    def __init__(
        self,
        manifest_url: str,
        poisoned=None,
        session=None,
        jitter_s: float = 30.0,
        *,
        s3_client=None,
        expires_in: int = DEFAULT_EXPIRES_S,
        region: str | None = None,
    ):
        self.bucket, self.key = parse_s3_uri(manifest_url)
        self.manifest_url = manifest_url
        self.jitter_s = require_jitter_s(jitter_s)
        self._poisoned = poisoned or (lambda version: False)
        self._session = session
        self._s3_client = s3_client
        self.expires_in = expires_in
        self.region = region

    def check(self):
        try:
            if self.jitter_s:
                time.sleep(random.uniform(0, self.jitter_s))
        except Exception as exc:
            log.warning("jitter sleep failed: %s", exc)
            return None
        try:
            http_url = presign_get(
                self.bucket,
                self.key,
                expires_in=self.expires_in,
                client=self._s3_client,
                region=self.region,
            )
        except Exception as exc:
            log.warning("s3 presign failed: %s", exc)
            return None
        inner = HttpManifestSource(
            http_url,
            poisoned=self._poisoned,
            session=self._session,
            jitter_s=0,
        )
        return inner.check()

    def report(self, update, status, detail: str) -> None:
        log.info("update %s -> %s (%s)", update.version, status.value, detail)
