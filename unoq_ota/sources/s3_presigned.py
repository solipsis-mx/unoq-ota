"""An s3:// manifest polled with botocore GetObject each cycle.

A presigned HTTPS URL pasted into a unit file expires, after which every poll
is a 403. Fetching via a presigned URL that `requests` then GETs also breaks
under IoT role-alias credentials: the session token in the query string does
not survive round-trip encoding (`SignatureDoesNotMatch`), while the same
principal's `get_object` succeeds. This source keeps the object identity
(`s3://bucket/key`) and reads through the standard AWS credential chain.

Requires `pip install unoq-ota[s3]` (botocore). Tests inject a fake client;
nothing here talks to AWS on its own.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from pathlib import Path
from urllib.parse import urlsplit

from unoq_ota.interfaces import Status, Update
from unoq_ota.preflight import MAX_PAYLOAD_BYTES
from unoq_ota.sources.http_manifest import require_jitter_s

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
    from botocore.config import Config

    from unoq_ota.sources.http_manifest import CONNECT_TIMEOUT_S, READ_TIMEOUT_S

    region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    kwargs = {
        "config": Config(
            connect_timeout=CONNECT_TIMEOUT_S,
            read_timeout=READ_TIMEOUT_S,
        )
    }
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
    session=None,  # noqa: ARG001 -- kept so callers that passed the HTTP session stay valid
    max_bytes: int = MAX_PAYLOAD_BYTES,
    expires_in: int = DEFAULT_EXPIRES_S,  # noqa: ARG001 -- unused; GetObject has no URL TTL
    region: str | None = None,
) -> Path:
    """`s3://bucket/key` via GetObject, streamed to disk with a hard size cap."""
    bucket, key = parse_s3_uri(uri)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        s3 = client or default_client(region)
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        with dest.open("wb") as handle:
            while True:
                chunk = body.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError(f"artifact exceeded {max_bytes} bytes")
                handle.write(chunk)
    except Exception:
        try:
            dest.unlink(missing_ok=True)
        except OSError as cleanup_exc:
            log.warning(
                "failed to remove partial download at %s: %s", dest, cleanup_exc
            )
        raise
    return dest


class S3PresignedSource:
    """Like HttpManifestSource, but the poll target is an s3:// object identity.

    Jitter runs before GetObject so a fleet does not stampede. check() never
    raises on transient failure -- same contract as the other sources.
    """

    def __init__(
        self,
        manifest_url: str,
        poisoned=None,
        session=None,  # noqa: ARG001 -- kept for call-site compatibility
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
            s3 = self._s3_client or default_client(self.region)
            response = s3.get_object(Bucket=self.bucket, Key=self.key)
            raw = response["Body"].read()
            manifest = json.loads(raw)
            version = str(manifest["version"])
            sequence = int(manifest["sequence"])
        except Exception as exc:
            log.warning("manifest fetch failed: %s", exc)
            return None

        try:
            poisoned = self._poisoned(version)
        except Exception as exc:
            log.warning("poison-list check failed for version %s: %s", version, exc)
            return None

        if poisoned:
            return None

        return Update(
            version=version, sequence=sequence, manifest=manifest, raw_manifest=raw
        )

    def report(self, update, status, detail: str) -> None:
        log.info("update %s -> %s (%s)", update.version, status.value, detail)
