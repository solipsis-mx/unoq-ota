from __future__ import annotations

import pytest

from unoq_ota.iot_credentials import IotCredentialsError, fetch_role_alias_credentials


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._response


def test_fetch_role_alias_credentials_maps_the_response_shape():
    session = _FakeSession(
        _FakeResponse(
            payload={
                "credentials": {
                    "accessKeyId": "AKIA...",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "expiration": "2026-09-10T12:00:00Z",
                }
            }
        )
    )
    creds = fetch_role_alias_credentials(
        "credentials.iot.us-east-2.amazonaws.com",
        "solipsis-device-ota-download",
        "solipsis-mls-001",
        "/etc/unoq-ota/cert.pem",
        "/etc/unoq-ota/key.pem",
        "/etc/unoq-ota/ca.pem",
        session=session,
    )
    assert creds == {
        "Version": 1,
        "AccessKeyId": "AKIA...",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2026-09-10T12:00:00Z",
    }
    url, kwargs = session.calls[0]
    assert url == (
        "https://credentials.iot.us-east-2.amazonaws.com/"
        "role-aliases/solipsis-device-ota-download/credentials"
    )
    assert kwargs["cert"] == ("/etc/unoq-ota/cert.pem", "/etc/unoq-ota/key.pem")
    assert kwargs["verify"] == "/etc/unoq-ota/ca.pem"
    assert kwargs["headers"] == {"x-amzn-iot-thingname": "solipsis-mls-001"}


def test_fetch_role_alias_credentials_raises_on_missing_field():
    session = _FakeSession(_FakeResponse(payload={"credentials": {"accessKeyId": "x"}}))
    with pytest.raises(IotCredentialsError, match="missing"):
        fetch_role_alias_credentials("ep", "alias", "thing", "c", "k", "ca", session=session)


def test_fetch_role_alias_credentials_raises_on_transport_error():
    class _Boom:
        def get(self, *a, **kw):
            raise OSError("no route to host")

    with pytest.raises(IotCredentialsError, match="request failed"):
        fetch_role_alias_credentials("ep", "alias", "thing", "c", "k", "ca", session=_Boom())


def test_fetch_role_alias_credentials_raises_on_http_error():
    session = _FakeSession(_FakeResponse(status_code=403))
    with pytest.raises(IotCredentialsError, match="request failed"):
        fetch_role_alias_credentials("ep", "alias", "thing", "c", "k", "ca", session=session)
