"""AWS IoT Credentials Provider client -- exchanges a device's existing
mutual-TLS certificate for temporary AWS credentials via an IoT role
alias, in the JSON shape botocore's `credential_process` expects.

Generic Linux/AWS glue, not fleet-specific: any UNO Q owner using an IoT
role alias for S3 (or any other AWS API) access needs the same exchange.
`unoq_ota.sources.s3_presigned.default_client` already builds its client
from botocore's standard credential chain, which already knows how to run
a `credential_process` command named in `~/.aws/config` -- this module IS
that command's implementation, invoked as a subprocess by botocore itself.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import requests


class IotCredentialsError(Exception):
    """The IoT Credentials Provider did not return usable credentials."""


def fetch_role_alias_credentials(
    endpoint: str,
    role_alias: str,
    thing_name: str,
    cert_path,
    key_path,
    ca_path,
    *,
    session=None,
    timeout: float = 10.0,
) -> dict:
    """Exchange the device's mTLS cert for temporary STS credentials.

    Returns the botocore `credential_process` JSON shape directly --
    `{"Version": 1, "AccessKeyId", "SecretAccessKey", "SessionToken",
    "Expiration"}` -- so the CLI entry point can just `json.dumps()` it.
    """
    http = session or requests
    url = f"https://{endpoint}/role-aliases/{role_alias}/credentials"
    try:
        response = http.get(
            url,
            cert=(str(cert_path), str(key_path)),
            verify=str(ca_path),
            headers={"x-amzn-iot-thingname": thing_name},
            timeout=timeout,
        )
        response.raise_for_status()
        body = response.json()
    except Exception as exc:  # noqa: BLE001 -- any transport/parse failure is the same "no creds" outcome
        raise IotCredentialsError(f"IoT Credentials Provider request failed: {exc}") from exc

    creds = body.get("credentials")
    if not isinstance(creds, dict):
        raise IotCredentialsError(f"no usable credentials in response: {body!r}")
    try:
        return {
            "Version": 1,
            "AccessKeyId": creds["accessKeyId"],
            "SecretAccessKey": creds["secretAccessKey"],
            "SessionToken": creds["sessionToken"],
            "Expiration": creds["expiration"],
        }
    except KeyError as exc:
        raise IotCredentialsError(f"credentials response missing {exc}: {creds!r}") from exc


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Print AWS credentials for an IoT role alias, in the "
        "shape a botocore credential_process expects. Intended for use as "
        "a `credential_process` line in ~/.aws/config, not run by hand."
    )
    parser.add_argument("--endpoint", required=True, help="IoT Credentials Provider host, no scheme")
    parser.add_argument("--role-alias", required=True)
    parser.add_argument("--thing-name", required=True)
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--ca", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        creds = fetch_role_alias_credentials(
            args.endpoint, args.role_alias, args.thing_name, args.cert, args.key, args.ca
        )
    except IotCredentialsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(creds))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
