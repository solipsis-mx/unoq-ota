"""Tests for tools/sign-artifact.py.

The signing tool is the publisher's half of this system: everything the
agent trusts, it trusts because this script said so. It lives outside the
package (it never runs on a device) and is loaded here by path.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import make_artifact_bytes
from unoq_ota.kms_sign import KmsSignError
from unoq_ota.verify import verify_manifest

ROOT = Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "sign_artifact", ROOT / "tools" / "sign-artifact.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bench(tmp_path):
    """A signing key on disk, plus the artifact it will be asked to sign."""
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "bench.private.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    artifact = tmp_path / "sketch.bin"
    artifact.write_bytes(make_artifact_bytes())
    return key_path, artifact, {"bench": key.public_key()}


def _argv(artifact, key_path, *extra):
    return [
        str(artifact),
        "--version",
        "1.0.0",
        "--sequence",
        "1",
        "--url",
        "http://example.invalid/sketch.bin",
        "--private-key",
        str(key_path),
        "--key-id",
        "bench",
        *extra,
    ]


def test_writes_a_manifest_the_agent_accepts(tmp_path, monkeypatch):
    tool = _load_tool()
    key_path, artifact, keys = _bench(tmp_path)
    out = tmp_path / "manifest.json"

    monkeypatch.setattr(sys, "argv", ["sign-artifact.py", *_argv(artifact, key_path, "--out", str(out))])
    assert tool.main() == 0

    manifest = json.loads(out.read_text())
    verify_manifest(manifest, keys, last_sequence=0, artifact_path=artifact)


def test_manifest_goes_to_stdout_when_no_out_is_given(tmp_path, monkeypatch, capsys):
    # The documented invocation redirects stdout to a file, so the progress
    # line must not land in the same stream as the manifest.
    tool = _load_tool()
    key_path, artifact, keys = _bench(tmp_path)

    monkeypatch.setattr(sys, "argv", ["sign-artifact.py", *_argv(artifact, key_path)])
    assert tool.main() == 0

    captured = capsys.readouterr()
    manifest = json.loads(captured.out)
    verify_manifest(manifest, keys, last_sequence=0, artifact_path=artifact)


def test_host_payload_digest_is_covered_by_the_signature(tmp_path, monkeypatch):
    tool = _load_tool()
    key_path, artifact, keys = _bench(tmp_path)
    host = tmp_path / "host.tar.gz"
    host.write_bytes(b"not really a tarball, but it is what gets hashed")
    out = tmp_path / "manifest.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sign-artifact.py",
            *_argv(
                artifact,
                key_path,
                "--host-payload",
                str(host),
                "--host-url",
                "http://example.invalid/host.tar.gz",
                "--out",
                str(out),
            ),
        ],
    )
    assert tool.main() == 0

    manifest = json.loads(out.read_text())
    verify_manifest(manifest, keys, last_sequence=0, artifact_path=artifact, host_payload_path=host)

    manifest["host_payload"]["sha256"] = "0" * 64
    with pytest.raises(Exception):
        verify_manifest(manifest, keys, last_sequence=0, artifact_path=artifact)


def test_kms_mode_signs_via_kms_instead_of_a_local_key(tmp_path, monkeypatch):
    tool = _load_tool()
    artifact = tmp_path / "sketch.bin"
    artifact.write_bytes(make_artifact_bytes())
    out = tmp_path / "manifest.json"

    kms_key = Ed25519PrivateKey.generate()
    calls = []

    def fake_sign_with_kms(client, key_id, payload):
        calls.append((client, key_id, payload))
        return kms_key.sign(payload)

    monkeypatch.setattr(tool, "default_kms_client", lambda region=None: "fake-client")
    monkeypatch.setattr(tool, "sign_with_kms", fake_sign_with_kms)

    argv = [
        str(artifact),
        "--version", "1.0.0",
        "--sequence", "1",
        "--url", "http://example.invalid/sketch.bin",
        "--kms-key-id", "alias/ota-signing",
        "--kms-region", "us-east-2",
        "--key-id", "kms-2026",
        "--out", str(out),
    ]
    monkeypatch.setattr(sys, "argv", ["sign-artifact.py", *argv])
    assert tool.main() == 0

    assert calls[0][0] == "fake-client"
    assert calls[0][1] == "alias/ota-signing"
    manifest = json.loads(out.read_text())
    verify_manifest(
        manifest, {"kms-2026": kms_key.public_key()}, last_sequence=0, artifact_path=artifact
    )


def test_requires_exactly_one_of_private_key_or_kms_key_id(tmp_path, monkeypatch):
    tool = _load_tool()
    artifact = tmp_path / "sketch.bin"
    artifact.write_bytes(make_artifact_bytes())

    argv = [
        str(artifact),
        "--version", "1.0.0",
        "--sequence", "1",
        "--url", "http://example.invalid/sketch.bin",
        "--key-id", "k",
    ]
    monkeypatch.setattr(sys, "argv", ["sign-artifact.py", *argv])
    with pytest.raises(SystemExit, match="exactly one"):
        tool.main()


def test_rejects_both_private_key_and_kms_key_id(tmp_path, monkeypatch):
    tool = _load_tool()
    key_path, artifact, _ = _bench(tmp_path)

    argv = _argv(artifact, key_path) + ["--kms-key-id", "alias/ota-signing"]
    monkeypatch.setattr(sys, "argv", ["sign-artifact.py", *argv])
    with pytest.raises(SystemExit, match="exactly one"):
        tool.main()


def test_kms_signing_failure_is_a_clean_systemexit(tmp_path, monkeypatch):
    tool = _load_tool()
    artifact = tmp_path / "sketch.bin"
    artifact.write_bytes(make_artifact_bytes())

    def boom(client, key_id, payload):
        raise KmsSignError("kms:Sign returned no usable Signature: None")

    monkeypatch.setattr(tool, "default_kms_client", lambda region=None: "fake-client")
    monkeypatch.setattr(tool, "sign_with_kms", boom)

    argv = [
        str(artifact),
        "--version", "1.0.0",
        "--sequence", "1",
        "--url", "http://example.invalid/sketch.bin",
        "--kms-key-id", "alias/ota-signing",
        "--key-id", "kms-2026",
    ]
    monkeypatch.setattr(sys, "argv", ["sign-artifact.py", *argv])
    with pytest.raises(SystemExit, match="KMS signing failed"):
        tool.main()
