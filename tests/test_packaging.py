"""Packaging invariants for a public tree: license, notice, collaboration docs."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mit_license_is_at_the_root():
    text = (ROOT / "LICENSE").read_text()
    assert "MIT License" in text
    assert "Solipsis MX" in text


def test_reuse_declares_mit_for_the_tree():
    text = (ROOT / "REUSE.toml").read_text()
    assert "SPDX-License-Identifier = \"MIT\"" in text
    assert (ROOT / "LICENSES" / "MIT.txt").is_file()


def test_collaboration_docs_exist():
    for name in (
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "AUTHORS.md",
        "NOTICE",
    ):
        assert (ROOT / name).is_file(), name


def test_authors_name_cursor_and_claude_as_co_collaborators():
    text = (ROOT / "AUTHORS.md").read_text()
    assert "Cursor" in text
    assert "Claude" in text
    assert "Co-collaborators" in text
