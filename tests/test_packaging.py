"""Packaging invariants for a public tree: license, notice, collaboration docs."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_gpl3_license_is_the_verbatim_gnu_text():
    # Arduino CLI keeps LICENSE.txt as the unmodified GPL-3.0 document so
    # licensee/GitHub can identify it. Same rule here: copyright lives in
    # NOTICE, not spliced into the license file.
    text = (ROOT / "LICENSE").read_text()
    assert "GNU GENERAL PUBLIC LICENSE" in text
    assert "Version 3, 29 June 2007" in text
    assert "Solipsis MX" not in text
    assert (ROOT / "NOTICE").read_text().count("GNU General Public License")


def test_reuse_declares_gpl3_or_later_for_the_tree():
    text = (ROOT / "REUSE.toml").read_text()
    assert "SPDX-License-Identifier = \"GPL-3.0-or-later\"" in text
    assert (ROOT / "LICENSES" / "GPL-3.0-or-later.txt").is_file()
    assert not (ROOT / "LICENSES" / "MIT.txt").exists()


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
