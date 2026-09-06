"""Host-side payload: a signed tarball swapped atomically next to the MCU flash.

An update may include Linux files that must stay version-locked to the
sketch (a parser, a systemd unit drop-in, a config). This module does not
know what those files are. It unpacks a tar.gz into a directory the
operator chose, keeps one previous tree for rollback, and refuses members
that would write outside that directory.

It never runs scripts from the archive. Restarting a service is the
caller's job.
"""

from __future__ import annotations

import tarfile
from pathlib import Path


class HostError(Exception):
    """The host payload could not be applied or rolled back safely."""


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _validate_member(member: tarfile.TarInfo, dest: Path) -> None:
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        raise HostError(f"host payload member has an absolute path: {name!r}")
    target = (dest / name).resolve()
    if not _is_within(dest, target):
        raise HostError(f"host payload member escapes install dir: {name!r}")
    if member.issym() or member.islnk():
        raise HostError(f"host payload must not contain links: {name!r}")


def apply_host_tree(archive: Path, live_dir: Path) -> None:
    """Replace *live_dir* with the contents of *archive* (gzip tar).

    The previous tree, if any, is moved to ``<live_dir>.previous``. A crash
    mid-apply leaves either the old tree or the new tree under *live_dir*,
    never a mix: extraction happens into a sibling ``.next`` directory that
    is renamed into place only after it is complete.
    """
    archive = Path(archive)
    live_dir = Path(live_dir)
    if not archive.is_file():
        raise HostError(f"host payload is not a file: {archive}")

    next_dir = live_dir.with_name(live_dir.name + ".next")
    prev_dir = live_dir.with_name(live_dir.name + ".previous")
    if next_dir.exists():
        _rmtree(next_dir)
    next_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                _validate_member(member, next_dir)
            tar.extractall(next_dir)
    except HostError:
        _rmtree(next_dir)
        raise
    except (tarfile.TarError, OSError) as exc:
        _rmtree(next_dir)
        raise HostError(f"could not extract host payload: {exc}") from exc

    if prev_dir.exists():
        _rmtree(prev_dir)
    if live_dir.exists():
        live_dir.rename(prev_dir)
    next_dir.rename(live_dir)


def rollback_host_tree(live_dir: Path) -> None:
    """Restore ``<live_dir>.previous`` over *live_dir*, if it exists."""
    live_dir = Path(live_dir)
    prev_dir = live_dir.with_name(live_dir.name + ".previous")
    if not prev_dir.exists():
        return
    failed = live_dir.with_name(live_dir.name + ".failed")
    if failed.exists():
        _rmtree(failed)
    if live_dir.exists():
        live_dir.rename(failed)
    prev_dir.rename(live_dir)
    if failed.exists():
        _rmtree(failed)


def _rmtree(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        for child in path.iterdir():
            _rmtree(child)
        path.rmdir()
    else:
        path.unlink(missing_ok=True)
