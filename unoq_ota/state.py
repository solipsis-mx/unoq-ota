"""Persisted agent state, written so a power loss cannot corrupt it.

Every transition that touches hardware is written with fsync + atomic rename
before the hardware is touched. Note the deliberate asymmetry: a *corrupt*
state file must never crash the agent, because the reconciler's anti-bricking
guarantee cannot be allowed to depend on this file being readable. Losing
state costs a redundant reflash; crashing on it costs a dead board.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

DEFAULT_STATE_DIR = Path("/var/lib/unoq-ota")
MAX_ATTEMPTS = 2


class Phase(str, Enum):
    IDLE = "idle"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    STAGED = "staged"
    FLASHING = "flashing"
    HEALTH_CHECK = "health_check"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


@dataclass
class State:
    phase: Phase = Phase.IDLE
    version: str | None = None
    attempts: dict = field(default_factory=dict)
    poisoned: list = field(default_factory=list)
    sequence: int = 0
    core_version: str | None = None


def _sanitize_attempts(value: object) -> dict:
    """Keep only entries whose count coerces to int.

    A poisoned version is the durable guard against a bad build; a dropped
    attempt counter just leaves that version's retries bounded by
    MAX_ATTEMPTS starting from zero again -- a redundant reflash at worst,
    never a crash.
    """
    if not isinstance(value, dict):
        return {}
    sanitized = {}
    for key, count in value.items():
        try:
            sanitized[key] = int(count)
        except (ValueError, TypeError, OverflowError):
            continue
    return sanitized


def _sanitize_poisoned(value: object) -> list:
    """Coerce to a list of strings, dropping anything that isn't one.

    Guards against e.g. a bare string ("hello") turning into a list of its
    characters, or a JSON object contributing its keys as fake entries.
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _sanitize_phase(value: object) -> Phase:
    """A valid Phase value, else Phase.IDLE.

    Each field is defaulted independently so that one shape-valid-but-wrong
    field (an unknown phase string, a non-numeric sequence, ...) cannot take
    the rest of the state -- in particular the poisoned list -- down with it.
    """
    try:
        return Phase(value)
    except ValueError:
        return Phase.IDLE


def _sanitize_optional_str(value: object) -> str | None:
    """The value if it is a string, else None."""
    return value if isinstance(value, str) else None


def _sanitize_sequence(value: object) -> int:
    """Coerced to int, else 0."""
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return 0


class StateStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> State:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return State()
        if not isinstance(raw, dict):
            # Valid JSON but not an object -- e.g. `[]`, `"hello"`, `null`.
            # Treat it the same as unreadable: return defaults, never raise.
            return State()
        # Each field is sanitized independently -- never one try/except
        # around the whole thing -- so a single shape-valid-but-wrong field
        # (e.g. a non-numeric "sequence") cannot discard the rest of the
        # state, in particular the poisoned list that guards against a bad
        # firmware version being re-offered forever.
        return State(
            phase=_sanitize_phase(raw.get("phase")),
            version=_sanitize_optional_str(raw.get("version")),
            attempts=_sanitize_attempts(raw.get("attempts")),
            poisoned=_sanitize_poisoned(raw.get("poisoned")),
            sequence=_sanitize_sequence(raw.get("sequence")),
            core_version=_sanitize_optional_str(raw.get("core_version")),
        )

    def save(self, state: State) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(state)
        payload["phase"] = state.phase.value
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def attempts_for(self, version: str) -> int:
        return int(self.load().attempts.get(version, 0))

    def record_attempt(self, version: str) -> None:
        state = self.load()
        state.attempts[version] = int(state.attempts.get(version, 0)) + 1
        self.save(state)

    def poison(self, version: str) -> None:
        state = self.load()
        if version not in state.poisoned:
            state.poisoned.append(version)
        self.save(state)

    def is_poisoned(self, version: str) -> bool:
        return version in self.load().poisoned
