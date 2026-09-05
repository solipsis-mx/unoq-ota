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


class StateStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> State:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return State()
        try:
            return State(
                phase=Phase(raw.get("phase", "idle")),
                version=raw.get("version"),
                attempts=dict(raw.get("attempts") or {}),
                poisoned=list(raw.get("poisoned") or []),
                sequence=int(raw.get("sequence") or 0),
                core_version=raw.get("core_version"),
            )
        except (ValueError, TypeError):
            return State()

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
