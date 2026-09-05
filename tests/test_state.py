from __future__ import annotations

import json

import pytest

from unoq_ota.state import MAX_ATTEMPTS, Phase, State, StateStore


def test_returns_a_default_state_when_no_file_exists(tmp_path):
    store = StateStore(tmp_path / "state.json")
    state = store.load()
    assert state.phase == Phase.IDLE
    assert state.attempts == {}
    assert state.poisoned == []


def test_round_trips_state(tmp_path):
    store = StateStore(tmp_path / "state.json")
    store.save(State(phase=Phase.STAGED, version="1.2.3", sequence=7))

    reloaded = store.load()
    assert reloaded.phase == Phase.STAGED
    assert reloaded.version == "1.2.3"
    assert reloaded.sequence == 7


def test_recovers_from_a_corrupt_state_file(tmp_path):
    # A power loss can leave this truncated. The agent must not crash on it,
    # because the reconciler's guarantees do not depend on it being readable.
    path = tmp_path / "state.json"
    path.write_text("{ this is not json")

    assert StateStore(path).load().phase == Phase.IDLE


def test_leaves_no_partial_file_behind(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.save(State(phase=Phase.FLASHING, version="1.0.0"))

    assert json.loads(path.read_text())["phase"] == "flashing"
    assert list(tmp_path.glob("*.tmp")) == []


def test_counts_attempts_per_version(tmp_path):
    store = StateStore(tmp_path / "state.json")
    store.record_attempt("1.0.0")
    store.record_attempt("1.0.0")
    store.record_attempt("2.0.0")

    assert store.attempts_for("1.0.0") == 2
    assert store.attempts_for("2.0.0") == 1
    assert store.attempts_for("3.0.0") == 0


def test_poisons_a_version_and_remembers_it(tmp_path):
    # Without this a failing version is re-offered forever: flash, fail
    # health, roll back, get offered again -- with the device dead each cycle.
    path = tmp_path / "state.json"
    StateStore(path).poison("1.0.0")

    assert StateStore(path).is_poisoned("1.0.0")
    assert not StateStore(path).is_poisoned("1.0.1")


def test_max_attempts_is_small():
    assert MAX_ATTEMPTS == 2


@pytest.mark.parametrize("payload", ["[]", '"hello"', "null"])
def test_load_returns_defaults_for_valid_json_that_is_not_an_object(tmp_path, payload):
    # json.loads happily accepts a list, a string, or null. The old code
    # called raw.get(...) unconditionally and raised AttributeError on all
    # three -- reproduced by hand before this fix.
    path = tmp_path / "state.json"
    path.write_text(payload)

    state = StateStore(path).load()

    assert state.phase == Phase.IDLE
    assert state.attempts == {}
    assert state.poisoned == []


def test_attempts_for_returns_zero_for_a_non_numeric_stored_value(tmp_path):
    # Structurally valid JSON ({"1.0.0": "banana"}) used to load cleanly and
    # then blow up with an uncaught ValueError the first time attempts_for
    # or record_attempt touched that version.
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"phase": "idle", "attempts": {"1.0.0": "banana"}}))
    store = StateStore(path)

    assert store.attempts_for("1.0.0") == 0

    # And it must still be safe to record a fresh attempt afterwards.
    store.record_attempt("1.0.0")
    assert store.attempts_for("1.0.0") == 1


def test_poisoned_is_sanitized_to_a_list_of_strings(tmp_path):
    # A bare string would otherwise explode into a list of its characters
    # (list("hello") == ['h','e','l','l','o']); a JSON object would
    # contribute its keys as fake poisoned versions.
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"phase": "idle", "poisoned": "hello"}))
    assert StateStore(path).load().poisoned == []

    path.write_text(json.dumps({"phase": "idle", "poisoned": {"1.0.0": True}}))
    assert StateStore(path).load().poisoned == []

    path.write_text(json.dumps({"phase": "idle", "poisoned": ["1.0.0", 2, None, "1.0.1"]}))
    assert StateStore(path).load().poisoned == ["1.0.0", "1.0.1"]


def test_write_failure_propagates_leaves_no_tmp_file_and_preserves_existing_state(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.save(State(phase=Phase.STAGED, version="1.0.0"))
    original_contents = path.read_text()

    def _boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(json, "dump", _boom)

    with pytest.raises(RuntimeError, match="disk full"):
        store.save(State(phase=Phase.FLASHING, version="2.0.0"))

    assert list(tmp_path.glob("*.tmp")) == []
    assert path.read_text() == original_contents
