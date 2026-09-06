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
    store.save(State(phase=Phase.STAGED, version="1.2.3", sequence=7, committed_version="1.0.0"))

    reloaded = store.load()
    assert reloaded.phase == Phase.STAGED
    assert reloaded.version == "1.2.3"
    assert reloaded.sequence == 7
    assert reloaded.committed_version == "1.0.0"


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


def test_load_preserves_poisoned_when_sequence_is_non_numeric(tmp_path):
    # Item 2's regression guard: a single shape-valid-but-wrong field (a
    # non-numeric "sequence") used to discard the whole state via one
    # all-or-nothing try/except, wiping the poisoned list along with it.
    # That list is the durable guard against a bad firmware version being
    # re-offered forever, so losing it here would be a real bricking risk,
    # not just a cosmetic loss.
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"phase": "staged", "poisoned": ["1.0.0"], "sequence": "abc"})
    )

    state = StateStore(path).load()

    assert state.poisoned == ["1.0.0"]
    assert state.sequence == 0
    assert state.phase == Phase.STAGED


def test_load_preserves_poisoned_when_phase_is_unknown(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"phase": "not-a-real-phase", "poisoned": ["1.0.0"], "sequence": 3})
    )

    state = StateStore(path).load()

    assert state.poisoned == ["1.0.0"]
    assert state.phase == Phase.IDLE
    assert state.sequence == 3


def test_load_defaults_unknown_phase_to_idle_while_keeping_other_fields(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "phase": "bogus",
                "version": "1.2.3",
                "attempts": {"1.2.3": 1},
                "poisoned": ["9.9.9"],
                "sequence": 5,
                "core_version": "2.0.0",
            }
        )
    )

    state = StateStore(path).load()

    assert state.phase == Phase.IDLE
    assert state.version == "1.2.3"
    assert state.attempts == {"1.2.3": 1}
    assert state.poisoned == ["9.9.9"]
    assert state.sequence == 5
    assert state.core_version == "2.0.0"


def test_load_returns_default_state_for_an_unreadable_file(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ this is not json")

    state = StateStore(path).load()

    assert state == State()


def test_load_returns_default_state_for_a_non_dict_file(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("[]")

    state = StateStore(path).load()

    assert state == State()


def test_load_survives_infinite_sequence_while_keeping_poisoned(tmp_path):
    # json.loads accepts the bare (non-standard) literal Infinity, and
    # int(float('inf')) raises OverflowError -- not a ValueError or
    # TypeError -- so it used to escape _sanitize_sequence and crash load()
    # outright. That's a regression against the exact "never raise"
    # invariant the per-field sanitizers were meant to strengthen: the old
    # all-or-nothing code returned a bare State() here, losing data but
    # surviving. Per-field defaulting must survive it AND keep poisoned.
    path = tmp_path / "state.json"
    path.write_text('{"sequence": Infinity, "poisoned": ["1.0.0"]}')

    state = StateStore(path).load()

    assert state.sequence == 0
    assert state.poisoned == ["1.0.0"]


def test_load_survives_negative_infinite_sequence(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"sequence": -Infinity}')

    assert StateStore(path).load().sequence == 0


def test_load_survives_nan_sequence(tmp_path):
    # int(float('nan')) already raises ValueError, which was already
    # caught -- pinned here against a future refactor of the except clause.
    path = tmp_path / "state.json"
    path.write_text('{"sequence": NaN}')

    assert StateStore(path).load().sequence == 0


def test_load_drops_an_infinite_attempts_entry_but_keeps_the_rest(tmp_path):
    # Same OverflowError defect, same route, in _sanitize_attempts: a
    # single non-coercible count must not take down the other entries.
    path = tmp_path / "state.json"
    path.write_text('{"attempts": {"1.0.0": Infinity, "2.0.0": 3}}')

    state = StateStore(path).load()

    assert "1.0.0" not in state.attempts
    assert state.attempts["2.0.0"] == 3


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
