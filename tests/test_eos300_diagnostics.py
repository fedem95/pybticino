"""Tests for the read-only EOS 300 diagnostic example."""

import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace

SCRIPT_PATH = Path(__file__).parents[1] / "examples" / "eos300_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("eos300_diagnostics", SCRIPT_PATH)
assert SPEC and SPEC.loader
DIAGNOSTICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTICS)


def test_redactor_removes_secrets_and_keeps_aliases_stable():
    """Sensitive values must not appear while repeated IDs remain correlatable."""
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    payload = {
        "access_token": "token-secret-value",
        "email": "owner@example.com",
        "home_id": "home-secret-id",
        "nested": {
            "home_id": "home-secret-id",
            "snapshot_url": "https://example.invalid/private",
            "message": "Device 00:03:50:aa:bb:cc at 192.168.1.10",
        },
        "city": "Privateville",
        "coordinates": [45.12345, 8.54321],
        "invitation_code": ["invite-me-secretly"],
        "rooms": [
            {
                "module_ids": ["module-secret-id"],
                "modules": ["module-secret-id"],
            },
        ],
        "modules": [{"id": "module-secret-id", "type": "BNDL"}],
        "modules_bridged": ["module-secret-id"],
    }

    sanitized = redactor.sanitize(payload)
    encoded = json.dumps(sanitized)

    for secret in (
        "token-secret-value",
        "owner@example.com",
        "home-secret-id",
        "https://example.invalid",
        "00:03:50:aa:bb:cc",
        "192.168.1.10",
        "Privateville",
        "45.12345",
        "8.54321",
        "invite-me-secretly",
        "module-secret-id",
    ):
        assert secret not in encoded
    assert sanitized["home_id"] == sanitized["nested"]["home_id"]
    module_alias = sanitized["modules"][0]["id"]
    assert sanitized["rooms"][0]["module_ids"] == [module_alias]
    assert sanitized["rooms"][0]["modules"] == [module_alias]
    assert sanitized["modules_bridged"] == [module_alias]


def test_bridge_busy_samples_distinguish_false_missing_and_ignore_other_modules(tmp_path):
    """Busy diagnostics must preserve false versus absent and only inspect bridges."""
    output = tmp_path / "diagnostics.jsonl"
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    recorder = DIAGNOSTICS.JsonlRecorder(output, redactor)
    state = DIAGNOSTICS.ProbeState(recorder, redactor)
    status_false = {
        "body": {
            "home": {
                "modules": [
                    {"id": "bridge-id", "type": "BNCX", "busy": False, "reachable": True},
                    {"id": "lock-id", "type": "BNDL", "busy": True},
                ]
            }
        }
    }
    status_missing = {"body": {"home": {"modules": [{"id": "bridge-id", "type": "BNCX", "reachable": True}]}}}

    DIAGNOSTICS._record_bridge_busy_samples(status_false, state, 1)
    DIAGNOSTICS._record_bridge_busy_samples(status_missing, state, 2)
    recorder.close()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[0]["bridge_type"] == "BNCX"
    assert rows[0]["busy_field_present"] is True
    assert rows[0]["busy"] is False
    assert rows[0]["changed"] is False
    assert rows[1]["busy_field_present"] is False
    assert rows[1]["busy"] is None
    assert rows[1]["changed"] is True
    assert state.busy_samples == 2
    assert state.busy_transitions == 1


def test_bridge_busy_sample_records_missing_bridge(tmp_path):
    """A malformed or bridge-free response must be visible rather than ambiguous."""
    output = tmp_path / "diagnostics.jsonl"
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    recorder = DIAGNOSTICS.JsonlRecorder(output, redactor)
    state = DIAGNOSTICS.ProbeState(recorder, redactor)

    DIAGNOSTICS._record_bridge_busy_samples({"body": {"home": {"modules": []}}}, state, 1)
    recorder.close()

    row = json.loads(output.read_text(encoding="utf-8"))
    assert row["record_type"] == "bridge_busy_sample"
    assert row["bridge_found"] is False
    assert state.busy_bridge_misses == 1


async def test_simulation_writes_private_jsonl_and_counts_duplicate(tmp_path):
    """The offline mode should produce shareable, private diagnostic output."""
    output = tmp_path / "diagnostics.jsonl"
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    recorder = DIAGNOSTICS.JsonlRecorder(output, redactor)
    state = DIAGNOSTICS.ProbeState(recorder, redactor)

    await DIAGNOSTICS.run_simulation(recorder, state)
    recorder.record("session_summary", **state.summary())
    recorder.close()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["record_type"] for row in rows] == [
        "simulation_topology",
        "websocket_message",
        "websocket_message",
        "session_summary",
    ]
    assert state.messages == 2
    assert state.duplicates == 1
    assert rows[2]["duplicate_index"] == 2
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


async def test_websocket_ids_match_topology_alias_and_ack_is_classified(tmp_path):
    """WebSocket records must use one redaction pass and identify re-subscribe acks."""
    output = tmp_path / "diagnostics.jsonl"
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    recorder = DIAGNOSTICS.JsonlRecorder(output, redactor)
    state = DIAGNOSTICS.ProbeState(recorder, redactor)

    recorder.record("topology", module={"id": "shared-module-id"})
    await state.on_message(
        {
            "push_type": "embedded_json",
            "extra_params": {
                "home": {"modules": [{"id": "shared-module-id", "sensor_status": "triggered"}]},
            },
        },
    )
    await state.on_message({"status": "ok"})
    recorder.close()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    topology_alias = rows[0]["module"]["id"]
    websocket_alias = rows[1]["message"]["extra_params"]["home"]["modules"][0]["id"]
    assert websocket_alias == topology_alias
    assert rows[1]["event_type"] == "module_status"
    assert rows[2]["push_type"] == "subscription_ack"


async def test_sequence_id_detects_retransmission_with_changed_volatile_fields(tmp_path):
    """A repeated sequence is a duplicate even when timestamps and uptime change."""
    output = tmp_path / "diagnostics.jsonl"
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    recorder = DIAGNOSTICS.JsonlRecorder(output, redactor)
    state = DIAGNOSTICS.ProbeState(recorder, redactor)

    first = {
        "push_type": "embedded_json",
        "ts_generated": 100,
        "extra_params": {
            "sequence_id": "shared-sequence",
            "home": {"modules": [{"id": "module-id", "sensor_status": "idle", "uptime": 10}]},
        },
    }
    second = {
        **first,
        "ts_generated": 101,
        "extra_params": {
            **first["extra_params"],
            "home": {"modules": [{"id": "module-id", "sensor_status": "idle", "uptime": 11}]},
        },
    }

    await state.on_message(first)
    await state.on_message(second)
    recorder.close()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert state.duplicates == 1
    assert rows[0]["fingerprint_source"] == "sequence_id"
    assert rows[0]["fingerprint"] == rows[1]["fingerprint"]
    assert rows[1]["duplicate_index"] == 2


async def test_forced_drop_aborts_only_probe_transport_and_records_success(tmp_path):
    """The live reconnect test should abort its socket and expose clear counters."""
    output = tmp_path / "diagnostics.jsonl"
    redactor = DIAGNOSTICS.Redactor(salt=b"fixed-test-salt")
    recorder = DIAGNOSTICS.JsonlRecorder(output, redactor)
    state = DIAGNOSTICS.ProbeState(recorder, redactor)

    transport = SimpleNamespace(aborted=False)

    def abort():
        transport.aborted = True

    transport.abort = abort
    client = object.__new__(DIAGNOSTICS.ObservedWebsocketClient)
    client._is_running = True
    client._websocket = SimpleNamespace(transport=transport)

    await DIAGNOSTICS._force_drop_after(client, state, delay=0)
    recorder.close()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert transport.aborted is True
    assert state.forced_drop_attempts == 1
    assert state.forced_drop_successes == 1
    assert state.forced_drop_failures == 0
    assert rows[0]["record_type"] == "websocket_forced_drop"
    assert rows[0]["result"] == "success"
