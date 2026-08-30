"""Tests for the read-only EOS 300 diagnostic example."""

import importlib.util
import json
from pathlib import Path
import stat

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
    ):
        assert secret not in encoded
    assert sanitized["home_id"] == sanitized["nested"]["home_id"]


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
