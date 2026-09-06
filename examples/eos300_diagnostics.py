#!/usr/bin/env python3

"""Read-only diagnostic probe for BTicino Classe 300 EOS installations.

The probe exercises authentication, topology, status, history, and the push
WebSocket without sending device commands or starting WebRTC signaling. Output
is written as redacted JSON Lines suitable for comparing device behaviour.
"""

# ruff: noqa: T201 - command-line examples intentionally print their result path

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from contextlib import suppress
from datetime import UTC, datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import re
import sys
from typing import Any

from pybticino import AsyncAccount, AuthHandler, WebsocketClient

_LOGGER = logging.getLogger("eos300_diagnostics")

_SECRET_KEYS = {
    "access_token",
    "authorization",
    "client_secret",
    "credential",
    "invitation_code",
    "password",
    "refresh_token",
    "secret",
    "token",
}
_NAME_KEYS = {"email", "home_name", "name", "username", "user"}
_LOCATION_KEYS = {
    "address",
    "altitude",
    "city",
    "coordinates",
    "latitude",
    "longitude",
    "postal_code",
    "postcode",
}
_IDENTIFIER_LIST_KEYS = {"module_ids", "modules_bridged"}
_IDENTIFIER_KEYS = {
    "bridge",
    "bridge_id",
    "camera_id",
    "device_id",
    "event_id",
    "home_id",
    "id",
    "local_ip",
    "module_id",
    "session_id",
    "subevent_id",
    "user_id",
}
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LONG_SECRET_RE = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


def _utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


class Redactor:
    """Redact secrets and replace identifiers with stable per-run aliases."""

    def __init__(self, salt: bytes | None = None) -> None:
        self._salt = salt or os.urandom(32)

    def alias(self, kind: str, value: Any) -> str:
        """Return a stable, non-reversible alias for this probe run."""
        digest = hashlib.sha256(self._salt + str(value).encode()).hexdigest()[:10]
        return f"<{kind}:{digest}>"

    def sanitize(self, value: Any, key: str | None = None) -> Any:
        """Recursively sanitize a JSON-compatible value."""
        normalized_key = (key or "").lower()
        if normalized_key in _SECRET_KEYS or normalized_key.endswith("_token"):
            return "<redacted-secret>"
        if "url" in normalized_key:
            return "<redacted-url>"
        if normalized_key in _NAME_KEYS or normalized_key.endswith("_name"):
            return "<redacted-name>"
        if normalized_key in _LOCATION_KEYS:
            return "<redacted-location>"
        if normalized_key in _IDENTIFIER_KEYS or normalized_key.endswith("_id"):
            return self.alias(normalized_key or "id", value)
        if normalized_key in _IDENTIFIER_LIST_KEYS and isinstance(value, (list, tuple)):
            return [self.alias("id", item) for item in value]

        # Room payloads use ``modules`` for a list of raw module identifiers,
        # while home/status payloads use the same key for full module objects.
        # Preserve the objects but pseudonymize scalar identifier collections.
        if (
            normalized_key == "modules"
            and isinstance(value, (list, tuple))
            and all(not isinstance(item, (dict, list, tuple)) for item in value)
        ):
            return [self.alias("id", item) for item in value]
        if normalized_key == "message" and isinstance(value, str):
            return "<redacted-message>"

        if isinstance(value, dict):
            return {str(item_key): self.sanitize(item_value, str(item_key)) for item_key, item_value in value.items()}
        if isinstance(value, list):
            return [self.sanitize(item) for item in value]
        if isinstance(value, tuple):
            return [self.sanitize(item) for item in value]
        if isinstance(value, str):
            return self._sanitize_text(value)
        return value

    def _sanitize_text(self, value: str) -> str:
        value = _URL_RE.sub("<redacted-url>", value)
        value = _EMAIL_RE.sub("<redacted-email>", value)
        value = _MAC_RE.sub(lambda match: self.alias("mac", match.group()), value)
        value = _UUID_RE.sub(lambda match: self.alias("uuid", match.group()), value)
        value = _IPV4_RE.sub(lambda match: self.alias("ip", match.group()), value)
        return _LONG_SECRET_RE.sub("<redacted-secret>", value)


class JsonlRecorder:
    """Write redacted diagnostic records to a private JSONL file."""

    def __init__(self, path: Path, redactor: Redactor) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.path = path
        self._stream = os.fdopen(descriptor, "w", encoding="utf-8")
        self._redactor = redactor

    def record(self, record_type: str, **payload: Any) -> None:
        """Append one redacted record and flush it immediately."""
        record = {
            "recorded_at": _utc_now(),
            "record_type": record_type,
            **self._redactor.sanitize(payload),
        }
        self._stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        self._stream.flush()

    def close(self) -> None:
        """Close the output stream."""
        self._stream.close()


class ProbeState:
    """Collect event and connection statistics for one probe run."""

    def __init__(self, recorder: JsonlRecorder, redactor: Redactor) -> None:
        self.recorder = recorder
        self.redactor = redactor
        self.push_types: Counter[str] = Counter()
        self.fingerprints: Counter[str] = Counter()
        self.messages = 0
        self.duplicates = 0
        self.connect_attempts = 0
        self.connect_successes = 0
        self.connect_failures = 0
        self.resubscribe_successes = 0
        self.resubscribe_failures = 0
        self.forced_drop_attempts = 0
        self.forced_drop_successes = 0
        self.forced_drop_failures = 0
        self.busy_poll_requests = 0
        self.busy_poll_failures = 0
        self.busy_samples = 0
        self.busy_transitions = 0
        self.busy_bridge_misses = 0
        self._last_busy_state: dict[str, tuple[bool, Any]] = {}

    async def on_message(self, message: dict[str, Any]) -> None:
        """Record one sanitized WebSocket push and duplicate metadata."""
        sanitized = self.redactor.sanitize(message)
        sanitized_extra_params = sanitized.get("extra_params")
        sequence_id = sanitized_extra_params.get("sequence_id") if isinstance(sanitized_extra_params, dict) else None
        if sequence_id:
            fingerprint_payload = {
                "push_type": sanitized.get("push_type"),
                "sequence_id": sequence_id,
            }
            fingerprint_source = "sequence_id"
        else:
            fingerprint_payload = sanitized
            fingerprint_source = "full_message"
        canonical = json.dumps(fingerprint_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        self.fingerprints[fingerprint] += 1
        duplicate_index = self.fingerprints[fingerprint]
        if duplicate_index > 1:
            self.duplicates += 1

        raw_push_type = message.get("push_type")
        if raw_push_type:
            push_type = str(raw_push_type)
        elif message.get("status") == "ok":
            push_type = "subscription_ack"
        else:
            push_type = "<missing>"
        extra_params = message.get("extra_params")
        event_type = extra_params.get("event_type") if isinstance(extra_params, dict) else None
        if push_type == "embedded_json" and event_type is None:
            event_type = "module_status"
        self.push_types[push_type] += 1
        self.messages += 1
        self.recorder.record(
            "websocket_message",
            sequence=self.messages,
            push_type=push_type,
            event_type=event_type,
            fingerprint=fingerprint,
            fingerprint_source=fingerprint_source,
            duplicate_index=duplicate_index,
            # JsonlRecorder performs the single redaction pass. Passing the
            # already-redacted copy here would hash identifiers twice and make
            # them impossible to correlate with topology/status records.
            message=message,
        )

    def summary(self) -> dict[str, Any]:
        """Return aggregate diagnostics without installation identifiers."""
        return {
            "messages": self.messages,
            "duplicates": self.duplicates,
            "push_types": dict(self.push_types),
            "connect_attempts": self.connect_attempts,
            "connect_successes": self.connect_successes,
            "connect_failures": self.connect_failures,
            "resubscribe_successes": self.resubscribe_successes,
            "resubscribe_failures": self.resubscribe_failures,
            "forced_drop_attempts": self.forced_drop_attempts,
            "forced_drop_successes": self.forced_drop_successes,
            "forced_drop_failures": self.forced_drop_failures,
            "busy_poll_requests": self.busy_poll_requests,
            "busy_poll_failures": self.busy_poll_failures,
            "busy_samples": self.busy_samples,
            "busy_transitions": self.busy_transitions,
            "busy_bridge_misses": self.busy_bridge_misses,
        }


class ObservedWebsocketClient(WebsocketClient):
    """WebSocket client that records lifecycle events without raw credentials."""

    def __init__(self, auth_handler: AuthHandler, state: ProbeState) -> None:
        super().__init__(auth_handler=auth_handler, message_callback=state.on_message)
        self._probe_state = state

    async def connect(self) -> None:
        self._probe_state.connect_attempts += 1
        attempt = self._probe_state.connect_attempts
        self._probe_state.recorder.record("websocket_connect_attempt", attempt=attempt)
        try:
            await super().connect()
        except Exception as error:
            self._probe_state.connect_failures += 1
            self._probe_state.recorder.record(
                "websocket_connect_failure",
                attempt=attempt,
                error_type=type(error).__name__,
                error=str(error),
            )
            raise
        self._probe_state.connect_successes += 1
        self._probe_state.recorder.record("websocket_connect_success", attempt=attempt)

    async def _listen(self) -> None:
        self._probe_state.recorder.record("websocket_listener_started")
        try:
            await super()._listen()
        except asyncio.CancelledError:
            self._probe_state.recorder.record("websocket_listener_stopped", reason="cancelled")
            raise
        except Exception as error:
            self._probe_state.recorder.record(
                "websocket_listener_stopped",
                reason="error",
                error_type=type(error).__name__,
                error=str(error),
                close_code=getattr(error, "code", None),
            )
            raise
        else:
            self._probe_state.recorder.record("websocket_listener_stopped", reason="clean")

    def abort_transport_for_test(self) -> None:
        """Abort only this client's socket to simulate a connection drop."""
        if not self._is_running or self._websocket is None:
            raise RuntimeError("No active WebSocket transport to abort.")
        transport = getattr(self._websocket, "transport", None)
        if transport is None or not callable(getattr(transport, "abort", None)):
            raise RuntimeError("The active WebSocket does not expose an abortable transport.")
        transport.abort()


def _default_output_path() -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path.cwd() / f"eos300-diagnostics-{timestamp}.jsonl"


def _select_home(account: AsyncAccount, requested_home_id: str | None) -> tuple[str, Any]:
    if not account.homes:
        raise RuntimeError("No homes returned by the API.")
    if requested_home_id:
        home = account.homes.get(requested_home_id)
        if home is None:
            raise RuntimeError("The requested home ID was not returned by the API.")
        return requested_home_id, home
    home_id = next(iter(account.homes))
    return home_id, account.homes[home_id]


def _extract_bridge_busy_samples(status: Any) -> list[dict[str, Any]]:
    """Extract BNC1/BNCX busy values while preserving missing-vs-false."""
    if not isinstance(status, dict):
        return []
    body = status.get("body")
    if not isinstance(body, dict):
        return []
    home = body.get("home")
    if not isinstance(home, dict):
        return []
    modules = home.get("modules")
    if not isinstance(modules, list):
        return []

    samples: list[dict[str, Any]] = []
    for module in modules:
        if not isinstance(module, dict) or module.get("type") not in {"BNC1", "BNCX"}:
            continue
        field_present = "busy" in module
        samples.append(
            {
                "bridge_id": module.get("id"),
                "bridge_type": module.get("type"),
                "busy_field_present": field_present,
                "busy": module.get("busy") if field_present else None,
                "reachable": module.get("reachable"),
                "websocket_connected": module.get("websocket_connected"),
            }
        )
    return samples


def _record_bridge_busy_samples(status: Any, state: ProbeState, sample_number: int) -> None:
    """Record compact bridge samples and count actual representation changes."""
    samples = _extract_bridge_busy_samples(status)
    if not samples:
        state.busy_bridge_misses += 1
        state.recorder.record(
            "bridge_busy_sample",
            sample_number=sample_number,
            bridge_found=False,
        )
        return

    for sample in samples:
        state.busy_samples += 1
        bridge_key = str(sample["bridge_id"])
        current = (sample["busy_field_present"], sample["busy"])
        previous = state._last_busy_state.get(bridge_key)
        changed = previous is not None and previous != current
        if changed:
            state.busy_transitions += 1
        state._last_busy_state[bridge_key] = current
        state.recorder.record(
            "bridge_busy_sample",
            sample_number=sample_number,
            bridge_found=True,
            changed=changed,
            **sample,
        )


async def _busy_poll_loop(
    account: AsyncAccount,
    home_id: str,
    state: ProbeState,
    interval: float,
) -> None:
    """Poll the read-only home status endpoint at a fixed start-to-start rate."""
    loop = asyncio.get_running_loop()
    sample_number = 0
    while True:
        started = loop.time()
        sample_number += 1
        state.busy_poll_requests += 1
        try:
            status = await account.async_get_home_status(home_id)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            state.busy_poll_failures += 1
            state.recorder.record(
                "bridge_busy_poll_failure",
                sample_number=sample_number,
                error_type=type(error).__name__,
                error=str(error),
            )
        else:
            _record_bridge_busy_samples(status, state, sample_number)

        elapsed = loop.time() - started
        await asyncio.sleep(max(0, interval - elapsed))


async def _resubscribe_loop(client: WebsocketClient, state: ProbeState, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await client.resubscribe()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            state.resubscribe_failures += 1
            state.recorder.record(
                "websocket_resubscribe",
                result="failure",
                error_type=type(error).__name__,
                error=str(error),
            )
        else:
            state.resubscribe_successes += 1
            state.recorder.record("websocket_resubscribe", result="success")


async def _force_drop_after(client: ObservedWebsocketClient, state: ProbeState, delay: float) -> None:
    """Abort the probe's socket after a delay so ``run_forever`` must reconnect."""
    await asyncio.sleep(delay)
    state.forced_drop_attempts += 1
    try:
        client.abort_transport_for_test()
    except Exception as error:
        state.forced_drop_failures += 1
        state.recorder.record(
            "websocket_forced_drop",
            result="failure",
            error_type=type(error).__name__,
            error=str(error),
        )
    else:
        state.forced_drop_successes += 1
        state.recorder.record("websocket_forced_drop", result="success", method="transport_abort")


async def _stop_client(client: WebsocketClient, run_task: asyncio.Task[Any]) -> None:
    await client.disconnect()
    try:
        await asyncio.wait_for(run_task, timeout=5)
    except TimeoutError:
        run_task.cancel()
        with suppress(asyncio.CancelledError):
            await run_task


async def run_live(args: argparse.Namespace, recorder: JsonlRecorder, state: ProbeState) -> None:
    username = os.getenv("BTICINOUSER")
    password = os.getenv("BTICINOPASSWORD")
    if not username or not password:
        raise RuntimeError("Set BTICINOUSER and BTICINOPASSWORD before running the live probe.")

    auth = AuthHandler(username, password)
    account = AsyncAccount(auth)
    client: ObservedWebsocketClient | None = None
    run_task: asyncio.Task[Any] | None = None
    resubscribe_task: asyncio.Task[Any] | None = None
    forced_drop_task: asyncio.Task[Any] | None = None
    busy_poll_task: asyncio.Task[Any] | None = None
    try:
        if args.force_drop_after < 0:
            raise ValueError("--force-drop-after cannot be negative.")
        if args.force_drop_after and args.force_drop_after >= args.duration:
            raise ValueError("--force-drop-after must be less than --duration.")
        if args.busy_poll_interval < 0:
            raise ValueError("--busy-poll-interval cannot be negative.")
        if 0 < args.busy_poll_interval < 0.5:
            raise ValueError("--busy-poll-interval must be at least 0.5 seconds when enabled.")

        recorder.record("api_request", operation="topology")
        await account.async_update_topology()
        home_id, home = _select_home(account, args.home_id or os.getenv("BTICINOHOMEID"))
        recorder.record(
            "topology",
            selected_home_id=home_id,
            home_count=len(account.homes),
            module_count=len(home.modules),
            raw=account.raw_data,
        )

        recorder.record("api_request", operation="home_status")
        status = await account.async_get_home_status(home_id)
        recorder.record("home_status", home_id=home_id, raw=status)

        recorder.record("api_request", operation="events", size=args.events_size)
        events = await account.async_get_events(home_id, size=args.events_size)
        recorder.record("events", home_id=home_id, raw=events)

        client = ObservedWebsocketClient(auth, state)
        run_task = asyncio.create_task(client.run_forever(reconnect_delay=args.reconnect_delay))
        if args.resubscribe_interval > 0:
            resubscribe_task = asyncio.create_task(
                _resubscribe_loop(client, state, args.resubscribe_interval),
            )
        if args.force_drop_after > 0:
            forced_drop_task = asyncio.create_task(
                _force_drop_after(client, state, args.force_drop_after),
            )
        if args.busy_poll_interval > 0:
            busy_poll_task = asyncio.create_task(
                _busy_poll_loop(account, home_id, state, args.busy_poll_interval),
            )
            print(
                f"Bridge busy polling active every {args.busy_poll_interval:g}s. "
                "Ring, answer, and end one intercom call while the probe is running."
            )
        recorder.record(
            "observation_started",
            duration_seconds=args.duration,
            busy_poll_interval=args.busy_poll_interval,
        )
        await asyncio.sleep(args.duration)
    finally:
        if busy_poll_task:
            busy_poll_task.cancel()
            with suppress(asyncio.CancelledError):
                await busy_poll_task
        if forced_drop_task:
            forced_drop_task.cancel()
            with suppress(asyncio.CancelledError):
                await forced_drop_task
        if resubscribe_task:
            resubscribe_task.cancel()
            with suppress(asyncio.CancelledError):
                await resubscribe_task
        if client and run_task:
            await _stop_client(client, run_task)
        await auth.close_session()


async def run_simulation(recorder: JsonlRecorder, state: ProbeState) -> None:
    """Exercise redaction, fingerprinting, and duplicate counting offline."""
    sample = {
        "push_type": "BNCX-incoming_call",
        "user_id": "user-secret-id",
        "extra_params": {
            "event_type": "incoming_call",
            "home_id": "home-secret-id",
            "device_id": "00:03:50:aa:bb:cc",
            "event_id": "00112233-4455-4677-8899-aabbccddeeff",
            "snapshot_url": "https://example.invalid/private?signed=secret",
        },
    }
    recorder.record("simulation_topology", email="owner@example.com", access_token="secret-token")
    await state.on_message(sample)
    await state.on_message(sample)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=600, help="Observation duration in seconds (default: 600).")
    parser.add_argument("--events-size", type=int, default=30, help="Number of recent events to fetch (default: 30).")
    parser.add_argument("--home-id", help="Optional home ID; defaults to BTICINOHOMEID or the first home.")
    parser.add_argument("--output", type=Path, help="Output JSONL path; must not already exist.")
    parser.add_argument("--reconnect-delay", type=float, default=15, help="WebSocket reconnect delay (default: 15).")
    parser.add_argument(
        "--resubscribe-interval",
        type=float,
        default=300,
        help="Seconds between token re-subscriptions; 0 disables it (default: 300).",
    )
    parser.add_argument(
        "--force-drop-after",
        type=float,
        default=0,
        help="Abort only the probe WebSocket after N seconds to test automatic reconnection; 0 disables it.",
    )
    parser.add_argument(
        "--busy-poll-interval",
        type=float,
        default=0,
        help="Poll read-only bridge busy status every N seconds; 0 disables it (minimum: 0.5).",
    )
    parser.add_argument("--simulate", action="store_true", help="Run an offline redaction/duplicate simulation.")
    return parser


async def async_main(args: argparse.Namespace) -> int:
    output_path = (args.output or _default_output_path()).expanduser().resolve()
    redactor = Redactor()
    recorder = JsonlRecorder(output_path, redactor)
    state = ProbeState(recorder, redactor)
    recorder.record(
        "session_start",
        mode="simulation" if args.simulate else "live",
        python=platform.python_version(),
        platform=platform.system(),
    )
    exit_code = 0
    try:
        if args.simulate:
            await run_simulation(recorder, state)
        else:
            await run_live(args, recorder, state)
    except KeyboardInterrupt:
        recorder.record("session_interrupted")
    except Exception as error:
        exit_code = 1
        recorder.record("session_error", error_type=type(error).__name__, error=str(error))
        _LOGGER.error("Probe failed (%s). Details are in %s", type(error).__name__, output_path)
    finally:
        recorder.record("session_summary", **state.summary())
        recorder.close()

    print(f"Diagnostic output: {output_path}")
    print(json.dumps(state.summary(), indent=2, sort_keys=True))
    return exit_code


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    logging.getLogger("pybticino").setLevel(logging.INFO)
    return asyncio.run(async_main(build_parser().parse_args()))


if __name__ == "__main__":
    sys.exit(main())
