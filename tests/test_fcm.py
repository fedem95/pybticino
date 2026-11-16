"""Tests for receiving call pushes through FCM."""

import asyncio
import contextlib
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("firebase_messaging")

from pybticino import fcm
from pybticino.exceptions import PyBticinoException

# Placeholders only: the real values belong to the Netatmo app and never go in the repo.
APP_CONFIG = {
    "api_key": "test-api-key",
    "app_id": "1:123456789:android:abcdef0123456789",
    "project_id": "test-project",
    "cert_sha1": "ab:cd:ef",
}


class TestFcmAppConfig:
    """Test the Firebase identity container."""

    def test_round_trip(self):
        config = fcm.FcmAppConfig.from_dict(APP_CONFIG)
        assert config.sender_id == "123456789"
        assert config.cert_sha1 == "ABCDEF"
        assert fcm.FcmAppConfig.from_dict(config.as_dict()) == config

    def test_missing_values_are_named(self):
        with pytest.raises(PyBticinoException, match="api_key, cert_sha1"):
            fcm.FcmAppConfig.from_dict({"app_id": APP_CONFIG["app_id"], "project_id": "p"})

    def test_rejects_a_non_android_app_id(self):
        with pytest.raises(PyBticinoException, match="app_id"):
            fcm.FcmAppConfig.from_dict({**APP_CONFIG, "app_id": "1:123456789:web:abcdef"})


class TestParsePush:
    """Test the FCM push → WebSocket shape conversion."""

    def test_extra_params_json_is_decoded(self):
        data = {
            "push_type": "BNCX-rtc",
            "extra_params": json.dumps({"session_id": "s1", "data": {"type": "offer"}}),
            "_category": "com.netatmo.camera",
        }
        push = fcm.parse_push(data)
        assert push == {"push_type": "BNCX-rtc", "extra_params": {"session_id": "s1", "data": {"type": "offer"}}}

    def test_message_without_push_type_is_ignored(self):
        assert fcm.parse_push({"message": "hello"}) is None

    def test_bad_extra_params_become_empty(self):
        push = fcm.parse_push({"push_type": "BNCX-rtc", "extra_params": "{not json"})
        assert push["extra_params"] == {}


def test_push_context_body():
    body = fcm.push_context("tok")
    assert json.loads(body["credentials"]) == {"device_token": "tok"}
    assert body["type"] == "Android"
    assert body["app_type"] == "app_camera"


class TestFcmCallListener:
    """Test the listener lifecycle with the FCM client mocked."""

    @pytest.fixture
    def client(self, monkeypatch):
        client = MagicMock()
        client.checkin_or_register = AsyncMock(return_value="tok")
        client.start = AsyncMock()
        client.stop = AsyncMock()
        client.stopping_lock = object()
        client.tasks = []
        monkeypatch.setattr(fcm, "_AndroidFcmPushClient", MagicMock(return_value=client))
        return client

    @pytest.fixture
    def account(self):
        account = MagicMock()
        account.async_add_push_context = AsyncMock(return_value={"status": "ok"})
        account.async_drop_push_context = AsyncMock(return_value={"status": "ok"})
        return account

    async def test_start_registers_and_stop_drops(self, client, account):
        listener = fcm.FcmCallListener(account, fcm.FcmAppConfig.from_dict(APP_CONFIG), MagicMock())
        await listener.async_start()
        assert listener.is_registered
        context = account.async_add_push_context.call_args[0][0]
        assert json.loads(context["credentials"]) == {"device_token": "tok"}

        await listener.async_stop()
        account.async_drop_push_context.assert_awaited_once_with(context["credentials"], "Android")
        client.stop.assert_awaited_once()
        assert not listener.is_registered

    async def test_stop_without_drop_keeps_the_context(self, client, account):
        listener = fcm.FcmCallListener(account, fcm.FcmAppConfig.from_dict(APP_CONFIG), MagicMock())
        await listener.async_start()
        await listener.async_stop(drop_context=False)
        account.async_drop_push_context.assert_not_awaited()

    async def test_failed_registration_cleans_up(self, client, account):
        account.async_add_push_context.side_effect = PyBticinoException("nope")
        listener = fcm.FcmCallListener(account, fcm.FcmAppConfig.from_dict(APP_CONFIG), MagicMock())
        with pytest.raises(PyBticinoException):
            await listener.async_start()
        client.stop.assert_awaited_once()
        account.async_drop_push_context.assert_not_awaited()

    async def test_pushes_reach_the_callback_parsed(self, client, account):
        on_push = MagicMock()
        listener = fcm.FcmCallListener(account, fcm.FcmAppConfig.from_dict(APP_CONFIG), on_push)
        listener._handle_push({"push_type": "BNCX-rtc", "extra_params": '{"session_id": "s1"}'}, "pid", None)
        listener._handle_push({"from": "123"}, "pid2", None)
        on_push.assert_called_once_with({"push_type": "BNCX-rtc", "extra_params": {"session_id": "s1"}})

    async def test_credentials_updates_are_forwarded(self, client, account):
        saved = MagicMock()
        listener = fcm.FcmCallListener(
            account, fcm.FcmAppConfig.from_dict(APP_CONFIG), MagicMock(), on_credentials_updated=saved
        )
        listener._handle_credentials({"android": True})
        saved.assert_called_once_with({"android": True})


# --- A connection whose socket has closed (the 16/11 and 15/11 crashes) ---

SPIN_GUARD = 200


class _Writer:
    """The stream writer side: only closing matters here."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _client_on_a_closed_socket(client_class):
    """A client mid-session whose socket has failed, while a reset holds its lock.

    That is the state of the incident: the monitor's reset holds the lock and is
    connecting again (run state STARTING_CONNECTION), and the listen loop reads
    the old stream, a real StreamReader with the socket's exception stored, so
    readexactly raises it again on every call without yielding.
    """
    from firebase_messaging.fcmpushclient import FcmPushClientConfig, FcmPushClientRunState

    kwargs = {"app_config": fcm.FcmAppConfig.from_dict(APP_CONFIG)} if client_class is fcm._AndroidFcmPushClient else {}
    client = client_class(
        MagicMock(),
        fcm.FcmAppConfig.from_dict(APP_CONFIG).register_config(),
        {"gcm": {"android_id": "1", "security_token": "2"}},
        config=FcmPushClientConfig(abort_on_sequential_error_count=None, connection_retry_count=1),
        **kwargs,
    )
    reader = asyncio.StreamReader()
    reader.set_exception(ConnectionResetError(104, "Connection reset by peer"))
    calls = {"read": 0}
    read = reader.readexactly

    async def counted_readexactly(n):
        calls["read"] += 1
        if calls["read"] >= SPIN_GUARD:
            client.do_listen = False  # stop a spinning loop so the test ends
        return await read(n)

    reader.readexactly = counted_readexactly
    client.reader = reader
    client.writer = _Writer()
    client.do_listen = True
    client.first_message = False
    client.last_login_time = 0
    client.reset_lock = asyncio.Lock()
    client.stopping_lock = asyncio.Lock()
    client._connect_with_retry = AsyncMock(return_value=True)

    async def login_then_reset_in_progress():
        # what the monitor's reset leaves behind while it connects again
        client.run_state = FcmPushClientRunState.STARTING_CONNECTION

    client._login = login_then_reset_in_progress
    return client, calls


async def _hold_reset_lock_while(client, run):
    await client.reset_lock.acquire()
    try:
        await asyncio.wait_for(run(), timeout=5)
    finally:
        client.reset_lock.release()


async def test_firebase_messaging_spins_on_a_closed_socket(caplog):
    """The library's own client loops on the failed stream: the crash, reproduced."""
    from firebase_messaging import FcmPushClient

    client, calls = _client_on_a_closed_socket(FcmPushClient)
    writer = client.writer
    await _hold_reset_lock_while(client, client._listen)
    # only the guard stopped it, and every turn logged a traceback
    assert calls["read"] == SPIN_GUARD
    assert caplog.text.count("Unexpected exception during read") >= SPIN_GUARD - 1
    assert writer.closed  # only because the loop was made to end


async def test_closed_socket_ends_the_client_at_once(caplog):
    """Our client closes the connection on the first read error and stops."""
    client, calls = _client_on_a_closed_socket(fcm._AndroidFcmPushClient)
    writer = client.writer
    await _hold_reset_lock_while(client, client._listen)
    assert calls["read"] == 1
    assert caplog.text.count("Unexpected exception during read") == 1
    assert writer.closed
    assert client.do_listen is False


class TestReconnect:
    """The listener opens a new connection after a growing wait."""

    @staticmethod
    def _dying_client():
        """A client whose connection ends as soon as it starts."""
        client = MagicMock()
        client.stopping_lock = object()
        client.stop = AsyncMock()
        client._do_writer_close = AsyncMock()

        async def start():
            done = asyncio.get_running_loop().create_future()
            done.set_result(None)
            client.tasks = [done]

        client.start = start
        client.tasks = []
        return client

    async def _delays(self, monkeypatch, count):
        delays = []
        enough = asyncio.Event()

        async def record(delay):
            delays.append(delay)
            if len(delays) >= count:
                enough.set()
            await asyncio.sleep(0)

        monkeypatch.setattr(fcm, "_sleep", record)
        listener = fcm.FcmCallListener(MagicMock(), fcm.FcmAppConfig.from_dict(APP_CONFIG), MagicMock())
        clients = []

        def new_client():
            clients.append(self._dying_client())
            return clients[-1]

        monkeypatch.setattr(listener, "_new_client", new_client)
        first = new_client()
        await first.start()
        listener._client = first
        supervisor = asyncio.create_task(listener._async_supervise())
        await asyncio.wait_for(enough.wait(), timeout=2)
        supervisor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await supervisor
        return delays, clients

    async def test_waits_grow_up_to_the_maximum(self, monkeypatch):
        delays, clients = await self._delays(monkeypatch, 8)
        assert delays == [5, 10, 20, 40, 80, 160, 300, 300]
        # every ended client was stopped and its connection closed
        for client in clients[:-1]:
            client.stop.assert_awaited_once()
            client._do_writer_close.assert_awaited_once()

    async def test_a_connection_that_stayed_up_starts_over(self, monkeypatch):
        monkeypatch.setattr(fcm, "RECONNECT_STABLE_SECONDS", 0)
        delays, _ = await self._delays(monkeypatch, 3)
        assert delays == [5, 5, 5]

    async def test_stop_ends_the_reconnects(self, monkeypatch):
        account = MagicMock()
        account.async_add_push_context = AsyncMock(return_value={"status": "ok"})
        account.async_drop_push_context = AsyncMock(return_value={"status": "ok"})
        client = self._dying_client()
        client.checkin_or_register = AsyncMock(return_value="tok")
        monkeypatch.setattr(fcm, "_AndroidFcmPushClient", MagicMock(return_value=client))
        waits = asyncio.Event()

        async def blocked(_delay):
            waits.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(fcm, "_sleep", blocked)
        listener = fcm.FcmCallListener(account, fcm.FcmAppConfig.from_dict(APP_CONFIG), MagicMock())
        await listener.async_start()
        await asyncio.wait_for(waits.wait(), timeout=2)  # the connection ended, a reconnect waits
        await listener.async_stop()
        assert listener._supervisor is None
        assert listener._client is None
