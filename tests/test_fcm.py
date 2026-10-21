"""Tests for receiving call pushes through FCM."""

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
