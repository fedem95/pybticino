"""Call pushes through Firebase Cloud Messaging, the way the Android app gets them.

A Classe 300 EOS (BNCX) never puts its call offer on the push WebSocket: the
``BNCX-rtc`` push (the device SDP with session_id and tag_id) only reaches real
FCM push contexts, and the WebSocket gets ``BNCX-incoming_call`` alone. This
module registers an FCM client as the Netatmo Android app, adds its token to
the account with ``/api/addpushcontext`` and hands every push to a callback in
the same shape as a WebSocket push.

The app's Firebase identity (API key, app id, project, signing certificate) is
not part of this library. Callers pass it as an :class:`FcmAppConfig`, for
example read once from the app's APK with :meth:`FcmAppConfig.from_apk` and
kept in a private file.

Needs the ``fcm`` extra (firebase-messaging).
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
import contextlib
from dataclasses import dataclass
import hashlib
import json
import logging
from pathlib import Path
import re
import struct
from typing import Any
import zipfile

import aiohttp
from firebase_messaging import FcmPushClient, FcmPushClientConfig, FcmRegisterConfig
from firebase_messaging.const import GCM_REGISTER_URL
from firebase_messaging.fcmregister import FcmRegister

from .account import AsyncAccount
from .const import DEFAULT_ANDROID_VERSION, DEFAULT_APP_VERSION, DEFAULT_BUILD_NUMBER, DEFAULT_DEVICE_INFO
from .exceptions import PyBticinoException

_LOGGER = logging.getLogger(__name__)

APP_PACKAGE = "com.netatmo.camera"
PUSH_TYPE = "Android"
PUSH_APP_TYPE = "app_camera"

# APK Signing Block ids of the v2 and v3 signature schemes.
_APK_SIG_BLOCK_IDS = (0x7109871A, 0xF05368C0)
# What an Android 13 device with recent Play services sends to c2dm/register3.
_GMS_VERSION = "243930038"
_ANDROID_SDK = "33"
_FCM_CLIENT_VERSION = "fcm-24.0.0"
_FIREBASE_APP_NAME_HASH = (
    base64.urlsafe_b64encode(hashlib.sha1(b"[DEFAULT]").digest()).decode().rstrip("=")  # noqa: S324 - fixed by Firebase
)
# PHONE_REGISTRATION_ERROR is common right after a new checkin; a retry clears it.
_REGISTER_ATTEMPTS = 5

OnPushCallback = Callable[[dict[str, Any]], None]
OnCredentialsCallback = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class FcmAppConfig:
    """Firebase identity of the Netatmo Android app.

    The API key only works for requests that present the app's package name
    and signing certificate, so all four values come from the same APK.
    """

    api_key: str
    app_id: str
    project_id: str
    cert_sha1: str

    @property
    def sender_id(self) -> str:
        """The FCM sender id, which is the project number inside the app id."""
        return self.app_id.split(":")[1]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FcmAppConfig:
        """Build the config from a dict such as one saved with as_dict()."""
        missing = [name for name in ("api_key", "app_id", "project_id", "cert_sha1") if not data.get(name)]
        if missing:
            err_msg = f"FCM app config is missing: {', '.join(missing)}"
            raise PyBticinoException(err_msg)
        if not re.fullmatch(r"1:\d+:android:[0-9a-f]+", str(data["app_id"])):
            err_msg = "FCM app config has an app_id that is not an Android Firebase app id"
            raise PyBticinoException(err_msg)
        return cls(
            api_key=str(data["api_key"]),
            app_id=str(data["app_id"]),
            project_id=str(data["project_id"]),
            cert_sha1=str(data["cert_sha1"]).replace(":", "").upper(),
        )

    def as_dict(self) -> dict[str, str]:
        """Return the config as a JSON-friendly dict."""
        return {
            "api_key": self.api_key,
            "app_id": self.app_id,
            "project_id": self.project_id,
            "cert_sha1": self.cert_sha1,
        }

    @classmethod
    def from_apk(cls, apk: str | Path) -> FcmAppConfig:
        """Read the config from the Netatmo app's APK (blocking file I/O).

        The Firebase options are in ``resources.arsc`` (the google-services
        values) and the certificate in the APK Signing Block.
        """
        path = Path(apk)
        with zipfile.ZipFile(path) as zf:
            arsc = zf.read("resources.arsc")
        api_keys = set(re.findall(rb"AIza[0-9A-Za-z_-]{35}", arsc))
        app_ids = set(re.findall(rb"1:\d{6,}:android:[0-9a-f]{10,}", arsc))
        projects = set(re.findall(rb"https://([a-z0-9-]+)\.firebaseio\.com", arsc))
        if len(api_keys) != 1 or len(app_ids) != 1 or len(projects) != 1:
            err_msg = (
                f"Ambiguous Firebase config in the APK: keys={len(api_keys)} "
                f"app_ids={len(app_ids)} projects={len(projects)}"
            )
            raise PyBticinoException(err_msg)
        return cls(
            api_key=api_keys.pop().decode(),
            app_id=app_ids.pop().decode(),
            project_id=projects.pop().decode(),
            cert_sha1=_apk_signing_sha1(path.read_bytes()),
        )

    def register_config(self) -> FcmRegisterConfig:
        """Return the config in the form firebase-messaging expects."""
        return FcmRegisterConfig(
            project_id=self.project_id,
            app_id=self.app_id,
            api_key=self.api_key,
            messaging_sender_id=self.sender_id,
        )


def _length_prefixed(buf: bytes, offset: int) -> tuple[bytes, int]:
    size = struct.unpack_from("<I", buf, offset)[0]
    return buf[offset + 4 : offset + 4 + size], offset + 4 + size


def _apk_signing_sha1(data: bytes) -> str:
    """SHA-1 of the first signer's certificate, from the APK Signing Block (v2/v3)."""
    cd_offset = struct.unpack_from("<I", data, data.rindex(b"PK\x05\x06") + 16)[0]
    if data[cd_offset - 16 : cd_offset] != b"APK Sig Block 42":
        err_msg = "APK has no v2/v3 signing block"
        raise PyBticinoException(err_msg)
    pos = cd_offset - struct.unpack_from("<Q", data, cd_offset - 24)[0]
    while pos < cd_offset - 24:
        size, block_id = struct.unpack_from("<QI", data, pos)
        value = data[pos + 12 : pos + 8 + size]
        pos += 8 + size
        if block_id in _APK_SIG_BLOCK_IDS:
            signer, _ = _length_prefixed(_length_prefixed(value, 0)[0], 0)
            signed, _ = _length_prefixed(signer, 0)
            certificates, _ = _length_prefixed(signed, _length_prefixed(signed, 0)[1])
            certificate, _ = _length_prefixed(certificates, 0)
            return hashlib.sha1(certificate).hexdigest().upper()  # noqa: S324 - Google's key restriction uses SHA-1
    err_msg = "No v2/v3 signer found in the APK"
    raise PyBticinoException(err_msg)


def push_context(token: str) -> dict[str, Any]:
    """Return the /api/addpushcontext body the Android app sends for a token."""
    manufacturer, _, model = DEFAULT_DEVICE_INFO.partition("/")
    return {
        "credentials": json.dumps({"device_token": token}, separators=(",", ":")),
        "device_version": f"{manufacturer}+{model}".replace(" ", "+"),
        "os_version": DEFAULT_ANDROID_VERSION,
        "type": PUSH_TYPE,
        "app_version": DEFAULT_BUILD_NUMBER,
        "app_type": PUSH_APP_TYPE,
        "extra_param": "{}",
    }


def parse_push(data: dict[str, Any]) -> dict[str, Any] | None:
    """Turn an FCM push into the shape of a WebSocket push.

    FCM delivers every value as a string, so ``extra_params`` arrives as JSON
    text where the WebSocket has an object. Returns None for a message that is
    not a Netatmo event (no push_type).
    """
    if not data.get("push_type"):
        return None
    push = {key: value for key, value in data.items() if not key.startswith("_")}
    extra: Any = push.get("extra_params")
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except json.JSONDecodeError:
            _LOGGER.debug("FCM push %s has extra_params that are not JSON", push["push_type"])
    push["extra_params"] = extra if isinstance(extra, dict) else {}
    return push


def _firebase_session(app_config: FcmAppConfig) -> aiohttp.ClientSession:
    """Return an HTTP session that presents the app's identity to the Firebase APIs."""
    android_headers = {"X-Android-Package": APP_PACKAGE, "X-Android-Cert": app_config.cert_sha1}

    async def android_identity(request: aiohttp.ClientRequest, handler: Any) -> aiohttp.ClientResponse:
        # Only the Firebase APIs check the key restriction; the GCM checkin and
        # register calls fail when these headers are present.
        if request.url.host and request.url.host.endswith("googleapis.com"):
            request.headers.update(android_headers)
        return await handler(request)

    return aiohttp.ClientSession(middlewares=(android_identity,))


async def _register_android(
    register: FcmRegister, session: aiohttp.ClientSession, app_config: FcmAppConfig
) -> dict[str, Any]:
    """Check in to GCM and get an FCM token for the Android app, as Play services would."""
    options = await register.gcm_check_in()
    if not options:
        err_msg = "GCM checkin failed"
        raise PyBticinoException(err_msg)
    android_id, security_token = options["androidId"], options["securityToken"]
    installation = await register.fcm_install()
    if not installation:
        err_msg = "Firebase installation failed"
        raise PyBticinoException(err_msg)
    headers = {
        "Authorization": f"AidLogin {android_id}:{security_token}",
        "app": APP_PACKAGE,
        "gcm_ver": _GMS_VERSION,
        "User-Agent": f"Android-GCM/1.5 ({DEFAULT_DEVICE_INFO.partition('/')[2]})",
    }
    form = {
        "X-subtype": app_config.sender_id,
        "sender": app_config.sender_id,
        "X-app_ver": DEFAULT_BUILD_NUMBER,
        "X-osv": _ANDROID_SDK,
        "X-cliv": _FCM_CLIENT_VERSION,
        "X-gmsv": _GMS_VERSION,
        "X-appid": installation["fid"],
        "X-scope": "*",
        "X-Goog-Firebase-Installations-Auth": installation["token"],
        "X-gmp_app_id": app_config.app_id,
        "X-firebase-app-name-hash": _FIREBASE_APP_NAME_HASH,
        "X-app_ver_name": DEFAULT_APP_VERSION,
        "app": APP_PACKAGE,
        "device": android_id,
        "app_ver": DEFAULT_BUILD_NUMBER,
        "gcm_ver": _GMS_VERSION,
        "plat": "0",
        "cert": app_config.cert_sha1.lower(),
        "target_ver": "34",
    }
    last = ""
    for attempt in range(_REGISTER_ATTEMPTS):
        async with session.post(GCM_REGISTER_URL, headers=headers, data=form) as resp:
            last = (await resp.text()).strip()
        if last.startswith("token="):
            return {
                "android": True,
                "gcm": {"android_id": android_id, "security_token": security_token, "app_id": APP_PACKAGE},
                "fcm": {"registration": {"token": last.removeprefix("token=")}, "installation": installation},
                "keys": {},
            }
        _LOGGER.debug("FCM register attempt %d failed: %s", attempt + 1, last)
        await asyncio.sleep(2 + 2 * attempt)
    err_msg = f"FCM registration failed: {last}"
    raise PyBticinoException(err_msg)


class _AndroidFcmPushClient(FcmPushClient):
    """FcmPushClient for an Android-app registration.

    Messages for an Android app arrive as plain key/value ``app_data``; the base
    class only knows the encrypted web-push form, which needs ``crypto-key``.
    """

    def __init__(self, *args: Any, app_config: FcmAppConfig, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._app_config = app_config

    async def checkin_or_register(self) -> str:
        register = FcmRegister(self.fcm_config, http_client_session=self._http_client_session)
        if self.credentials and self.credentials.get("android"):
            gcm = self.credentials["gcm"]
            if await register.gcm_check_in(gcm["android_id"], gcm["security_token"]):
                return self.credentials["fcm"]["registration"]["token"]
            _LOGGER.info("Saved FCM identity refused at checkin; registering a new one")
        if self._http_client_session is None:
            err_msg = "FCM client needs an HTTP session"
            raise PyBticinoException(err_msg)
        self.credentials = await _register_android(register, self._http_client_session, self._app_config)
        if self.credentials_updated_callback:
            self.credentials_updated_callback(self.credentials)
        return self.credentials["fcm"]["registration"]["token"]

    def _handle_data_message(self, msg: Any) -> None:
        values = {item.key: item.value for item in msg.app_data}
        if values.get("message_type") == "deleted_messages":
            return
        if "crypto-key" in values:
            super()._handle_data_message(msg)
            return
        try:
            self.callback(values, msg.persistent_id, self.callback_context)
        except Exception:
            _LOGGER.exception("Error handling an FCM push")


class FcmCallListener:
    """Receive the account's pushes through FCM, registered as the Android app.

    ``on_push`` gets each Netatmo push in WebSocket shape (see parse_push). It
    runs on the event loop and must not block. The FCM identity is passed in
    as ``credentials`` and handed back through ``on_credentials_updated``
    whenever it changes: keep it private, it lets anyone receive the pushes.
    """

    def __init__(
        self,
        account: AsyncAccount,
        app_config: FcmAppConfig,
        on_push: OnPushCallback,
        credentials: dict[str, Any] | None = None,
        on_credentials_updated: OnCredentialsCallback | None = None,
    ) -> None:
        """Initialize the listener; nothing is contacted until async_start()."""
        self._account = account
        self._app_config = app_config
        self._on_push = on_push
        self._credentials = credentials
        self._on_credentials_updated = on_credentials_updated
        self._session: aiohttp.ClientSession | None = None
        self._client: _AndroidFcmPushClient | None = None
        self._context: dict[str, Any] | None = None

    @property
    def is_registered(self) -> bool:
        """Return True once the token is registered with the account."""
        return self._context is not None

    async def async_start(self) -> None:
        """Register with FCM, start listening and add the token to the account."""
        self._session = _firebase_session(self._app_config)
        self._client = _AndroidFcmPushClient(
            self._handle_push,
            self._app_config.register_config(),
            self._credentials,
            self._handle_credentials,
            http_client_session=self._session,
            # A long-running listener must keep reconnecting, never give up.
            config=FcmPushClientConfig(abort_on_sequential_error_count=None),
            app_config=self._app_config,
        )
        try:
            token = await self._client.checkin_or_register()
            await self._client.start()
            context = push_context(token)
            await self._account.async_add_push_context(context)
            self._context = context
        except BaseException:
            await self.async_stop(drop_context=False)
            raise
        _LOGGER.info("FCM push context registered")

    async def async_stop(self, drop_context: bool = True) -> None:
        """Stop listening; with drop_context, also remove the token from the account."""
        if drop_context and self._context:
            try:
                await self._account.async_drop_push_context(self._context["credentials"], PUSH_TYPE)
                _LOGGER.info("FCM push context removed")
            except Exception as err:
                _LOGGER.warning("Could not remove the FCM push context: %s", err)
        self._context = None
        client, self._client = self._client, None
        # stop() needs the locks start() creates.
        if client and client.stopping_lock is not None:
            with contextlib.suppress(Exception):
                await client.stop()
        session, self._session = self._session, None
        if session:
            await session.close()

    def _handle_credentials(self, credentials: dict[str, Any]) -> None:
        self._credentials = credentials
        if self._on_credentials_updated:
            self._on_credentials_updated(credentials)

    def _handle_push(self, data: dict[str, Any], _persistent_id: str, _context: Any) -> None:
        push = parse_push(data)
        if push is None:
            _LOGGER.debug("Ignoring an FCM message without push_type")
            return
        self._on_push(push)


def main(argv: list[str] | None = None) -> int:
    """Write the app config read from an APK to a private JSON file.

    ``python -m pybticino.fcm netatmo.apk bticino_intercom_fcm.json``
    """
    import argparse

    parser = argparse.ArgumentParser(description=main.__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("apk", type=Path, help="APK of the Netatmo Home + Security app (com.netatmo.camera)")
    parser.add_argument("output", type=Path, help="JSON file to create, e.g. bticino_intercom_fcm.json")
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error(f"{args.output} already exists")
    config = FcmAppConfig.from_apk(args.apk)
    args.output.touch(mode=0o600)
    args.output.write_text(json.dumps(config.as_dict(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output} (project {config.project_id}); keep it private and out of git.")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
