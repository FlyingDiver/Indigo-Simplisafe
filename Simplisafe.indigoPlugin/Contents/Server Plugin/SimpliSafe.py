import asyncio
from aiohttp import ClientSession
import aiofiles
from aioconsole import ainput

from simplipy import API
from simplipy.errors import (
    EndpointUnavailableError,
    InvalidCredentialsError,
    SimplipyError,
    WebsocketError,
)

from simplipy.websocket import (
    EVENT_AUTOMATIC_TEST,
    EVENT_CAMERA_MOTION_DETECTED,
    EVENT_CONNECTION_LOST,
    EVENT_CONNECTION_RESTORED,
    EVENT_DEVICE_TEST,
    EVENT_DOORBELL_DETECTED,
    EVENT_LOCK_LOCKED,
    EVENT_LOCK_UNLOCKED,
    EVENT_POWER_OUTAGE,
    EVENT_POWER_RESTORED,
    EVENT_SECRET_ALERT_TRIGGERED,
    EVENT_SENSOR_PAIRED_AND_NAMED,
    EVENT_USER_INITIATED_TEST,
    WebsocketEvent,
)
import logging

REFRESH_TIMER = 30 * 60.0   # 30 minutes

class SimpliSafe:
    """Define a SimpliSafe data object."""

    def __init__(self, api: API) -> None:
        """Initialize."""
        logging.basicConfig(format='%(asctime)s.%(msecs)02d\t%(levelname)6s %(name)12s.%(funcName)-30s%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.logger = logging.getLogger("SimpliSafe")
        self.logger.setLevel(logging.DEBUG)

        self._api = api
        self._token_refresh_task: asyncio.Task | None = None
        self._websocket_reconnect_task: asyncio.Task | None = None
        self.initial_event_to_use: dict[int, dict[str, Any]] = {}
        self.subscription_data: dict[int, Any] = api.subscription_data
        self.systems: dict[int, SystemType] = {}

    async def _async_start_websocket_loop(self) -> None:
        """Start a websocket reconnection loop."""
        assert self._api.websocket
        try:
            await self._api.websocket.async_connect()
            await self._api.websocket.async_listen()
        except asyncio.CancelledError as err:
            raise
        except WebsocketError as err:
            self.logger.error(f"_async_start_websocket_loop: WebsocketError: {err}")
        except Exception as err:  # pylint: disable=broad-except
            self.logger.error(f"_async_start_websocket_loop: Exception: {err}")

        await self._async_cancel_websocket_loop()
        self._websocket_reconnect_task = asyncio.create_task(self._async_start_websocket_loop())

    async def _async_cancel_websocket_loop(self) -> None:
        """Stop any existing websocket reconnection loop."""
        if self._websocket_reconnect_task:
            self._websocket_reconnect_task.cancel()
            try:
                await self._websocket_reconnect_task
            except asyncio.CancelledError as err:
                self._websocket_reconnect_task = None
            except Exception as err:  # pylint: disable=broad-except
                self.logger.error(f"_async_cancel_websocket_loop: Exception: {err}")

            assert self._api.websocket
            await self._api.websocket.async_disconnect()

    async def _async_token_refresh_loop(self) -> None:
        try:
            while True:
                self.logger.debug(f"do_token_refresh: starting timer for {REFRESH_TIMER} seconds")
                await asyncio.sleep(REFRESH_TIMER)
                await self._api._async_refresh_access_token() # noqa
                self.logger.debug(f"do_token_refresh: New Refresh Token = {_api.refresh_token}")
        except asyncio.CancelledError:
            self.logger.debug("do_token_refresh: cancelled")
            raise

    async def _async_websocket_on_event(self, event: WebsocketEvent) -> None:
        """Define a callback for receiving a websocket event."""
        self.logger.debug(f"_async_websocket_on_event, event: {event.info}")

    async def async_update(self) -> None:
        """Get updated data from SimpliSafe."""
        self.logger.debug("async_update")

        async def async_update_system(system: SystemType) -> None:
            """Update a system."""
            await asyncio.sleep(0)

        tasks = [async_update_system(system) for system in self.systems.values()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    async def async_init(self) -> None:
        """Initialize the SimpliSafe "manager" class."""

        async def async_save_refresh_token(token: str) -> None:
            """Save a refresh token to the config entry."""
            self.logger.debug(f"async_save_refresh_token: {token}")
            async with aiofiles.open("token_file", "w", encoding="utf-8") as f:
                await f.write(token)

        async def async_handle_refresh_token(token: str) -> None:
            """Handle a new refresh token."""
            await async_save_refresh_token(token)

            # Open a new websocket connection with the fresh token:
            assert self._api.websocket
            await self._async_cancel_websocket_loop()
            self._websocket_reconnect_task = asyncio.create_task(self._async_start_websocket_loop())

        assert self._api.refresh_token
        assert self._api.websocket

        # Save the refresh token we got on entry setup:
        await async_save_refresh_token(self._api.refresh_token)

        self._api.websocket.add_event_callback(self._async_websocket_on_event)
        self._api.add_refresh_token_callback(async_handle_refresh_token)

        self._websocket_reconnect_task = asyncio.create_task(self._async_start_websocket_loop())

        # force refresh the auth token, as the library won't do it without consistent API calls
        self._token_refresh_task = asyncio.create_task(self._async_token_refresh_loop())

        self.systems = await self._api.async_get_systems()
        for system in self.systems.values():

            # Future events will come from the websocket, but since subscription to the
            # websocket doesn't provide the most recent event, we grab it from the REST
            # API to ensure event-related attributes aren't empty on startup:
            try:
                self.initial_event_to_use[
                    system.system_id
                ] = await system.async_get_latest_event()
            except SimplipyError as err:
                self.logger.error(f"async_init: SimplipyError: {err}")
                self.initial_event_to_use[system.system_id] = {}

async def main() -> None:
    """Create the aiohttp session and run."""
    async with ClientSession() as session:

        try:
            async with aiofiles.open("token_file", "r", encoding="utf-8") as f:
                refresh_token = await f.read()
        except OSError:
            refresh_token = None

        if refresh_token:
            _api = await API.async_from_refresh_token(refresh_token, session=session)
        else:
            username = await ainput("Username: ")
            password = await ainput("Password: ")
            _api = await API.async_from_credentials(username, password, session=session)

            sms = await ainput("SMS Code: ")
            try:
                await _api.async_verify_2fa_sms(sms)
            except InvalidCredentialsError as err:
                print("Invalid SMS 2FA code")

        print(f"Authentication Successful: {_api.auth_state}")
        print(f"Refresh Token: {_api.refresh_token}")

        simplisafe = SimpliSafe(_api)
        try:
            await simplisafe.async_init()
        except SimplipyError as err:
            raise ConfigEntryNotReady from err

        systems = await _api.async_get_systems()
        for systemid, system in systems.items():
            print(f"System: {system.system_id} @ {system.address}: {system.state}")

        while True:
            # get commands
            await asyncio.sleep(0)
            cmd = await ainput("Command: ")
            match cmd:
                case 'quit':
                    break
                case 'off':
                    await system.async_set_off()
                    await system.async_update()
                case 'home':
                    await system.async_set_home()
                    await system.async_update()
                case 'away':
                    await system.async_set_away()
                    await system.async_update()
                case 'state':
                    print(f"System state: {system.state}")
                case '':
                    continue
                case _:
                    print(f"Unknown command '{cmd}'")

if __name__ == '__main__':
    asyncio.run(main(), debug=True)
