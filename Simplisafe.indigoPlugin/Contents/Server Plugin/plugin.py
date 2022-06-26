#! /usr/bin/env python
# -*- coding: utf-8 -*-

import indigo
import logging
import json
import threading
import asyncio

import simplipy.api
from aiohttp import ClientSession

from SimpliSafe import SimpliSafe

from simplipy import API
from simplipy.errors import (
    EndpointUnavailableError,
    InvalidCredentialsError,
    SimplipyError,
    WebsocketError,
)

class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.logLevel = int(pluginPrefs.get("logLevel", logging.INFO))
        self.indigo_log_handler.setLevel(self.logLevel)
        self.plugin_file_handler.setLevel(self.logLevel)
        self.logger.debug(f"LogLevel = {self.logLevel}")

        self.pluginPrefs = pluginPrefs
        self.refresh_token = pluginPrefs.get("refresh_token", None)
        self.username = pluginPrefs.get("username", None)
        self.password = pluginPrefs.get("password", None)
        self.triggers = []
        self._event_loop = None
        self._async_thread = None
        self._api = None
        self._session = None
        self.sms_code = None
        self.auth_wait_event = asyncio.Event()
        self.auth_complete_event = asyncio.Event()
        self.simplisafe = None

    def validatePrefsConfigUi(self, valuesDict):

        errorDict = indigo.Dict()
        if self.refresh_token:
            valuesDict['refresh_token'] = self.refresh_token    # force in the new one that was obtained asynchronously
        valuesDict['auth_code'] = ""
        username = valuesDict.get('username', None)
        if not username or not len(username):
            errorDict['username'] = "Username is required"
        password = valuesDict.get('password', None)
        if not password or not len(password):
            errorDict['password'] = "Password is required"
        if len(errorDict) > 0:
            return False, valuesDict, errorDict
        return True

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            self.username = valuesDict["username"]
            self.password = valuesDict["password"]
            self.logLevel = int(valuesDict.get("logLevel", logging.INFO))
            self.indigo_log_handler.setLevel(self.logLevel)
            self.plugin_file_handler.setLevel(self.logLevel)
            self.logger.debug(f"LogLevel = {self.logLevel}")

    def startup(self):
        self.logger.info(f"SimpliSafe starting")

        # async thread is used instead of concurrent thread
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._async_thread = threading.Thread(target=self._run_async_thread)
        self._async_thread.start()

    def shutdown(self):  # noqa
        self.logger.info(f"SimpliSafe stopping")

    def _run_async_thread(self):
        self.logger.debug("_run_async_thread starting")
        self._event_loop.create_task(self.async_main())
        self._event_loop.run_until_complete(self._async_stop())
        self._event_loop.close()

    async def _async_stop(self):
        self.logger.debug("_async_stop waiting")
        while True:
            await asyncio.sleep(1.0)
            if self.stopThread:
                self.logger.debug("_async_stop: stopping")
                self.auth_wait_event.set()
                break

    def request_auth(self, valuesDict):
        self.logger.threaddebug(f"request_auth valuesDict = {valuesDict}")
        self._event_loop.create_task(self._async_auth_wait_continue())
        return valuesDict

    def verify_sms(self, valuesDict):
        self.logger.threaddebug(f"verify_sms valuesDict = {valuesDict}")
        self.sms_code = valuesDict['auth_code']
        self._event_loop.create_task(self._async_auth_wait_continue())
        return valuesDict

    async def _async_auth_wait_continue(self):
        self.logger.debug(f"_async_auth_wait_continue")
        self.auth_wait_event.set()

    # Use refresh token to authenticate with SimpliSafe
    async def _authenticate(self):
        self.logger.debug(f"_authenticate with token '{self.refresh_token}'")
        if self.refresh_token:
            try:
                self._api = await API.async_from_refresh_token(self.refresh_token, session=self._session)
            except InvalidCredentialsError as err:
                self.logger.warning(f"_authenticate: Error refreshing auth token: {err}")
            except Exception as err:
                self.logger.warning(f"_authenticate: Error refreshing auth token: {err}")

        if self._api and self._api.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
            self.auth_complete_event.set()
        else:
            # no token or refresh did not work, start the auth flow
            self._event_loop.create_task(self._auth_flow_1())

    # wait for Event from Config dialog to start auth process
    async def _auth_flow_1(self):
        self.logger.debug(f"_auth_flow_1")
        self.logger.warning("SimpliSafe plugin not authenticated - open plugin Configure dialog")
        if await self.auth_wait_event.wait():
            self.logger.debug(f"_auth_flow_1 auth_wait_event set")
            # user presses the button, so go to next step
            self.auth_wait_event.clear()
            self._event_loop.create_task(self._auth_flow_2())
        else:
            self.logger.debug(f"_auth_flow_1 auth_wait_event timeout")
            self._event_loop.create_task(self._auth_flow_1())

    # Attempt to use username and password to authenticate with SimpliSafe
    async def _auth_flow_2(self):
        self.logger.debug(f"_auth_flow_2")
        if not self.username or not self.password:
            self.logger.error("SimpliSafe plugin not authenticated - username or password not set")
            self._event_loop.create_task(self._auth_flow_1())
            return

        try:
            self._api = await API.async_from_credentials(self.username, self.password, session=self._session)
        except InvalidCredentialsError as err:
            self.logger.warning(f"Error requesting auth from credentials: {err}")
        except Exception as err:
            self.logger.warning(f"Error requesting auth from credentials: {err}")

        self.logger.debug(f"async_from_credentials Auth State: {self._api.auth_state}")

        if self._api and self._api.auth_state == simplipy.api.AuthStates.PENDING_2FA_SMS:
            self._event_loop.create_task(self._auth_flow_3())
        elif self._api and self._api.auth_state == simplipy.api.AuthStates.PENDING_2FA_EMAIL:
            self.logger.warning("SimpliSafe authentication in progress - verify 2FA email")
            self._event_loop.create_task(self._auth_flow_4())
        elif self._api and self._api.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
            self.auth_complete_event.set()

    # wait for Event from Config dialog to verify SMS code
    async def _auth_flow_3(self):
        self.logger.debug(f"_auth_flow_3")
        self.logger.warning("SimpliSafe authentication in progress - enter SMS code in Configure dialog")

        # wait for flag from Config dialog to verify the sms code
        if await self.auth_wait_event.wait():
            # user presses the button, so go to next step
            self.auth_wait_event.clear()
            try:
                await self._api.async_verify_2fa_sms(self.sms_code)
            except InvalidCredentialsError as err:
                self.logger.error("Invalid SMS 2FA code")

            if self._api and self._api.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
                self.auth_complete_event.set()
                return

        # timed out, or verify failed, do it again
        self._event_loop.create_task(self._auth_flow_2())

    # wait for user to validate 2FA email
    async def _auth_flow_4(self):
        self.logger.debug(f"_auth_flow_4")
        await asyncio.sleep(3.0)
        try:
            await self._api.async_verify_2fa_email()
        except Verify2FAPending as err:
            self.logger.warning(f"Verify 2FA email pending: {err}")

        if self._api and self._api.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
            self.auth_complete_event.set()
            return

        # timed out, or verify failed, do it again
        self._event_loop.create_task(self._auth_flow_2())


    async def async_main(self):
        self.logger.debug("async_main starting")

        """Create the aiohttp session and run."""
        async with ClientSession() as self._session:

            # Authentication Flow
            await self._authenticate()
            self.logger.debug(f"async_main waiting for auth_complete_event")
            await self.auth_complete_event.wait()

            # Authentication complete

            self.logger.debug(f"Auth State: {self._api.auth_state}")
            self.logger.debug(f"user_id = {self._api.user_id}")
            self.logger.debug(f"refresh_token = {self._api.refresh_token}")
            self.pluginPrefs["refresh_token"] = self._api.refresh_token
            indigo.server.savePluginPrefs()

            self._api.websocket.add_event_callback(self.event_handler)

            self.simplisafe = SimpliSafe(self._api)
            try:
                await simplisafe.async_init()
            except SimplipyError as err:
                raise ConfigEntryNotReady from err

            for systemid, system in self.simplisafe.systems.items():
                self.logger.debug(f"System: {system.system_id}")
                self.logger.debug(f"\taddress = {system.address}")
                self.logger.debug(f"\tconnection_type = {system.connection_type}")
                self.logger.debug(f"\tserial = {system.serial}")
                self.logger.debug(f"\tversion = {system.version}")
                self.logger.debug(f"\tstate = {system.state}")
                self.logger.debug(f"\tsensors:")
                for serial, sensor in system.sensors.items():
                    self.logger.debug(f"\t\tname = {sensor.name}")
                    self.logger.debug(f"\t\ttype = {sensor.type}")

    def event_handler(self, event):
        self.logger.debug(f"Received a SimpliSafe™ event: {event.info}")

    ##################
    # Device Methods
    ##################

    def getDeviceConfigUiValues(self, pluginProps, typeId, devId):
        self.logger.debug(f"getDeviceConfigUiValues, typeId = {typeId}, pluginProps = {pluginProps}")
        valuesDict = indigo.Dict(pluginProps)
        errorsDict = indigo.Dict()
        return valuesDict, errorsDict

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.logger.debug(f"validateDeviceConfigUi, typeId = {typeId}, valuesDict = {valuesDict}")
        errorsDict = indigo.Dict()
        if len(errorsDict) > 0:
            return False, valuesDict, errorsDict
        return True, valuesDict

    def deviceStartComm(self, device):
        self.logger.debug(f"{device.name}: Starting Device")

    def deviceStopComm(self, device):
        self.logger.debug(f"{device.name}: Stopping Device")

    def didDeviceCommPropertyChange(self, origDev, newDev):  # noqa
        return False

    ########################################
    # Trigger (Event) handling
    ########################################

    def triggerStartProcessing(self, trigger):
        self.logger.debug(f"{trigger.name}: Adding Trigger")
        assert trigger.id not in self.triggers
        self.triggers.append(trigger.id)

    def triggerStopProcessing(self, trigger):
        self.logger.debug(f"{trigger.name}: Removing Trigger")
        assert trigger.id in self.triggers
        self.triggers.remove(trigger.id)

    # doesn't do anything, just needed to force other menus to dynamically refresh
    def menuChanged(self, valuesDict=None, typeId=None, devId=None):  # noqa
        return valuesDict

    ########################################
    # Action handling
    ########################################
    def actionSetMode(self, action, systemDevice, callerWaitingForResult):
        mode = action.props.get("mode", "away")
        system_id = systemDevice.address
        self._event_loop.create_task(self._async_set_mode(system_id, mode))

    async def _async_set_mode(self, system_id, mode):

        pass