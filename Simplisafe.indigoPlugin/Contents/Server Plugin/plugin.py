#! /usr/bin/env python
# -*- coding: utf-8 -*-

import indigo
import logging
import json
import asyncio
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
        self.loop = None
        self.sms_code = None
        self.start_request_auth_event = asyncio.Event()
        self.start_verify_sms_event = asyncio.Event()

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

    def runConcurrentThread(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(self.async_shutdown())
        self.loop.run_until_complete(self.async_main())

    def request_auth(self, valuesDict):
        self.logger.threaddebug(f"request_auth valuesDict = {valuesDict}")
        self.loop.create_task(self._async_request_auth())
        return valuesDict

    async def _async_request_auth(self):
        self.logger.debug(f"_async_request_auth")
        self.start_request_auth_event.set()

    def verify_sms(self, valuesDict):
        self.logger.threaddebug(f"verify_sms valuesDict = {valuesDict}")
        self.sms_code = valuesDict['auth_code']
        self.loop.create_task(self._async_verify_sms(self.sms_code))
        return valuesDict

    async def _async_verify_sms(self, sms_code):
        self.logger.debug(f"_async_verify_sms sms_code = {sms_code}")
        self.start_verify_sms_event.set()

    async def async_shutdown(self):
        while True:
            await asyncio.sleep(1.0)
            if self.stopThread:
                self.logger.debug("async_shutdown: shutdown()")
                self.start_request_auth_event.set()
                self.start_verify_sms_event.set()
                break

    async def async_main(self):
        """Create the aiohttp session and run."""
        async with ClientSession() as session:

            if self.refresh_token:
                self.logger.debug(f"async_main start with token {self.refresh_token}")
                try:
                    api = await API.async_from_refresh_token(self.refresh_token, session=session)
                except InvalidCredentialsError as err:
                    self.logger.debug(f"Error refreshing auth from token: {err}")
                    self.refresh_token = None

            else:
                # wait for Event from Config dialog to start auth process
                self.logger.warning("SimpliSafe plugin not authenticated - open plugin Configure dialog")
                await self.start_request_auth_event.wait()
                try:
                    api = await API.async_from_credentials(self.username, self.password, session=session)
                except InvalidCredentialsError as err:
                    self.logger.warning(f"Error requesting auth from credentials: {err}")
                    self.refresh_token = None
                self.logger.debug(f"async_from_credentials Auth State: {api.auth_state}")

                # wait for flag from Config dialog to verify the sms code
                await self.start_verify_sms_event.wait()
                try:
                    await api.async_verify_2fa_sms(self.sms_code)
                except InvalidCredentialsError as err:
                    self.logger.error("Invalid SMS 2FA code")

            self.logger.debug(f"Auth State: {api.auth_state}")
            self.logger.debug(f"user_id = {api.user_id}")
            self.logger.debug(f"refresh_token = {api.refresh_token}")
            self.pluginPrefs["refresh_token"] = api.refresh_token
            indigo.server.savePluginPrefs()

            simplisafe = SimpliSafe(api)
            try:
                await simplisafe.async_init()
            except SimplipyError as err:
                raise ConfigEntryNotReady from err

            systems = await api.async_get_systems()
            for systemid, system in systems.items():
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

            api.websocket.add_event_callback(self.event_handler)

            self.logger.debug("async_main: starting idle loop")
            try:
                while True:
                    await asyncio.sleep(1.0)
            except self.StopThread:
                self.logger.debug("async_main: stopping")

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
