#! /usr/bin/env python
# -*- coding: utf-8 -*-

import indigo
import logging
import json
import asyncio
from aiohttp import ClientSession
from simplipy.api import API, AuthStates
from simplipy.errors import SimplipyError, InvalidCredentialsError, Verify2FAError, Verify2FAPending

async def request_auth(username, password):
    """Create the aiohttp session and run."""
    async with ClientSession() as session:
        return await API.async_from_credentials(username, password, session=session)


async def auth_from_token(token):
    """Create the aiohttp session and run."""
    async with ClientSession() as session:
        return await API.async_from_refresh_token(token, session=session)


async def verify_sms(api, code):
    async with ClientSession() as session:
        await api.async_verify_2fa_sms(code)


class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.logLevel = int(pluginPrefs.get("logLevel", logging.INFO))
        self.indigo_log_handler.setLevel(self.logLevel)
        self.plugin_file_handler.setLevel(self.logLevel)
        self.logger.debug(f"LogLevel = {self.logLevel}")
        self.temp_api = None

        self.ss_accounts = {}
        self.triggers = []

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            self.logLevel = int(valuesDict.get("logLevel", logging.INFO))
            self.indigo_log_handler.setLevel(self.logLevel)
            self.plugin_file_handler.setLevel(self.logLevel)
            self.logger.debug(f"New logLevel = {self.logLevel}")

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

        if device.deviceTypeId == 'ssAccount':
            try:
                api = asyncio.run(auth_from_token(device.pluginProps['refreshToken']))
            except InvalidCredentialsError as err:
                self.logger.debug(f"Error refreshing auth from token: {err}")
            self.logger.debug(f"{device.name}: {api.auth_state}")

            # remember new refresh token
            newProps = device.pluginProps
            newProps.update({'refreshToken': api.refresh_token})
            device.replacePluginPropsOnServer(newProps)
            self.ss_accounts[device.id] = api

    def didDeviceCommPropertyChange(self, origDev, newDev):  # noqa
        return False

    def request_auth(self, valuesDict, typeId, devId):
        self.logger.debug(f"request_auth valuesDict = {valuesDict}")

        self.ss_accounts[devId] = asyncio.run(request_auth(valuesDict['username'], valuesDict['password']))
        self.logger.debug(f"request_auth api.auth_state = {self.ss_accounts[devId].auth_state}")
        valuesDict["authStatus"] = "SMS Requested"
        return valuesDict

    def verify_sms(self, valuesDict, typeId, devId):
        self.logger.debug(f"verify_sms valuesDict = {valuesDict}")
        try:
            asyncio.run(asyncio.run(verify_sms(self.ss_accounts[devId], valuesDict['authCode'])))
        except InvalidCredentialsError as err:
            self.logger.debug("Invalid SMS 2FA code")
            valuesDict["authStatus"] = "SMS Verify Failed"
        else:
            valuesDict["authStatus"] = "Authenticated"
            # remember new refresh token
            device = indigo.devices[devId]
            newProps = device.pluginProps
            newProps.update({'refreshToken': self.ss_accounts[devId].refresh_token})
            device.replacePluginPropsOnServer(newProps)

        return valuesDict

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
