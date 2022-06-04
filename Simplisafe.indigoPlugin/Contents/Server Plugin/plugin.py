#! /usr/bin/env python
# -*- coding: utf-8 -*-

import indigo
import logging
import json
import asyncio
from aiohttp import ClientSession
import simplipy

REFRESH_INTERVAL = 6.0 * 60.0 * 60.0    # 6 hours


async def get_api(username, password):
    """Create the aiohttp session and run."""
    async with ClientSession() as session:
        return await simplipy.API.async_from_credentials(username, password, session=session)


class SimpliSafe:

    def __init__(self, dev, refresh_token=None):
        self.logger = logging.getLogger("Plugin.SimpliSafe")
        self.authenticated = False
        self.next_refresh = time.time()
        self.access_token = None
        self.refresh_token = None
        self.authorization_code = None

        if not dev:  # temp account objects created during PIN authentication don't have an associated device
            return

        self.devID = dev.id

        if refresh_token:
            self.logger.info(f"{dev.name}: SimpliSafe created using refresh token = {refresh_token}")
            self.refresh_token = refresh_token
            self.do_token_refresh()

    def request_sms(self, valuesDict, typeId, devId):

        asyncio.run(get_api())
    # Authentication Step 1
    def request_pin(self):

        params = {'response_type': 'ecobeePin', 'client_id': API_KEY, 'scope': 'smartWrite'}
        try:
            request = requests.get('https://api.ecobee.com/authorize', params=params)
        except requests.RequestException as e:
            self.logger.error(f"PIN Request Error, exception = {e}")
            return None

        if request.status_code == requests.codes.ok:
            self.authorization_code = request.json()['code']
            pin = request.json()['ecobeePin']
            self.logger.info(f"PIN Request OK, pin = {pin}")
            return pin

        else:
            self.logger.error(f"PIN Request failed, response = '{request.text}'")
            return None

    # Authentication Step 2
    def get_tokens(self):

        params = {'grant_type': 'ecobeePin', 'code': self.authorization_code, 'client_id': API_KEY, 'ecobee_type': 'jwt'}
        try:
            request = requests.post('https://api.ecobee.com/token', params=params)
        except requests.RequestException as e:
            self.logger.error(f"Token Request Error, exception = {e}")
            self.authenticated = False
            return

        if request.status_code == requests.codes.ok:
            self.logger.info("Token Request OK")
            self.access_token = request.json()['access_token']
            self.refresh_token = request.json()['refresh_token']
            self.next_refresh = time.time() + (float(request.json()['expires_in']) * 0.80)
            self.authenticated = True
        else:
            self.logger.error("Token Request failed, response = '{}'".format(request.text))
            self.authenticated = False

    # called from __init__ or main loop to refresh the access tokens

    def do_token_refresh(self):
        if not self.refresh_token:
            self.authenticated = False
            return

        dev = indigo.devices[self.devID]
        self.logger.debug(f"{dev.name}: Token Refresh, old refresh_token = {self.refresh_token}")

        params = {'grant_type': 'refresh_token', 'refresh_token': self.refresh_token, 'client_id': API_KEY, 'ecobee_type': 'jwt'}
        try:
            request = requests.post('https://api.ecobee.com/token', params=params)
        except requests.RequestException as e:
            self.logger.warning(f"Token Refresh Error, exception = {e}")
            self.next_refresh = time.time() + 300.0  # try again in five minutes
            return

        if request.status_code == requests.codes.ok:
            if self.access_token and request.json()['access_token'] == self.access_token:
                self.logger.debug(f"{dev.name}: Access Token did not change")
            else:
                self.access_token = request.json()['access_token']
                self.logger.debug(f"{dev.name}: Token Refresh OK, new Access Token")

            if self.refresh_token and request.json()['refresh_token'] == self.refresh_token:
                self.logger.debug(f"{dev.name}: Refresh Token did not change")
            else:
                self.refresh_token = request.json()['refresh_token']
                self.logger.info(f"{dev.name}: Token Refresh OK, new refresh_token: {self.refresh_token}")

            self.next_refresh = time.time() + (float(request.json()['expires_in']) * 0.80)
            self.authenticated = True
            return

        try:
            error = request.json()['error']
            if error == 'invalid_grant':
                self.logger.error(f"{dev.name}: Token refresh failed, will retry in 5 minutes.")
                self.authenticated = False
            else:
                self.logger.error(f"{dev.name}: Token Refresh Error, error = {error}")
        except (Exception,):
            pass

        self.next_refresh = time.time() + 300.0  # try again in five minutes

   ########################################
    # Authentication routines
    ########################################

    async def get_api(self, username, password):
        """Create the aiohttp session and run."""
        async with ClientSession() as session:
            api = await simplipy.API.async_from_credentials(username, password, session=session)
            return api

    def request_sms(self, valuesDict, typeId, devId):

        api = asyncio.run(get_api(valuesDict['username'], valuesDict['password']))

        if devId in self.ecobee_accounts:
            self.temp_ecobeeAccount = self.ecobee_accounts[devId]
            self.logger.debug(f"request_pin: using existing Ecobee account {self.temp_ecobeeAccount.devID}")
        else:
            self.temp_ecobeeAccount = EcobeeAccount(None, None)
            self.logger.debug("request_pin: using temporary Ecobee account object")
        pin = self.temp_ecobeeAccount.request_pin()
        if pin:
            valuesDict["pin"] = pin
            valuesDict["authStatus"] = "PIN Request OK"
        else:
            valuesDict["authStatus"] = "PIN Request Failed"
        return valuesDict

    #    Authentication Step 2, called from Devices.xml

    def open_browser_to_ecobee(self, valuesDict, typeId, devId):
        self.browserOpen("https://www.ecobee.com/consumerportal/")

    #    Authentication Step 3, called from Devices.xml

    def get_tokens(self, valuesDict, typeId, devId):
        valuesDict["pin"] = ''
        self.temp_ecobeeAccount.get_tokens()
        if self.temp_ecobeeAccount.authenticated:
            valuesDict["authStatus"] = "Authenticated"
            self.pluginPrefs[REFRESH_TOKEN_PLUGIN_PREF.format(devId)] = self.temp_ecobeeAccount.refresh_token
            self.savePluginPrefs()
        else:
            valuesDict["authStatus"] = "Token Request Failed"
        return valuesDict




class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.logLevel = int(pluginPrefs.get("logLevel", logging.INFO))
        self.indigo_log_handler.setLevel(self.logLevel)
        self.plugin_file_handler.setLevel(self.logLevel)
        self.logger.debug(f"LogLevel = {self.logLevel}")

        self.ss_accounts = {}
        self.triggers = []
        self.refresh_tokens()

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            self.logLevel = int(valuesDict.get("logLevel", logging.INFO))
            self.indigo_log_handler.setLevel(self.logLevel)
            self.plugin_file_handler.setLevel(self.logLevel)
            self.logger.debug(f"New logLevel = {self.logLevel}")

    def deviceStartComm(self, device):
        self.logger.debug(f"{device.name}: Starting Device")


    def didDeviceCommPropertyChange(self, origDev, newDev): # noqa
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


    def menu_dump_devices(self):
        self.logger.info(f"ss_accounts=\n{json.dumps(self.ss_accounts, indent=4, sort_keys=True)}")
        return True
