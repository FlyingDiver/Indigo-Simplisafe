#! /usr/bin/env python
# -*- coding: utf-8 -*-

import indigo
import logging
import json
import time
import threading
import asyncio
from aiohttp import ClientSession

import simplipy.api
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

state_strings = {
    simplipy.system.SystemStates.ALARM: "Alarm",
    simplipy.system.SystemStates.ALARM_COUNT: "Alarm Count",
    simplipy.system.SystemStates.AWAY: "Away",
    simplipy.system.SystemStates.AWAY_COUNT: "Away Count",
    simplipy.system.SystemStates.ENTRY_DELAY: "Entry Delay",
    simplipy.system.SystemStates.ERROR: "Error",
    simplipy.system.SystemStates.EXIT_DELAY: "Exit Delay",
    simplipy.system.SystemStates.HOME: "Home",
    simplipy.system.SystemStates.HOME_COUNT: "Home Count",
    simplipy.system.SystemStates.OFF: "Off",
    simplipy.system.SystemStates.TEST: "Test",
    simplipy.system.SystemStates.UNKNOWN: "Unknown",
}

device_type_strings = {
    simplipy.system.DeviceTypes.PANIC_BUTTON: "Panic Button",
    simplipy.system.DeviceTypes.MOTION: "Motion Sensor",
    simplipy.system.DeviceTypes.ENTRY: "Entry Sensor",
    simplipy.system.DeviceTypes.GLASS_BREAK: "Glass Break Sensor",
    simplipy.system.DeviceTypes.CARBON_MONOXIDE: "Carbon Monoxide Sensor",
    simplipy.system.DeviceTypes.SMOKE: "Smoke Detector",
    simplipy.system.DeviceTypes.LEAK: "Leak Detector",
    simplipy.system.DeviceTypes.REMOTE: "Remote",
    simplipy.system.DeviceTypes.KEYPAD: "Keypad",
    simplipy.system.DeviceTypes.KEYCHAIN: "Keychain",
    simplipy.system.DeviceTypes.TEMPERATURE: "Temperature Sensor",
    simplipy.system.DeviceTypes.CAMERA: "Camera",
    simplipy.system.DeviceTypes.SIREN: "Siren",
    simplipy.system.DeviceTypes.DOORBELL: "Doorbell",
    simplipy.system.DeviceTypes.LOCK: "Lock",
    simplipy.system.DeviceTypes.OUTDOOR_CAMERA: "Outdoor Camera",
    simplipy.system.DeviceTypes.LOCK_KEYPAD: "Lock Keypad",
    simplipy.system.DeviceTypes.UNKNOWN: "Unknown Device",
}

TOKEN_REFRESH_TIMER = 30 * 60.0  # 30 minutes

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
        self.triggers = []
        self._event_loop = None
        self._async_thread = None
        self._api = None
        self._session = None
        self.sms_code = None
        self.known_systems = {}
        self.known_sensors = {}
        self.active_systems = {}
        self.active_sensors = {}

        self._token_refresh_task: asyncio.Task | None = None
        self._websocket_reconnect_task: asyncio.Task | None = None
        self.systems: dict[int, SystemType] = {}

        self.update_needed = False
        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "15")) * 60.0
        self.logger.debug(f"updateFrequency = {self.updateFrequency}")
        self.next_update = time.time() + self.updateFrequency

    def validatePrefsConfigUi(self, valuesDict):
        self.logger.threaddebug(f"validatePrefsConfigUi, valuesDict = {valuesDict}")
        errorDict = indigo.Dict()
        valuesDict['auth_code'] = ""
        username = valuesDict.get('username', None)
        if not username or not len(username):
            errorDict['username'] = "Username is required"
        password = valuesDict.get('password', None)
        if not password or not len(password):
            errorDict['password'] = "Password is required"
        if len(errorDict) > 0:
            return False, valuesDict, errorDict
        return True, valuesDict

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        self.logger.threaddebug(f"closedPrefsConfigUi, valuesDict = {valuesDict}")
        if not userCancelled:
            self.logLevel = int(valuesDict.get("logLevel", logging.INFO))
            self.indigo_log_handler.setLevel(self.logLevel)
            self.plugin_file_handler.setLevel(self.logLevel)
            self.logger.debug(f"LogLevel = {self.logLevel}")

    def startup(self):
        self.logger.debug("startup")
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._async_thread = threading.Thread(target=self._run_async_thread)
        self._async_thread.start()
        self.logger.debug("startup complete")

    def _run_async_thread(self):
        self.logger.debug("_run_async_thread starting")
        self._event_loop.run_until_complete(self._async_main())
        self._event_loop.close()
        self.logger.debug("_run_async_thread ending")

    def request_auth(self, valuesDict, typeId):
        self.logger.threaddebug(f"request_auth typeId = {typeId}, valuesDict = {valuesDict}")
        self._event_loop.create_task(self._authenticate_with_credentials())
        return valuesDict

    def verify_sms(self, valuesDict, typeId):
        self.logger.threaddebug(f"verify_sms typeId = {typeId}, valuesDict = {valuesDict}")
        self.sms_code = valuesDict['auth_code']
        valuesDict['auth_code'] = ""  # clear the code
        self._event_loop.create_task(self._auth_verify_sms())
        return valuesDict

    def print_pins(self, valuesDict, typeId):
        self.logger.threaddebug(f"print_pins typeId = {typeId}, valuesDict = {valuesDict}")
        device = indigo.devices[int(valuesDict['system'])]
        system = self.known_systems[int(device.address)]
        self._event_loop.create_task(self._async_print_pins(system))
        return valuesDict

    async def _async_print_pins(self, system):
        self.logger.debug("_async_print_pins starting")
        try:
            pins = await system.async_get_pins(cached=False)
            self.logger.debug(f"_async_print_pins pins = {pins}")

            for k, v in pins.items():
                self.logger.info(f"{k}: {v}")
        except Exception as e:
            self.logger.error(f"_async_print_pins error: {e}")

    # Use refresh token to authenticate with SimpliSafe
    async def _authenticate_with_token(self):
        token = self.pluginPrefs.get("refresh_token", None)
        self.logger.debug(f"_authenticate with token '{token}'")
        if token:
            try:
                self._api = await API.async_from_refresh_token(token, session=self._session)
            except InvalidCredentialsError as err:
                self.logger.warning(f"_authenticate: Error refreshing auth token: {err}")
            except Exception as err:
                self.logger.warning(f"_authenticate: Error refreshing auth token: {err}")

        if not self._api or self._api.auth_state != simplipy.api.AuthStates.AUTHENTICATED:
            # no token or refresh did not work, remind user to start the auth flow
            self.logger.warning("SimpliSafe plugin not authenticated - use plugin menu Authenticate...")

    # Use username and password to authenticate with SimpliSafe
    async def _authenticate_with_credentials(self):
        self.logger.debug(f"_authenticate_with_credentials")
        try:
            self._api = await API.async_from_credentials(self.pluginPrefs.get("username"), self.pluginPrefs.get("password"), session=self._session)
        except InvalidCredentialsError as err:
            self.logger.warning(f"Error requesting auth from credentials: {err}")
        except Exception as err:
            self.logger.warning(f"Error requesting auth from credentials: {err}")

        self.logger.debug(f"async_from_credentials Auth State: {self._api.auth_state}")

        if self._api and self._api.auth_state == simplipy.api.AuthStates.PENDING_2FA_SMS:
            self.logger.warning("SimpliSafe authentication in progress - enter SMS code in plugin menu Authenticate...")

        elif self._api and self._api.auth_state == simplipy.api.AuthStates.PENDING_2FA_EMAIL:
            self.logger.warning("SimpliSafe authentication in progress - verify 2FA email")
            self._event_loop.create_task(self._auth_verify_email())

    # wait for Event from Config dialog to verify SMS code
    async def _auth_verify_sms(self):
        self.logger.debug(f"_auth_verify_sms, code = {self.sms_code}")
        try:
            await self._api.async_verify_2fa_sms(self.sms_code)
        except InvalidCredentialsError as err:
            self.logger.error("Invalid SMS 2FA code")

        if not self._api or self._api.auth_state != simplipy.api.AuthStates.AUTHENTICATED:
            self.logger.warning("SimpliSafe authentication failed - use plugin menu Authenticate...")

    # wait for user to validate 2FA email
    async def _auth_verify_email(self):
        self.logger.debug(f"_auth_verify_email")
        await asyncio.sleep(3.0)
        try:
            await self._api.async_verify_2fa_email()
        except Verify2FAPending as err:
            self.logger.warning(f"Verify 2FA email error: {err}")
            self.logger.warning("SimpliSafe authentication failed - use plugin menu Authenticate...")

        if not self._api or self._api.auth_state != simplipy.api.AuthStates.AUTHENTICATED:
            # timed out, or verify failed, do it again
            self._event_loop.create_task(self._auth_verify_email())

    async def _async_main(self):
        self.logger.debug("async_main starting")

        """Create the aiohttp session and run."""
        async with ClientSession() as self._session:

            # Authentication Flow
            await self._authenticate_with_token()
            while not self._api or self._api.auth_state != simplipy.api.AuthStates.AUTHENTICATED:
                await asyncio.sleep(1.0)

            # Authentication complete
            self.logger.debug(f"new refresh_token = {self._api.refresh_token}")
            self.pluginPrefs["refresh_token"] = self._api.refresh_token
            indigo.server.savePluginPrefs()

            self._websocket_reconnect_task = asyncio.create_task(self._async_start_websocket_loop())
            self._api.websocket.add_event_callback(self.event_handler)
            self._token_refresh_task = asyncio.create_task(self._async_token_refresh_loop())

            self.systems = await self._api.async_get_systems()

            for system in self.systems.values():
                self.known_systems[system.system_id] = system
                self.known_sensors[system.system_id] = {}
                for sensor in system.sensors.values():
                    self.known_sensors[system.system_id][sensor.serial] = sensor

            self.logger.threaddebug(f"known_systems: {self.known_systems}")
            self.logger.threaddebug(f"known_sensors: {self.known_sensors}")
            self.logger.threaddebug(f"active_systems: {self.active_systems}")
            self.logger.threaddebug(f"active_sensors: {self.active_sensors}")

            while True:
                if (time.time() > self.next_update) or self.update_needed:
                    self.update_needed = False
                    self.next_update = time.time() + self.updateFrequency
                    for device_id in self.active_systems:
                        device = indigo.devices[device_id]
                        self.update_system_device(device)
                    for device_id in self.active_sensors:
                        device = indigo.devices[device_id]
                        self.update_sensor_device(device)

                await asyncio.sleep(1.0)
                if self.stopThread:
                    self.logger.debug("_async_main: stopping")
                    await _async_cancel_websocket_loop(self._websocket_reconnect_task)
                    await self._token_refresh_task.cancel()
                    break

    def event_handler(self, event):
        self.logger.debug(f"Received a SimpliSafe™ event:")
        self.logger.debug(f"event.info:          {event.info}")
        self.logger.debug(f"event.system_id:     {event.system_id}")
        self.logger.debug(f"event.timestamp:     {event.timestamp}")
        self.logger.debug(f"event.event_type:    {event.event_type}")
        self.logger.debug(f"event.changed_by:    {event.changed_by}")
        self.logger.debug(f"event.sensor_name:   {event.sensor_name}")
        self.logger.debug(f"event.sensor_serial: {event.sensor_serial}")
        self.logger.debug(f"event.sensor_type:   {event.sensor_type}")
        self.triggerCheck(event)

    ##################
    # Device Methods
    ##################

    def getDeviceConfigUiValues(self, pluginProps, typeId, devId):
        self.logger.threaddebug(f"getDeviceConfigUiValues, typeId = {typeId}, pluginProps = {pluginProps}")
        valuesDict = indigo.Dict(pluginProps)
        errorsDict = indigo.Dict()
        return valuesDict, errorsDict

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.logger.threaddebug(f"validateDeviceConfigUi, typeId = {typeId}, valuesDict = {valuesDict}")
        errorsDict = indigo.Dict()
        if len(errorsDict) > 0:
            return False, valuesDict, errorsDict
        return True, valuesDict

    def deviceStartComm(self, device):
        self.logger.debug(f"{device.name}: Starting Device")
        if device.deviceTypeId == "system":
            self.active_systems[device.id] = device.name
        elif device.deviceTypeId == "simple_sensor":
            self.active_sensors[device.id] = device.name
        self.update_needed = True
        device.stateListOrDisplayStateIdChanged()

    def deviceStopComm(self, device):
        self.logger.debug(f"{device.name}: Stopping Device")
        if device.deviceTypeId == "system":
            del self.active_systems[device.id]
        elif device.deviceTypeId == "sensor":
            del self.active_sensors[device.id]

    def didDeviceCommPropertyChange(self, origDev, newDev):  # noqa
        self.logger.threaddebug(f"{origDev.name}: didDeviceCommPropertyChange")
        return False

    def update_system_device(self, device):
        system = self.known_systems[int(device.address)]
        self.logger.debug(f"{device.name}: doing update for {system.address}")
        update_list = [
            {'key': "system_address", 'value': system.address},
            {'key': "connection_type", 'value': system.connection_type},
            {'key': "system_serial", 'value': system.serial},
            {'key': "system_id", 'value': system.system_id},
            {'key': "system_version", 'value': system.version},
            {'key': "system_state", 'value': state_strings[system.state]},
            {'key': "system_temperature", 'value': system.temperature}
        ]
        if system.version == 3:
            update_list.append({'key': "alarm_duration", 'value': system.alarm_duration})
            update_list.append({'key': "battery_backup_power_level", 'value': system.battery_backup_power_level})
            update_list.append({'key': "wall_power_level", 'value': system.wall_power_level})
            update_list.append({'key': "entry_delay_away", 'value': system.entry_delay_away})
            update_list.append({'key': "entry_delay_home", 'value': system.entry_delay_home})
            update_list.append({'key': "exit_delay_away", 'value': system.exit_delay_away})
            update_list.append({'key': "exit_delay_home", 'value': system.exit_delay_home})
            update_list.append({'key': "gsm_strength", 'value': system.gsm_strength})
            update_list.append({'key': "wifi_strength", 'value': system.wifi_strength})
            update_list.append({'key': "light", 'value': system.light})
            update_list.append({'key': "power_outage", 'value': system.power_outage})
            update_list.append({'key': "offline", 'value': system.offline})
            update_list.append({'key': "wifi_ssid", 'value': system.wifi_ssid})
        device.updateStatesOnServer(update_list)

    def update_sensor_device(self, device):
        system = self.known_systems[int(device.pluginProps["system"])]
        sensor = self.known_sensors[system.system_id][device.address]
        self.logger.debug(f"{device.name}: doing update for {sensor.serial}")
        update_list = [
            {'key': "name", 'value': sensor.name},
            {'key': "serial", 'value': sensor.serial},
            {'key': "type", 'value': device_type_strings[sensor.type]},
        ]
        if system.version == 3:
            update_list.append({'key': "error", 'value': sensor.error})
            update_list.append({'key': "low_battery", 'value': sensor.low_battery})
            update_list.append({'key': "offline", 'value': sensor.offline})
            update_list.append({'key': "triggered", 'value': sensor.triggered})
            update_list.append({'key': "trigger_instantly", 'value': sensor.trigger_instantly})
        device.updateStatesOnServer(update_list)

    def getDeviceStateList(self, device):
        self.logger.debug(f"{device.name}: getDeviceStateList")
        stateList = indigo.PluginBase.getDeviceStateList(self, device)
        return stateList

    ########################################
    # Trigger (Event) handling
    ########################################

    def triggerStartProcessing(self, trigger):
        self.logger.debug(f"{trigger.name}: Adding Trigger")
        assert trigger not in self.triggers
        self.triggers.append(trigger)

    def triggerStopProcessing(self, trigger):
        self.logger.debug(f"{trigger.name}: Removing Trigger")
        assert trigger in self.triggers
        self.triggers.remove(trigger)

    def triggerCheck(self, event):
        self.logger.debug(f"triggerCheck:  system = {event.system_id}, type = {event.event_type}")
        for trigger in self.triggers:
            self.logger.debug(f"Checking Trigger {trigger.name}")
            if trigger.pluginProps['system'] == event.system_id:
                indigo.trigger.execute(trigger)

    ########################################
    # callbacks from device creation UI
    ########################################

    def get_system_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_system_list: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        systems = [
            (system.system_id, system.address)
            for system in self.known_systems.values()
        ]
        self.logger.debug(f"get_system_list: systems = {systems}")
        return systems

    def get_sensor_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_sensor_list: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        try:
            sensors = []
            for sensor in self.known_sensors[int(valuesDict["system"])].values():
                if sensor.type in device_type_strings:
                    sensors.append((sensor.serial, f"{sensor.name} - {device_type_strings[sensor.type]}"))
        except KeyError:
            sensors = []
        self.logger.debug(f"get_sensor_list: sensors = {sensors}")
        return sensors

    # doesn't do anything, just needed to force other menus to dynamically refresh
    def menuChanged(self, valuesDict=None, typeId=None, devId=None):  # noqa
        self.logger.threaddebug(f"menuChanged: typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        return valuesDict

    ########################################
    # Action handling
    ########################################

    def actionSetMode(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"actionSetMode: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        mode = action.props.get("mode", None)
        if mode not in ['away', 'home', 'off']:
            self.logger.error(f"actionSetMode: Invalid mode '{mode}'")
            return
        system = self.known_systems[int(device.address)]
        self._event_loop.create_task(self._async_set_mode(system, mode))

    async def _async_set_mode(self, system, mode):
        if mode == 'off':
            await system.async_set_off()
        elif mode == 'away':
            await system.async_set_away()
        elif mode == 'home':
            await system.async_set_home()
        else:
            self.logger.error(f"_async_set_mode: Invalid mode '{mode}'")

    def actionSetPIN(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"actionSetMode: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        label = action.props.get("label", None)
        pin = action.props.get("pin", None)
        if not label or len(label) == 0 or not pin or len(pin) == 0:
            self.logger.error(f"actionSetPIN: Invalid label or pin")
            return
        system = self.known_systems[int(device.address)]
#        self._event_loop.create_task(system.async_set_pin(label, pin))
        self._event_loop.create_task(self._async_set_pin(system, label, pin))

    async def _async_set_pin(self, system, label, pin):
        self.logger.threaddebug(f"_async_set_pin: system = {system.system_id}, label = {label}, pin = {pin}")
        try:
            await system.async_set_pin(label, pin)
        except Exception as e:
            self.logger.error(f"_set_pin: {e}")

    def actionRemovePIN(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"actionSetMode: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        label = action.props.get("label", None)
        if not label or len(label) == 0:
            self.logger.error(f"actionRemovePIN: Invalid label")
            return
        system = self.known_systems[int(device.address)]
        self._event_loop.create_task(system.async_remove_pin(label))

    ########################################
    # Recurring tasks
    ########################################

    async def _async_start_websocket_loop(self) -> None:
        """Start a websocket reconnection loop."""
        self.logger.threaddebug("_async_start_websocket_loop: starting")
        assert self._api.websocket
        try:
            await self._api.websocket.async_connect()
            await self._api.websocket.async_listen()
        except asyncio.CancelledError as err:
            self.logger.debug("_async_start_websocket_loop: cancelled")
            raise
        except WebsocketError as err:
            self.logger.error(f"_async_start_websocket_loop: WebsocketError: {err}")
        except Exception as err:  # pylint: disable=broad-except
            self.logger.error(f"_async_start_websocket_loop: Exception: {err}")

        await self._async_cancel_websocket_loop()
        self._websocket_reconnect_task = asyncio.create_task(self._async_start_websocket_loop())

    async def _async_cancel_websocket_loop(self) -> None:
        """Stop any existing websocket reconnection loop."""
        self.logger.threaddebug("_async_cancel_websocket_loop: starting")
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
        self.logger.threaddebug("_async_cancel_websocket_loop: exiting")

    async def _async_token_refresh_loop(self) -> None:
        try:
            while True:
                self.logger.debug(f"do_token_refresh: starting timer for {TOKEN_REFRESH_TIMER} seconds")
                await asyncio.sleep(TOKEN_REFRESH_TIMER)
                try:
                    await self.api.async_refresh_access_token()
                except AttributeError:
                    await self._api._async_refresh_access_token() # noqa
                self.logger.debug(f"do_token_refresh: New Refresh Token = {self._api.refresh_token}")
                self.pluginPrefs["refresh_token"] = self._api.refresh_token
                indigo.server.savePluginPrefs()
        except asyncio.CancelledError:
            self.logger.debug("do_token_refresh: cancelled")
            raise


