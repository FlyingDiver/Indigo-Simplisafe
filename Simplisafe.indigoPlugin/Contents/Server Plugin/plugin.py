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
import simplipy.device

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

class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.logLevel = int(pluginPrefs.get("logLevel", logging.INFO))
        self.logger.debug(f"LogLevel = {self.logLevel}")
        self.indigo_log_handler.setLevel(self.logLevel)
        self.plugin_file_handler.setLevel(self.logLevel)

        self.pluginPrefs = pluginPrefs
        self.triggers = []
        self.event_loop = None
        self.async_thread = None
        self.simplisafe = None
        self.session = None
        self.sms_code = None
        self.known_systems = {}
        self.known_sensors = {}
        self.known_cameras = {}
        self.known_locks = {}

        self.active_systems = {}
        self.active_sensors = {}
        self.active_cameras = {}
        self.active_locks = {}

        self.system_refresh_task: asyncio.Task | None = None
        self.websocket_reconnect_task: asyncio.Task | None = None
        self.systems: dict[int, SystemType] = {}

        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "15")) * 60.0
        self.logger.debug(f"updateFrequency = {self.updateFrequency}")

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
        update = valuesDict.get('updateFrequency', None)
        if not update or float(update) < 5.0:
            errorDict['updateFrequency'] = "Update frequency must be at least 5 minutes"
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
            self.updateFrequency = float(valuesDict.get('updateFrequency', "15")) * 60.0
            self.logger.debug(f"updateFrequency = {self.updateFrequency}")

    def startup(self):
        self.logger.debug("startup")
        self.async_thread = threading.Thread(target=self.run_async_thread)
        self.async_thread.start()
        self.logger.debug("startup complete")

    def run_async_thread(self):
        self.logger.debug("run_async_thread starting")
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self.event_loop.run_until_complete(self.async_main())
        self.event_loop.close()
        self.logger.debug("run_async_thread ending")

    def request_auth(self, valuesDict, typeId):
        self.logger.threaddebug(f"request_auth typeId = {typeId}, valuesDict = {valuesDict}")
        self.event_loop.create_task(self.authenticate_with_credentials())
        return valuesDict

    def verify_sms(self, valuesDict, typeId):
        self.logger.threaddebug(f"verify_sms typeId = {typeId}, valuesDict = {valuesDict}")
        self.sms_code = valuesDict['auth_code']
        valuesDict['auth_code'] = ""  # clear the code
        self.event_loop.create_task(self.auth_verify_sms())
        return valuesDict

    async def authenticate_with_token(self):
        token = self.pluginPrefs.get("refresh_token", None)
        self.logger.debug(f"authenticate_with_token, old token: '{token}'")
        if token:
            try:
                self.simplisafe = await API.async_from_refresh_token(token, session=self.session)
            except InvalidCredentialsError as err:
                self.logger.warning(f"authenticate_with_token: Error refreshing auth token: {err}")
            except Exception as err:
                self.logger.warning(f"authenticate_with_token: Error refreshing auth token: {err}")

        if self.simplisafe and self.simplisafe.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
            await self.async_save_refresh_token(self.simplisafe.refresh_token)
        else:
            self.logger.warning("SimpliSafe plugin not authenticated - use plugin menu Authenticate...")

    async def authenticate_with_credentials(self):
        self.logger.debug(f"authenticate_with_credentials")
        try:
            self.simplisafe = await API.async_from_credentials(self.pluginPrefs.get("username"), self.pluginPrefs.get("password"), session=self.session)
        except InvalidCredentialsError as err:
            self.logger.warning(f"authenticate_with_credentials: Error requesting auth from credentials: {err}")
        except Exception as err:
            self.logger.warning(f"authenticate_with_credentials: Error requesting auth from credentials: {err}")

        if self.simplisafe and self.simplisafe.auth_state == simplipy.api.AuthStates.AUTHENTICATED:     # not sure this case is possible
            await self.async_save_refresh_token(self.simplisafe.refresh_token)

        elif self.simplisafe and self.simplisafe.auth_state == simplipy.api.AuthStates.PENDING_2FA_SMS:
            self.logger.warning("SimpliSafe authentication in progress - enter SMS code in plugin menu Authenticate...")

        elif self.simplisafe and self.simplisafe.auth_state == simplipy.api.AuthStates.PENDING_2FA_EMAIL:
            self.logger.warning("SimpliSafe authentication in progress - verify 2FA email")
            self.event_loop.create_task(self.auth_verify_email())

    # action from Config dialog to verify SMS code
    async def auth_verify_sms(self):
        self.logger.debug(f"auth_verify_sms, code = {self.sms_code}")
        try:
            await self.simplisafe.async_verify_2fa_sms(self.sms_code)
        except InvalidCredentialsError as err:
            self.logger.warning("SimpliSafe SMS verification failed - Invalid SMS code")

        if self.simplisafe and self.simplisafe.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
            await self.async_save_refresh_token(self.simplisafe.refresh_token)
        else:
            self.logger.warning("SimpliSafe SMS verification failed - use plugin menu Authenticate...")

    # wait for user to validate 2FA email
    async def auth_verify_email(self):
        self.logger.debug(f"auth_verify_email")
        await asyncio.sleep(3.0)
        try:
            await self.simplisafe.async_verify_2fa_email()
        except Verify2FAPending as err:
            self.logger.warning(f"SimpliSafe Verify 2FA email error: {err}")
            self.logger.warning("SimpliSafe authentication failed - use plugin menu Authenticate...")

        if self.simplisafe and self.simplisafe.auth_state == simplipy.api.AuthStates.AUTHENTICATED:
            await self.async_save_refresh_token(self.simplisafe.refresh_token)
        else:
            self.event_loop.create_task(self.auth_verify_email())

    ##############################################################################################

    async def async_main(self):
        self.logger.debug("async_main starting")

        """Create the aiohttp session and run."""
        async with ClientSession() as self.session:

            await self.authenticate_with_token()
            while not self.simplisafe or self.simplisafe.auth_state != simplipy.api.AuthStates.AUTHENTICATED:
                await asyncio.sleep(1.0)
            logging.getLogger("simplipi").setLevel(self.logLevel)
            self.logger.info(f"SimpliSafe authentication successful")

            self.simplisafe.add_refresh_token_callback(self.async_handle_refresh_token)
            self.simplisafe.websocket.add_event_callback(self.event_handler)
            self.websocket_reconnect_task = asyncio.create_task(self.async_start_websocket_loop())
            self.system_refresh_task = asyncio.create_task(self.async_system_refresh_loop())

            while True:
                await asyncio.sleep(1.0)
                if self.stopThread:
                    self.logger.debug("async_main: stopping")
                    await _async_cancel_websocket_loop(self.websocket_reconnect_task)
                    break

    def event_handler(self, event):
        self.logger.debug(f"Received a SimpliSafe event:")
        self.logger.debug(f"event.info:          {event.info}")
        self.logger.debug(f"event.system_id:     {event.system_id}")
        self.logger.debug(f"event.event_type:    {event.event_type}")
        self.logger.debug(f"event.changed_by:    {event.changed_by}")
        self.logger.debug(f"event.sensor_name:   {event.sensor_name}")
        self.logger.debug(f"event.sensor_serial: {event.sensor_serial}")
        self.logger.debug(f"event.sensor_type:   {event.sensor_type}")
        self.logger.debug(f"event.timestamp:     {event.timestamp}")

        for device in indigo.devices.iter("self.system"):
            if str(device.address) == str(event.system_id):
                self.logger.debug(f"event_handler doing update for {device.name} ({event.system_id})")
                update_list = [
                    {'key': "last_event_info", 'value': event.info},
                    {'key': "last_event_type", 'value': event.event_type},
                    {'key': "last_event_changed_by", 'value': event.changed_by},
                    {'key': "last_event_sensor_name", 'value': event.sensor_name},
                    {'key': "last_event_sensor_serial", 'value': event.sensor_serial},
                    {'key': "last_event_sensor_type", 'value': str(event.sensor_type)},
                    {'key': "last_event_timestamp", 'value': str(event.timestamp)},
                ]
                try:
                    device.updateStatesOnServer(update_list)
                except Exception as e:
                    self.logger.error(f"{device.name}: failed to update states: {e}")
                break
        self.triggerCheck(event)
        asyncio.create_task(self.async_system_refresh())

    ##################
    # Device Methods
    ##################

    def getDeviceConfigUiValues(self, pluginProps, typeId, devId):
        self.logger.threaddebug(f"getDeviceConfigUiValues, typeId = {typeId}, devId = {devId}, pluginProps = {pluginProps}")
        valuesDict = indigo.Dict(pluginProps)
        errorsDict = indigo.Dict()

        if typeId != "system" and len(self.known_systems) > 0:
            valuesDict["system"] = list(self.known_systems.keys())[0]

        return valuesDict, errorsDict

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.logger.threaddebug(f"validateDeviceConfigUi, typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        errorsDict = indigo.Dict()
        if typeId == "sensor":
            system = self.known_systems[int(valuesDict["system"])]
            sensor = self.known_sensors[system.system_id][valuesDict["address"]]
            self.logger.threaddebug(f"validateDeviceConfigUi, sensor.name = {sensor.name}, sensor.type = {sensor.type}")
            if sensor.type == simplipy.device.DeviceTypes.TEMPERATURE:
                valuesDict["SupportsSensorValue"] = True
        if len(errorsDict) > 0:
            return False, valuesDict, errorsDict
        return True, valuesDict

    def deviceStartComm(self, device):
        self.logger.debug(f"{device.name}: Starting Device")
        if device.deviceTypeId == "system":
            self.active_systems[device.id] = device.name
            self.update_system_device(device)
        elif device.deviceTypeId == "sensor":
            self.active_sensors[device.id] = device.name
            self.update_sensor_device(device)
        elif device.deviceTypeId == "camera":
            self.active_cameras[device.id] = device.name
            self.update_camera_device(device)
        elif device.deviceTypeId == "lock":
            self.active_locks[device.id] = device.name
            self.update_lock_device(device)
        device.stateListOrDisplayStateIdChanged()

    def deviceStopComm(self, device):
        self.logger.debug(f"{device.name}: Stopping Device")
        if device.deviceTypeId == "system":
            del self.active_systems[device.id]
        elif device.deviceTypeId == "sensor":
            del self.active_sensors[device.id]
        elif device.deviceTypeId == "camera":
            del self.active_cameras[device.id]
        elif device.deviceTypeId == "lock":
            del self.active_locks[device.id]

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

    def triggerCheck(self, event):
        for trigger_id in self.triggers:
            trigger = indigo.triggers[trigger_id]
            device = indigo.devices[int(trigger.pluginProps['system'])]
            self.logger.debug(f"{trigger.name}: triggerCheck system = {device.address}, event_type = {trigger.pluginProps['event_type']}")
            if str(device.address) == str(event.system_id) and str(trigger.pluginProps['event_type']) == str(event.event_type):
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

    def get_device_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_device_list: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        try:
            devices = []
            system_id = int(valuesDict["system"])
            if filter == "camera":
                devices = [
                    (device_id, device.name)
                    for device_id, device in self.known_cameras[system_id].items()
                ]
            elif filter == "lock":
                devices = [
                    (device_id, device.name)
                    for device_id, device in self.known_locks[system_id].items()
                ]
            elif filter == "sensor":
                devices = [
                    (device_id, f"{device.name} - {str(device.type)}")
                    for device_id, device in self.known_sensors[system_id].items()
                ]
            else:
                self.logger.debug(f"get_device_list: unknown filter = {filter}")

        except KeyError:
            devices = []
        self.logger.debug(f"get_device_list: devices = {devices}")
        return devices

    # doesn't do anything, just needed to force other menus to dynamically refresh
    def menuChanged(self, valuesDict=None, typeId=None, devId=None):  # noqa
        self.logger.threaddebug(f"menuChanged: typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        return valuesDict

    ########################################
    # Menu and Action methods
    ########################################

    def actionControlDevice(self, action, device):
        ss_system = self.known_systems[int(device.address)]
        ss_device = ss_system.locks[int(device.device_serial)]

        if action.deviceAction == indigo.kDeviceAction.TurnOn:
            return

        elif action.deviceAction == indigo.kDeviceAction.TurnOff:
            return

    def print_pins(self, valuesDict, typeId):
        self.logger.threaddebug(f"print_pins typeId = {typeId}, valuesDict = {valuesDict}")
        device = indigo.devices[int(valuesDict['system'])]
        system = self.known_systems[int(device.address)]
        self.event_loop.create_task(self.async_print_pins(system))
        return valuesDict

    async def async_print_pins(self, system):
        self.logger.debug("async_print_pins starting")
        try:
            pins = await system.async_get_pins(cached=False)
            for k, v in pins.items():
                self.logger.info(f"{k}: {v}")
        except Exception as e:
            self.logger.error(f"async_print_pins error: {e}")

    def action_set_mode(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"action_set_mode: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        mode = action.props.get("mode", None)
        if mode not in ['away', 'home', 'off']:
            self.logger.error(f"action_set_mode: Invalid mode '{mode}'")
            return
        system = self.known_systems[int(device.address)]
        self.event_loop.create_task(self.async_set_mode(system, mode))

    async def async_set_mode(self, system, mode):
        if mode == 'off':
            await system.async_set_off()
        elif mode == 'away':
            await system.async_set_away()
        elif mode == 'home':
            await system.async_set_home()
        else:
            self.logger.error(f"async_set_mode: Invalid mode '{mode}'")

    def action_set_pin(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"action_set_pin: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        label = action.props.get("label", None)
        pin = action.props.get("pin", None)
        if not label or len(label) == 0 or not pin or len(pin) == 0:
            self.logger.error(f"action_set_pin: Invalid label or pin")
            return
        system = self.known_systems[int(device.address)]
        self.event_loop.create_task(self.async_set_pin(system, label, pin))

    async def async_set_pin(self, system, label, pin):
        self.logger.threaddebug(f"async_set_pin: system = {system.system_id}, label = {label}, pin = {pin}")
        try:
            await system.async_set_pin(label, pin)
        except Exception as e:
            self.logger.error(f"_set_pin: {e}")

    def action_remove_pin(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"action_remove_pin: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        label = action.props.get("label", None)
        if not label or len(label) == 0:
            self.logger.error(f"action_remove_pin: Invalid label")
            return
        system = self.known_systems[int(device.address)]
        self.event_loop.create_task(system.async_remove_pin(label))

    ########################################
    # Recurring tasks
    ########################################

    async def async_start_websocket_loop(self) -> None:
        """Start a websocket reconnection loop."""
        self.logger.threaddebug("async_start_websocket_loop: starting")
        assert self.simplisafe.websocket
        try:
            await self.simplisafe.websocket.async_connect()
            await self.simplisafe.websocket.async_listen()
            self.logger.threaddebug("async_start_websocket_loop: async_listen() returned")
        except asyncio.CancelledError as err:
            self.logger.debug("async_start_websocket_loop: cancelled")
            raise
        except WebsocketError as err:
            self.logger.error(f"async_start_websocket_loop: WebsocketError: {err}")
        except Exception as err:  # pylint: disable=broad-except
            self.logger.error(f"async_start_websocket_loop: Exception: {err}")

        await self.async_cancel_websocket_loop()
        self.websocket_reconnect_task = asyncio.create_task(self.async_start_websocket_loop())

    async def async_cancel_websocket_loop(self) -> None:
        """Stop any existing websocket reconnection loop."""
        self.logger.threaddebug("async_cancel_websocket_loop: starting")
        if self.websocket_reconnect_task:
            self.websocket_reconnect_task.cancel()
            try:
                await self.websocket_reconnect_task
            except asyncio.CancelledError as err:
                self.websocket_reconnect_task = None
            except Exception as err:  # pylint: disable=broad-except
                self.logger.error(f"async_cancel_websocket_loop: Exception: {err}")

            assert self.simplisafe.websocket
            await self.simplisafe.websocket.async_disconnect()
        self.logger.threaddebug("async_cancel_websocket_loop: exiting")

    async def async_handle_refresh_token(self, token: str) -> None:
        """Handle a new refresh token."""
        self.logger.debug(f"async_handle_refresh_token: token = {token}")
        await self.async_save_refresh_token(token)

        assert self.simplisafe.websocket
        await self.async_cancel_websocket_loop()
        self.websocket_reconnect_task = asyncio.create_task(self.async_start_websocket_loop())

    async def async_save_refresh_token(self, token: str) -> None:
        self.logger.debug(f"async_save_refresh_token: {token}")
        self.pluginPrefs["refresh_token"] = token
        indigo.server.savePluginPrefs()

    async def async_system_refresh_loop(self) -> None:
        self.logger.debug("async_system_refresh_loop: starting")
        try:
            while True:
                await self.async_system_refresh()
                self.logger.debug(f"async_system_refresh_loop: starting timer for {self.updateFrequency} seconds")
                await asyncio.sleep(self.updateFrequency)

        except asyncio.CancelledError:
            self.logger.debug("async_system_refresh_loop: cancelled")
            raise

    # update from the cloud
    async def async_system_refresh(self) -> None:
        self.logger.debug(f"async_system_refresh")

        self.systems = await self.simplisafe.async_get_systems()

        for system_id, system in self.systems.items():
            if system.version < 3:
                self.logger.warning(f"Unsupported V2 system: {system.address}, {system.system_id}, {system.serial}")
            else:
                self.known_systems[system_id] = system
                self.known_sensors[system_id] = {}
                for sensor_id, sensor in system.sensors.items():
                    if sensor.__class__ == simplipy.device.sensor.v3.SensorV3:
                        self.known_sensors[system_id][sensor_id] = sensor
                    else:
                        self.logger.warning(f"Unsupported device: {sensor.serial}, {sensor.type}, {sensor.__class__}")
                self.known_locks[system_id] = {}
                for lock_id, lock in system.locks.items():
                    self.known_locks[system_id][lock_id] = lock
                self.known_cameras[system_id] = {}
                for camera_id, camera in system.cameras.items():
                    self.logger.threaddebug(f"camera_id: {camera_id}, camera: {camera}")
                    self.known_cameras[system_id][camera_id] = camera

        self.logger.threaddebug(f"known_systems: {self.known_systems}")
        self.logger.threaddebug(f"known_sensors: {self.known_sensors}")
        self.logger.threaddebug(f"known_cameras: {self.known_cameras}")
        self.logger.threaddebug(f"known_locks:   {self.known_locks}")

        await self.async_device_refresh()

    # update the indigo devices
    async def async_device_refresh(self) -> None:
        self.logger.debug(f"async_device_refresh")

        self.logger.threaddebug(f"active_systems: {self.active_systems}")
        self.logger.threaddebug(f"active_sensors: {self.active_sensors}")
        self.logger.threaddebug(f"active_cameras: {self.active_cameras}")
        self.logger.threaddebug(f"active_locks:   {self.active_locks}")

        for device_id in self.active_systems:
            self.update_system_device(indigo.devices[device_id])
        for device_id in self.active_sensors:
            self.update_sensor_device(indigo.devices[device_id])
        for device_id in self.active_cameras:
            self.update_camera_device(indigo.devices[device_id])
        for device_id in self.active_locks:
            self.update_lock_device(indigo.devices[device_id])

    def update_system_device(self, device):
        try:
            system = self.known_systems[int(device.address)]
        except KeyError:
            return
        self.logger.debug(f"{device.name}: doing update for {system.address}")
        update_list = [
            {'key': "system_address", 'value': system.address},
            {'key': "connection_type", 'value': system.connection_type},
            {'key': "system_serial", 'value': system.serial},
            {'key': "system_id", 'value': system.system_id},
            {'key': "system_version", 'value': system.version},
            {'key': "system_state", 'value': str(system.state)},
            {'key': "system_temperature", 'value': system.temperature},
            {'key': "alarm_duration", 'value': system.alarm_duration},
            {'key': "battery_backup_power_level", 'value': system.battery_backup_power_level},
            {'key': "wall_power_level", 'value': system.wall_power_level},
            {'key': "entry_delay_away", 'value': system.entry_delay_away},
            {'key': "entry_delay_home", 'value': system.entry_delay_home},
            {'key': "exit_delay_away", 'value': system.exit_delay_away},
            {'key': "exit_delay_home", 'value': system.exit_delay_home},
            {'key': "gsm_strength", 'value': system.gsm_strength},
            {'key': "wifi_strength", 'value': system.wifi_strength},
            {'key': "light", 'value': system.light},
            {'key': "power_outage", 'value': system.power_outage},
            {'key': "offline", 'value': system.offline},
            {'key': "wifi_ssid", 'value': system.wifi_ssid},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

    def update_sensor_device(self, device):
        try:
            system = self.known_systems[int(device.pluginProps["system"])]
        except KeyError:
            return
        try:
            sensor = self.known_sensors[system.system_id][device.address]
        except KeyError:
            return

        self.logger.debug(f"{device.name}: doing update for {sensor.name} - {sensor.serial}  ({str(sensor.type)})")
        update_list = [
            {'key': "name", 'value': sensor.name},
            {'key': "serial", 'value': sensor.serial},
            {'key': "type", 'value': str(sensor.type)},
            {'key': "error", 'value': sensor.error},
            {'key': "low_battery", 'value': sensor.low_battery},
            {'key': "offline", 'value': sensor.offline},
            {'key': "triggered", 'value': sensor.triggered},
            {'key': "trigger_instantly", 'value': sensor.trigger_instantly},
            {'key': "onOffState", 'value': sensor.triggered},
        ]
        if sensor.type == simplipy.system.DeviceTypes.TEMPERATURE:
            update_list.append({'key': "sensorValue", 'value': sensor.temperature, 'uiValue': f"{int(sensor.temperature)}°F"})
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

    def update_camera_device(self, device):
        try:
            system = self.known_systems[int(device.pluginProps["system"])]
        except KeyError:
            return
        try:
            camera = self.known_cameras[system.system_id][device.address]
        except KeyError:
            return

        self.logger.debug(f"{device.name}: doing update for {camera.name} - {camera.serial} ({camera.camera_type})")
        update_list = [
            {'key': "name", 'value': camera.name},
            {'key': "serial", 'value': camera.serial},
            {'key': "camera_type", 'value': str(camera.camera_type)},
            {'key': "shutter_open_when_off", 'value': camera.shutter_open_when_off},
            {'key': "shutter_open_when_home", 'value': camera.shutter_open_when_home},
            {'key': "shutter_open_when_away", 'value': camera.shutter_open_when_away},
            {'key': "subscription_enabled", 'value': camera.subscription_enabled},
            {'key': "video_url", 'value': camera.video_url()},
            {'key': "status", 'value': camera.status},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

    def update_lock_device(self, device):
        try:
            system = self.known_systems[int(device.pluginProps["system"])]
        except KeyError:
            return
        try:
            lock = self.known_locks[system.system_id][device.address]
        except KeyError:
            return

        self.logger.debug(f"{device.name}: doing update for {lock.name} - {lock.serial}")
        update_list = [
            {'key': "name", 'value': lock.name},
            {'key': "serial", 'value': lock.serial},
            {'key': "state", 'value': lock.state},
            {'key': "error", 'value': lock.error},
            {'key': "low_battery", 'value': lock.low_battery},
            {'key': "offline", 'value': lock.offline},
            {'key': "lock_low_battery", 'value': lock.lock_low_battery},
            {'key': "pin_pad_low_battery", 'value': lock.pin_pad_low_battery},
            {'key': "pin_pad_offline", 'value': lock.pin_pad_offline},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")
