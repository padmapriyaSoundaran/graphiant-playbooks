"""
Device Lifecycle Manager for Graphiant Playbooks

This module provides functionality for managing device lifecycle states using
the /v1/devices/bringup API (PUT method).

Key Features:
- Change device lifecycle status (Pending/staging, Allowed/active, Denied, Removed, Maintenance)
- Support for config file input or direct device list
- Process multiple devices concurrently
"""

import json
import os
from typing import Dict, Any, Optional, List

try:
    from jinja2 import Template, TemplateError as Jinja2TemplateError
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False
    Template = None  # type: ignore

    class Jinja2TemplateError(Exception):
        """Placeholder for Jinja2 TemplateError when Jinja2 is not installed."""
        pass

from .base_manager import BaseManager
from .logger import setup_logger
from .exceptions import ConfigurationError, DeviceNotFoundError, APIError

LOG = setup_logger()


class DeviceLifecycleManager(BaseManager):
    """
    Manager for device lifecycle operations.

    This manager handles the following operations:
    - bringup_device: Change device lifecycle status (PUT /v1/devices/bringup)

    Configuration files support Jinja2 templating. The config file format (same as playbook input):

    devices:
      edge-1-sdktest:
        status: "Pending"  # or "staging", "active", "Allowed", etc.
      edge-2-sdktest:
        status: "active"
    """

    def configure(self, config_yaml_file: str) -> None:
        """Required by BaseManager abstract method - not used for device lifecycle."""
        pass

    def deconfigure(self, config_yaml_file: str) -> None:
        """Required by BaseManager abstract method - not used for device lifecycle."""
        pass

    def bringup_device(self, config_yaml_file: str = None, devices: Dict[str, Dict[str, Any]] = None) -> dict:
        """
        Change device lifecycle status using config file or direct device list.

        Args:
            config_yaml_file: Optional path to the YAML configuration file
            devices: Optional dictionary of devices with their target statuses
                    Format: {"device-name": {"status": "Pending"}, ...}

        Returns:
            dict: Result with 'changed' status and list of updated devices

        Raises:
            ConfigurationError: If configuration processing fails
            DeviceNotFoundError: If any device cannot be found
            APIError: If API call fails
        """
        result = {
            'changed': False,
            'updated_devices': [],
            'failed_devices': [],
            'skipped_devices': []
        }

        # Process devices from config file or direct input
        device_list = []
        if config_yaml_file:
            LOG.info("Processing device lifecycle from config file: %s", config_yaml_file)
            device_list = self._load_devices_from_config(config_yaml_file)
        elif devices:
            LOG.info("Processing device lifecycle from direct device list")
            device_list = self._load_devices_from_dict(devices)
        else:
            raise ConfigurationError("Either config_file or devices parameter must be provided")

        if not device_list:
            LOG.warning("No devices found in configuration")
            return result

        # Process each device
        for device_entry in device_list:
            device_name = device_entry.get('device_name')
            status = device_entry.get('status')

            if not device_name:
                LOG.warning("Skipping entry with missing device_name: %s", device_entry)
                result['skipped_devices'].append(device_entry)
                continue

            if not status:
                LOG.warning("Skipping device '%s' with missing status", device_name)
                result['skipped_devices'].append(device_name)
                continue

            try:
                # Get device ID
                device_id = self.gsdk.get_device_id(device_name)
                if device_id is None:
                    raise DeviceNotFoundError(
                        f"Device '{device_name}' is not found in the current enterprise: "
                        f"{self.gsdk.enterprise_info.get('company_name', 'Unknown')}. "
                        f"Please check device name and enterprise credentials."
                    )

                # Normalize status to user-friendly format (the SDK method handles conversion)
                # User inputs: "staging", "active", "maintenance", "deactivate", "decommission"
                # SDK converts: staging->Pending, active->Allowed, deactivate->Denied, decommission->Removed
                LOG.info("Updating device '%s' (ID: %s) to status: %s", device_name, device_id, status)
                success = self.gsdk.put_devices_bringup(device_ids=[device_id], status=status)

                if success:
                    result['updated_devices'].append({
                        'device_name': device_name,
                        'device_id': device_id,
                        'status': status
                    })
                    result['changed'] = True
                    LOG.info("✓ Successfully updated device '%s' to status: %s", device_name, status)
                else:
                    result['failed_devices'].append({
                        'device_name': device_name,
                        'device_id': device_id,
                        'status': status,
                        'error': 'API call returned False'
                    })
                    LOG.error("✗ Failed to update device '%s' to status: %s", device_name, status)

            except DeviceNotFoundError as e:
                result['failed_devices'].append({
                    'device_name': device_name,
                    'error': str(e)
                })
                LOG.error("✗ Device not found: %s", device_name)
            except Exception as e:
                result['failed_devices'].append({
                    'device_name': device_name,
                    'error': str(e)
                })
                LOG.error("✗ Error updating device '%s': %s", device_name, str(e))

        return result

    def change_lifecycle_state(self, device_ids: list = None, status: str = None, 
                               config_yaml_file: str = None, devices: Dict[str, Dict[str, Any]] = None) -> dict:
        """
        Alias for bringup_device to maintain consistency with operation naming.
        Change device lifecycle status using device IDs or config file/direct device list.

        Args:
            device_ids: Optional list of device IDs (for direct API call)
            status: Optional status for device_ids (for direct API call)
            config_yaml_file: Optional path to the YAML configuration file
            devices: Optional dictionary of devices with their target statuses
                    Format: {"device-name": {"status": "Pending"}, ...}

        Returns:
            dict: Result with 'changed' status and list of updated devices

        Raises:
            ConfigurationError: If configuration processing fails
            DeviceNotFoundError: If any device cannot be found
            APIError: If API call fails
        """
        # If device_ids and status are provided, use direct API call
        if device_ids and status:
            result = {
                'changed': False,
                'success': False,
                'updated_devices': [],
                'failed_devices': [],
                'error': None
            }
            try:
                success = self.gsdk.put_devices_bringup(device_ids=device_ids, status=status)
                if success:
                    result['changed'] = True
                    result['success'] = True
                    # Add device IDs to result
                    for device_id in device_ids:
                        result['updated_devices'].append({
                            'device_id': device_id,
                            'status': status
                        })
                    LOG.info("✓ Successfully updated %d device(s) to status: %s", len(device_ids), status)
                else:
                    result['error'] = 'API call returned False'
                    result['failed_devices'] = [{'device_id': did, 'error': 'API call returned False'} for did in device_ids]
                    LOG.error("✗ Failed to update devices to status: %s", status)
            except Exception as e:
                result['error'] = str(e)
                result['failed_devices'] = [{'device_id': did, 'error': str(e)} for did in device_ids]
                LOG.error("✗ Error updating devices: %s", str(e))
            return result
        else:
            # Use the standard bringup_device method
            return self.bringup_device(config_yaml_file=config_yaml_file, devices=devices)

    def schedule_upgrade(self, config_yaml_file: str = None, devices: Dict[str, Dict[str, Any]] = None, 
                         action: str = "InstallActivate", ts: Optional[Dict[str, int]] = None) -> dict:
        """
        Schedule device upgrades using config file or direct device list.

        Args:
            config_yaml_file: Optional path to the YAML configuration file
            devices: Optional dictionary of devices with their upgrade configurations
                    Format: {"device-name": {"version": {"release": "Latest"}, ...}, ...}
            action: Upgrade action - "InstallActivate" or "Install" (default: "InstallActivate")
            ts: Optional timestamp with seconds and nanos. If not provided, uses current time

        Returns:
            dict: Result with 'changed' status and list of scheduled devices

        Raises:
            ConfigurationError: If configuration processing fails
            DeviceNotFoundError: If any device cannot be found
            APIError: If API call fails
        """
        import time
        
        result = {
            'changed': False,
            'scheduled_devices': [],
            'failed_devices': [],
            'skipped_devices': []
        }

        # Process devices from config file or direct input
        device_list = []
        if config_yaml_file:
            LOG.info("Processing upgrade schedule from config file: %s", config_yaml_file)
            device_list = self._load_upgrade_devices_from_config(config_yaml_file)
        elif devices:
            LOG.info("Processing upgrade schedule from direct device list")
            device_list = self._load_upgrade_devices_from_dict(devices)
        else:
            raise ConfigurationError("Either config_file or devices parameter must be provided for schedule_upgrade")

        if not device_list:
            LOG.warning("No devices found in configuration")
            return result

        # Group devices by action and ts (to make separate API calls for different actions/timestamps)
        # This allows per-device actions and timestamps
        device_groups = {}  # Key: (action, ts_key), Value: list of device entries
        
        for device_entry in device_list:
            device_name = device_entry.get('device_name')
            version_info = device_entry.get('version', {})
            release = version_info.get('release', 'Latest') if isinstance(version_info, dict) else str(version_info) if version_info else 'Latest'
            
            # Get per-device action or use default
            device_action = device_entry.get('action', action)
            
            # Get per-device ts or use default
            # Default timestamp is "now" in protobuf/gRPC format: {"seconds": epoch_seconds, "nanos": 0}
            device_ts = device_entry.get('ts', ts)
            if device_ts is None:
                current_time = int(time.time())
                device_ts = {"seconds": current_time, "nanos": 0}  # protobuf/gRPC-style timestamp
            
            # Create a key for grouping (action + timestamp)
            ts_key = f"{device_ts.get('seconds', 0)}_{device_ts.get('nanos', 0)}"
            group_key = (device_action, ts_key)
            
            if group_key not in device_groups:
                device_groups[group_key] = []
            
            device_groups[group_key].append({
                'device_name': device_name,
                'version': version_info if isinstance(version_info, dict) else {'release': str(version_info)},
                'action': device_action,
                'ts': device_ts
            })
        
        # Process each group separately
        for (group_action, group_ts_key), group_devices in device_groups.items():
            # Extract ts from key
            ts_parts = group_ts_key.split('_')
            group_ts = {"seconds": int(ts_parts[0]), "nanos": int(ts_parts[1])}
            
            # Build deviceVersions list for this group
            device_versions = []
            for device_entry in group_devices:
                device_name = device_entry.get('device_name')
                version_info = device_entry.get('version', {})
                release = version_info.get('release', 'Latest') if isinstance(version_info, dict) else str(version_info) if version_info else 'Latest'
                
                try:
                    device_id = self.gsdk.get_device_id(device_name)
                    if device_id is None:
                        raise DeviceNotFoundError(
                            f"Device '{device_name}' is not found in the current enterprise: "
                            f"{self.gsdk.enterprise_info.get('company_name', 'Unknown')}. "
                            f"Please check device name and enterprise credentials."
                        )
                    device_versions.append({
                        "deviceId": device_id,
                        "version": {
                            "release": release
                        }
                    })
                except DeviceNotFoundError as e:
                    result['failed_devices'].append({
                        'device_name': device_name,
                        'error': str(e)
                    })
                    LOG.error("Device not found: %s", device_name)
                    continue
            
            if not device_versions:
                LOG.warning("No valid devices found for upgrade scheduling in group (action=%s)", group_action)
                continue
            
            # Schedule the upgrade for this group
            try:
                LOG.info("Scheduling upgrade for %d device(s) with action: %s, ts: %s", 
                        len(device_versions), group_action, group_ts)
                response = self.gsdk.put_devices_upgrade_schedule(
                    action=group_action,
                    device_versions=device_versions,
                    ts=group_ts
                )
                
                result['changed'] = True
                for device_entry in group_devices:
                    device_name = device_entry.get('device_name')
                    if device_name not in [d['device_name'] for d in result['failed_devices']]:
                        try:
                            device_id = self.gsdk.get_device_id(device_name)
                            result['scheduled_devices'].append({
                                'device_name': device_name,
                                'device_id': device_id,
                                'action': group_action,
                                'version': device_entry.get('version', {}),
                                'ts': group_ts
                            })
                        except Exception as e:
                            LOG.warning("Could not get device_id for %s: %s", device_name, str(e))
                            result['scheduled_devices'].append({
                                'device_name': device_name,
                                'device_id': None,
                                'action': group_action,
                                'version': device_entry.get('version', {}),
                                'ts': group_ts
                            })
                
            except APIError as e:
                # Mark all devices in this group as failed
                for device_entry in group_devices:
                    device_name = device_entry.get('device_name')
                    result['failed_devices'].append({
                        'device_name': device_name,
                        'error': str(e)
                    })
                LOG.error("Failed to schedule upgrade for group (action=%s): %s", group_action, str(e))
                continue
            except Exception as e:
                # Mark all devices in this group as failed
                for device_entry in group_devices:
                    device_name = device_entry.get('device_name')
                    result['failed_devices'].append({
                        'device_name': device_name,
                        'error': str(e)
                    })
                LOG.error("Unexpected error during upgrade scheduling for group (action=%s): %s", group_action, str(e))
                continue
        
        if result['scheduled_devices']:
            result['msg'] = f"Successfully scheduled upgrade for {len(result['scheduled_devices'])} device(s)"
            LOG.info(result['msg'])
        elif result['failed_devices']:
            result['msg'] = f"Failed to schedule upgrade for {len(result['failed_devices'])} device(s)"
        else:
            result['msg'] = "No devices were scheduled for upgrade"
        
        return result

    def get_upgrade_status(self, config_yaml_file: str = None, devices: Any = None,
                          device_name: str = None, role: str = "UnknownDeviceRole") -> dict:
        """
        Get device upgrade status using GET /v1/edges-summary API.

        Args:
            config_yaml_file: Optional path to the YAML configuration file
            devices: Optional list of device names or dict of devices (for get_upgrade_status, just device names are needed)
            device_name: Optional single device name to check
            role: Device role to filter by (default: "UnknownDeviceRole")

        Returns:
            dict: Result with upgrade status information for devices

        Raises:
            ConfigurationError: If configuration processing fails
            APIError: If API call fails
        """
        result = {
            'changed': False,
            'devices_upgrade_status': {},  # Dict with device_name as key
            'failed_devices': [],
            'msg': ''
        }

        # Determine which devices to check
        device_names_to_check = []
        
        if config_yaml_file:
            LOG.info("Getting upgrade status from config file: %s", config_yaml_file)
            try:
                config_data = self.render_config_file(config_yaml_file)
                if config_data is None:
                    raise ConfigurationError(f"Config file {config_yaml_file} returned None")
                
                if isinstance(config_data, dict):
                    if 'devices' in config_data:
                        # Extract device names from config (list format for get_upgrade_status)
                        devices_value = config_data['devices']
                        if isinstance(devices_value, list):
                            device_names_to_check = devices_value
                            LOG.info("Found devices as list with %d items: %s", len(device_names_to_check), device_names_to_check)
                        else:
                            raise ConfigurationError(
                                f"For get_upgrade_status operation, devices must be a list. "
                                f"Got {type(devices_value)}: {devices_value}"
                            )
                    else:
                        LOG.warning("No 'devices' key found in config file. Available keys: %s", list(config_data.keys()))
                        device_names_to_check = []
                else:
                    raise ConfigurationError(f"Config file {config_yaml_file} did not return a dictionary. Got: {type(config_data)}")
            except Exception as e:
                LOG.error("Error reading config file %s: %s", config_yaml_file, str(e))
                raise ConfigurationError(f"Error reading config file {config_yaml_file}: {str(e)}")
        elif devices:
            LOG.info("Getting upgrade status for devices from direct device list")
            # For get_upgrade_status, devices must be a list
            if isinstance(devices, list):
                device_names_to_check = devices
            else:
                raise ConfigurationError(
                    f"For get_upgrade_status operation, devices must be a list. "
                    f"Got {type(devices)}: {devices}"
                )
        elif device_name:
            LOG.info("Getting upgrade status for single device: %s", device_name)
            device_names_to_check = [device_name]
        else:
            # If no devices specified, get all devices with the specified role
            LOG.info("Getting upgrade status for all devices with role: %s", role)

        # Get edges summary with upgrade status using SDK
        try:
            # Use SDK get_edges_summary() - upgrade_summary is included in the response
            edges_summary = self.gsdk.get_edges_summary_with_upgrade(role=role)

            if not edges_summary:
                result['msg'] = f"No devices found with role: {role}"
                return result

            # Create a mapping of hostname to device info for quick lookup
            device_map = {}
            for edge in edges_summary:
                # Handle different response formats - SDK returns edge objects with upgrade_summary attribute
                hostname = None
                device_info = None
                
                if hasattr(edge, 'hostname'):
                    hostname = edge.hostname
                    # Convert edge object to dict for easier processing, including upgrade_summary
                    try:
                        device_info = edge.to_dict() if hasattr(edge, 'to_dict') else edge
                        # Ensure upgrade_summary is included
                        if hasattr(edge, 'upgrade_summary'):
                            upgrade_summary = edge.upgrade_summary
                            if isinstance(device_info, dict):
                                device_info['upgradeSummary'] = upgrade_summary.to_dict() if hasattr(upgrade_summary, 'to_dict') else upgrade_summary
                            else:
                                device_info = {'hostname': hostname, 'upgradeSummary': upgrade_summary.to_dict() if hasattr(upgrade_summary, 'to_dict') else upgrade_summary}
                    except (AttributeError, TypeError):
                        device_info = edge
                elif isinstance(edge, dict):
                    hostname = edge.get('hostname')
                    device_info = edge
                else:
                    try:
                        edge_dict = edge.to_dict()
                        hostname = edge_dict.get('hostname')
                        device_info = edge_dict
                    except (AttributeError, TypeError):
                        continue
                
                if hostname:
                    device_map[hostname] = device_info

            # If specific devices were requested, filter to only those
            if not device_names_to_check or len(device_names_to_check) == 0:
                result['msg'] = "No devices specified for get_upgrade_status operation. Please provide devices via config_file, devices parameter, or device_name parameter."
                LOG.warning(result['msg'])
                return result
            
            LOG.info("Filtering to %d specific device(s): %s", len(device_names_to_check), device_names_to_check)
            for device_name in device_names_to_check:
                if device_name in device_map:
                    device_info = device_map[device_name]
                    upgrade_status = self._extract_upgrade_status(device_info)
                    result['devices_upgrade_status'][device_name] = {
                        'device_id': self._get_device_id_from_info(device_info),
                        **upgrade_status
                    }
                else:
                    result['failed_devices'].append({
                        'device_name': device_name,
                        'error': f"Device '{device_name}' not found in edges summary"
                    })

            if result['devices_upgrade_status']:
                device_count = len(result['devices_upgrade_status'])
                result['msg'] = f"Retrieved upgrade status for {device_count} device(s)"
                # Add summary of upgrade statuses
                status_summary = {}
                for device_name, device_status in result['devices_upgrade_status'].items():
                    upgrade_status = device_status.get('upgrade_status', 'Unknown')
                    if upgrade_status not in status_summary:
                        status_summary[upgrade_status] = 0
                    status_summary[upgrade_status] += 1
                
                status_parts = [f"{count} device(s) {status}" for status, count in status_summary.items()]
                if status_parts:
                    result['msg'] += f" - {', '.join(status_parts)}"
            else:
                result['msg'] = "No devices found or no upgrade status retrieved"
            LOG.info(result['msg'])
            
        except APIError as e:
            result['msg'] = f"Failed to get upgrade status: {str(e)}"
            LOG.error(result['msg'])
            raise
        except Exception as e:
            result['msg'] = f"Unexpected error during upgrade status retrieval: {str(e)}"
            LOG.error(result['msg'])
            raise APIError(result['msg'])

        return result

    def _extract_upgrade_status(self, device_info) -> Dict[str, Any]:
        """
        Extract upgrade status information from device info.

        Args:
            device_info: Device information object/dict from edges summary

        Returns:
            dict: Extracted upgrade status information
        """
        upgrade_status = {
            'upgrade_status': None,
            'running_version': None,
            'scheduled_upgrade': None,
            'last_upgrade_ts': None
        }

        # Handle different response formats
        if hasattr(device_info, 'upgrade_summary'):
            upgrade_summary = device_info.upgrade_summary
        elif isinstance(device_info, dict):
            upgrade_summary = device_info.get('upgradeSummary', device_info.get('upgrade_summary'))
        else:
            try:
                device_dict = device_info.to_dict()
                upgrade_summary = device_dict.get('upgradeSummary', device_dict.get('upgrade_summary'))
            except (AttributeError, TypeError):
                upgrade_summary = None

        if not upgrade_summary:
            return upgrade_status

        # Extract upgrade status
        if hasattr(upgrade_summary, 'status'):
            upgrade_status['upgrade_status'] = upgrade_summary.status
        elif isinstance(upgrade_summary, dict):
            upgrade_status['upgrade_status'] = upgrade_summary.get('status')

        # Extract running version
        if hasattr(upgrade_summary, 'running_version'):
            running_version = upgrade_summary.running_version
        elif isinstance(upgrade_summary, dict):
            running_version = upgrade_summary.get('runningVersion', upgrade_summary.get('running_version'))
        else:
            try:
                upgrade_dict = upgrade_summary.to_dict()
                running_version = upgrade_dict.get('runningVersion', upgrade_dict.get('running_version'))
            except (AttributeError, TypeError):
                running_version = None

        if running_version:
            if hasattr(running_version, 'version'):
                upgrade_status['running_version'] = {
                    'release': getattr(running_version, 'release', None),
                    'version': running_version.version,
                    'name': getattr(running_version, 'name', None)
                }
            elif isinstance(running_version, dict):
                upgrade_status['running_version'] = {
                    'release': running_version.get('release'),
                    'version': running_version.get('version'),
                    'name': running_version.get('name')
                }

        # Extract scheduled upgrade
        if hasattr(upgrade_summary, 'schedule'):
            schedule = upgrade_summary.schedule
        elif isinstance(upgrade_summary, dict):
            schedule = upgrade_summary.get('schedule')
        else:
            try:
                upgrade_dict = upgrade_summary.to_dict()
                schedule = upgrade_dict.get('schedule')
            except (AttributeError, TypeError):
                schedule = None

        if schedule:
            if hasattr(schedule, 'state'):
                upgrade_status['scheduled_upgrade'] = {
                    'action': getattr(schedule, 'action', None),
                    'state': schedule.state,
                    'version': getattr(schedule, 'version', None),
                    'ts': getattr(schedule, 'ts', None)
                }
            elif isinstance(schedule, dict):
                upgrade_status['scheduled_upgrade'] = {
                    'action': schedule.get('action'),
                    'state': schedule.get('state'),
                    'version': schedule.get('version'),
                    'ts': schedule.get('ts')
                }

        # Extract last upgrade timestamp
        if hasattr(upgrade_summary, 'last_upgrade_ts'):
            upgrade_status['last_upgrade_ts'] = upgrade_summary.last_upgrade_ts
        elif isinstance(upgrade_summary, dict):
            upgrade_status['last_upgrade_ts'] = upgrade_summary.get('lastUpgradeTs', upgrade_summary.get('last_upgrade_ts'))
        else:
            try:
                upgrade_dict = upgrade_summary.to_dict()
                upgrade_status['last_upgrade_ts'] = upgrade_dict.get('lastUpgradeTs', upgrade_dict.get('last_upgrade_ts'))
            except (AttributeError, TypeError):
                pass

        return upgrade_status

    def _get_device_id_from_info(self, device_info) -> Optional[int]:
        """
        Extract device ID from device info object/dict.

        Args:
            device_info: Device information object/dict

        Returns:
            int or None: Device ID if found
        """
        if hasattr(device_info, 'device_id'):
            return device_info.device_id
        elif isinstance(device_info, dict):
            return device_info.get('deviceId', device_info.get('device_id'))
        else:
            try:
                device_dict = device_info.to_dict()
                return device_dict.get('deviceId', device_dict.get('device_id'))
            except (AttributeError, TypeError):
                return None

    def _load_upgrade_devices_from_config(self, config_yaml_file: str) -> List[Dict[str, Any]]:
        """
        Load device upgrade configuration from YAML file.
        Expects dictionary format with devices and their version info.
        Supports per-device action and ts.
        """
        config_data = self.render_config_file(config_yaml_file)
        
        if 'devices' not in config_data:
            raise ConfigurationError("Config file must contain 'devices' dictionary for upgrade scheduling")
        
        device_list = []
        for device_name, device_data in config_data['devices'].items():
            if not isinstance(device_data, dict):
                raise ConfigurationError(f"Device '{device_name}' must have a dictionary configuration")
            
            version_info = device_data.get('version', {})
            if not version_info:
                version_info = {'release': 'Latest'}  # Default to Latest
            
            device_entry = {
                'device_name': device_name,
                'version': version_info if isinstance(version_info, dict) else {'release': str(version_info)}
            }
            
            # Support per-device action
            if 'action' in device_data:
                device_entry['action'] = device_data['action']
            
            # Support per-device ts
            if 'ts' in device_data:
                device_entry['ts'] = device_data['ts']
            
            device_list.append(device_entry)
        
        return device_list

    def _load_upgrade_devices_from_dict(self, devices: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Load device upgrade configuration from dictionary.
        Supports per-device action and ts.
        """
        device_list = []
        for device_name, device_data in devices.items():
            if not isinstance(device_data, dict):
                raise ConfigurationError(f"Device '{device_name}' must have a dictionary configuration")
            
            version_info = device_data.get('version', {})
            if not version_info:
                version_info = {'release': 'Latest'}  # Default to Latest
            
            device_entry = {
                'device_name': device_name,
                'version': version_info if isinstance(version_info, dict) else {'release': str(version_info)}
            }
            
            # Support per-device action
            if 'action' in device_data:
                device_entry['action'] = device_data['action']
            
            # Support per-device ts
            if 'ts' in device_data:
                device_entry['ts'] = device_data['ts']
            
            device_list.append(device_entry)
        
        return device_list

    def _load_devices_from_config(self, config_yaml_file: str) -> List[Dict[str, Any]]:
        """
        Load device lifecycle configuration from YAML file.
        Uses dictionary format (same as playbook input).

        Args:
            config_yaml_file: Path to the YAML configuration file

        Returns:
            list: List of device entries with device_name and status

        Raises:
            ConfigurationError: If file cannot be read or parsed
        """
        try:
            config_data = self.render_config_file(config_yaml_file)

            device_list = []
            
            # Support dictionary format (same as playbook input)
            if 'devices' in config_data and isinstance(config_data['devices'], dict):
                for device_name, device_config in config_data['devices'].items():
                    if isinstance(device_config, dict):
                        status = device_config.get('status')
                        if status:
                            device_list.append({
                                'device_name': device_name,
                                'status': status
                            })
                        else:
                            LOG.warning("Missing 'status' for device '%s'", device_name)
                    else:
                        LOG.warning("Invalid configuration for device '%s': %s", device_name, device_config)
            else:
                raise ConfigurationError(
                    f"Config file must contain 'devices' dictionary. "
                    f"Format: devices: {{device-name: {{status: 'Pending'}}, ...}}"
                )

            return device_list

        except Exception as e:
            raise ConfigurationError(f"Failed to load device lifecycle config from {config_yaml_file}: {str(e)}")

    def _load_devices_from_dict(self, devices: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Load device lifecycle configuration from dictionary.

        Args:
            devices: Dictionary mapping device names to their configuration
                    Format: {"device-name": {"status": "Pending"}, ...}

        Returns:
            list: List of device entries with device_name and status
        """
        device_list = []
        for device_name, device_config in devices.items():
            if isinstance(device_config, dict):
                status = device_config.get('status')
                if status:
                    device_list.append({
                        'device_name': device_name,
                        'status': status
                    })
                else:
                    LOG.warning("Missing 'status' for device '%s'", device_name)
            else:
                LOG.warning("Invalid configuration for device '%s': %s", device_name, device_config)

        return device_list
