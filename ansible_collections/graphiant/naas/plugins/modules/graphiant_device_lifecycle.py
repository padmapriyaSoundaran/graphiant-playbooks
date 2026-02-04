#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Graphiant Team <support@graphiant.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ansible module for managing device lifecycle states in Graphiant.

This module provides the ability to change device lifecycle status using
the PUT /v1/devices/bringup API endpoint.
"""

DOCUMENTATION = r'''
---
module: graphiant_device_lifecycle
short_description: Manage device lifecycle states in Graphiant
description:
  - This module changes device lifecycle status using the C(PUT /v1/devices/bringup) API.
  - Supports changing device status to Pending (staging), Allowed (active), Denied, Removed, or Maintenance.
  - Can process devices from a config file or directly from a device list.
  - Supports parallel execution for multiple devices.
version_added: "25.12.3"
notes:
  - "Supported Status Values (user-friendly format):"
  - "  - V(staging): Move device to staging/Pending state"
  - "  - V(active): Activate device (Allowed state)"
  - "  - V(maintenance): Put device in maintenance mode"
  - "  - V(deactivate): Deactivate device (Denied state)"
  - "  - V(decommission): Remove device (Removed state)"
  - "Input Methods:"
  - "  - Config file: YAML file with device_lifecycle entries"
  - "  - Direct input: Dictionary of devices with their target statuses"
options:
  host:
    description:
      - Graphiant portal host URL for API connectivity.
      - 'Example: "https://api.graphiant.com"'
    type: str
    required: true
    aliases: [ base_url ]
  username:
    description:
      - Graphiant portal username for authentication.
    type: str
    required: true
  password:
    description:
      - Graphiant portal password for authentication.
    type: str
    required: true
  config_file:
    description:
      - Path to the device lifecycle configuration YAML file.
      - Required if O(devices) or O(device_name) is not provided.
      - Can be an absolute path or relative path.
      - Configuration files support Jinja2 templating syntax.
      - "File must contain I(devices) dictionary (same format as playbook input):"
      - "  devices:"
      - "    edge-1-sdktest:"
      - "      status: \"Pending\""
    type: str
    required: false
  devices:
    description:
      - Dictionary of devices with their target statuses (for V(change_lifecycle_state), V(schedule_upgrade)).
      - List of device names (for V(get_upgrade_status)).
      - Required if O(config_file) or O(device_name) is not provided.
      - "Format for lifecycle/upgrade operations:"
      - "  devices:"
      - "    edge-1-sdktest:"
      - "      status: \"Pending\""
      - "Format for get_upgrade_status (list of device names):"
      - "  devices:"
      - "    - edge-1-sdktest"
      - "    - edge-2-sdktest"
    type: raw
    required: false
  device_name:
    description:
      - Single device name for direct input (used with O(status) for loop iteration).
      - Required if O(config_file) and O(devices) are not provided.
    type: str
    required: false
  status:
    description:
      - Target lifecycle status for the device (used with O(device_name) for loop iteration).
      - Required when O(device_name) is provided.
    type: str
    required: false
  operation:
    description:
      - The specific device lifecycle operation to perform.
      - "V(change_lifecycle_state): Change device lifecycle status (PUT /v1/devices/bringup)."
      - "V(schedule_upgrade): Schedule device upgrades (PUT /v1/devices/upgrade/schedule)."
      - "V(get_upgrade_status): Get device upgrade status (GET /v1/edges-summary?upgradeSummary=true)."
    type: str
    choices:
      - change_lifecycle_state
      - schedule_upgrade
      - get_upgrade_status
    default: change_lifecycle_state
  action:
    description:
      - Upgrade action when using V(schedule_upgrade) operation.
      - "V(InstallActivate): Install and activate the upgrade immediately."
      - "V(Install): Install the upgrade without activating."
    type: str
    required: false
    choices:
      - InstallActivate
      - Install
    default: "InstallActivate"
  ts:
    description:
      - Timestamp for scheduled upgrade when using V(schedule_upgrade) operation.
      - Format: C({"seconds": int, "nanos": int}) - protobuf/gRPC-style timestamp.
      - If not provided, defaults to current time (now) with C({"seconds": epoch_seconds, "nanos": 0}).
      - Example: C({"seconds": 1770018050, "nanos": 236000000}).
    type: dict
    required: false
  version:
    description:
      - Version information for upgrade when using V(schedule_upgrade) operation with O(device_name).
      - Format: C({"release": "Latest"}) or C({"release": "stable"}) or C({"release": "recommended"}).
      - Can also be a string like C("Latest"), C("stable"), or C("recommended").
    type: raw
    required: false
  role:
    description:
      - Device role to filter by when using V(get_upgrade_status) operation.
      - Options: V(UnknownDeviceRole), V(cpe), V(gateway), etc.
      - Default is V(UnknownDeviceRole).
    type: str
    required: false
    default: "UnknownDeviceRole"
  state:
    description:
      - The desired state of the device lifecycle.
      - "V(present): Maps to V(change_lifecycle_state) operation when O(operation) not specified."
    type: str
    choices: [ present ]
    default: present
  detailed_logs:
    description:
      - Enable detailed logging output for troubleshooting and monitoring.
    type: bool
    default: false

attributes:
  check_mode:
    description: Supports check mode with partial support.
    support: partial
    details: >
      Check mode returns V(changed=True) as the module cannot accurately determine
      whether changes would actually be made without querying the current state via API calls.

requirements:
  - python >= 3.7
  - graphiant-sdk >= 25.12.1

author:
  - Graphiant Team (@graphiant)

'''

EXAMPLES = r'''
- name: Change device lifecycle status using config file
  graphiant.naas.graphiant_device_lifecycle:
    operation: change_lifecycle_state
    config_file: "sample_device_lifecycle.yaml"
    host: "{{ graphiant_host }}"
    username: "{{ graphiant_username }}"
    password: "{{ graphiant_password }}"
    detailed_logs: true
  register: lifecycle_result

- name: Display lifecycle result
  ansible.builtin.debug:
    msg: "{{ lifecycle_result.msg }}"

- name: Change device lifecycle status using direct device list
  graphiant.naas.graphiant_device_lifecycle:
    operation: change_lifecycle_state
    devices:
      edge-1-sdktest:
        status: "staging"
      edge-2-sdktest:
        status: "active"
    host: "{{ graphiant_host }}"
    username: "{{ graphiant_username }}"
    password: "{{ graphiant_password }}"
  register: direct_result

- name: Move device to staging using direct input
  graphiant.naas.graphiant_device_lifecycle:
    operation: change_lifecycle_state
    devices:
      edge-1-sdktest:
        status: "staging"
    host: "{{ graphiant_host }}"
    username: "{{ graphiant_username }}"
    password: "{{ graphiant_password }}"

- name: Schedule device upgrade using direct input
  graphiant.naas.graphiant_device_lifecycle:
    operation: schedule_upgrade
    devices:
      edge-1-sdktest:
        version:
          release: "Latest"  # or "stable", "recommended"
    action: "InstallActivate"  # or "Install"
    host: "{{ graphiant_host }}"
    username: "{{ graphiant_username }}"
    password: "{{ graphiant_password }}"
  register: upgrade_result

- name: Schedule device upgrade with custom timestamp
  graphiant.naas.graphiant_device_lifecycle:
    operation: schedule_upgrade
    devices:
      edge-1-sdktest:
        version:
          release: "stable"
    action: "Install"
    ts:
      seconds: 1770018050
      nanos: 236000000
    host: "{{ graphiant_host }}"
    username: "{{ graphiant_username }}"
    password: "{{ graphiant_password }}"

# Example config file (sample_device_lifecycle.yaml):
# ---
# devices:
#   edge-1-sdktest:
#     status: "staging"  # or "active", "maintenance", "deactivate", "decommission"
#   edge-2-sdktest:
#     status: "active"
'''

RETURN = r'''
msg:
  description:
    - Result message from the operation, including detailed logs when O(detailed_logs) is enabled.
  type: str
  returned: always
  sample: "Successfully updated 2 device(s) to new lifecycle status"
changed:
  description:
    - Whether the operation made changes to the system.
  type: bool
  returned: always
  sample: true
operation:
  description:
    - The operation that was performed.
  type: str
  returned: always
  sample: "change_lifecycle_state"
updated_devices:
  description:
    - List of devices that were successfully updated.
  type: list
  returned: always
  sample:
    - device_name: "edge-1-sdktest"
      device_id: 30000051597
      status: "Pending"
failed_devices:
  description:
    - List of devices that failed to update.
  type: list
  returned: always
  sample: []
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.graphiant.naas.plugins.module_utils.graphiant_utils import (
    get_graphiant_connection,
    handle_graphiant_exception
)
from ansible_collections.graphiant.naas.plugins.module_utils.logging_decorator import (
    capture_library_logs
)


@capture_library_logs
def execute_with_logging(module, func, *args, **kwargs):
    """
    Execute a function with optional detailed logging.

    Args:
        module: Ansible module instance
        func: Function to execute
        *args: Arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function

    Returns:
        dict: Result with 'changed' and 'result_msg' keys
    """
    success_msg = kwargs.pop('success_msg', 'Operation completed successfully')

    try:
        result = func(*args, **kwargs)

        if isinstance(result, dict) and 'changed' in result:
            return {
                'changed': result['changed'],
                'result_msg': success_msg,
                'result_data': result
            }

        return {
            'changed': True,
            'result_msg': success_msg,
            'result_data': result
        }
    except Exception as e:
        raise e


def main():
    """
    Main function for the Graphiant device lifecycle module.
    """

    # Define module arguments
    argument_spec = dict(
        host=dict(type='str', required=True, aliases=['base_url']),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        config_file=dict(type='str', required=False, default=None),
        devices=dict(type='dict', required=False, default=None),
        device_name=dict(type='str', required=False, default=None),
        status=dict(type='str', required=False, default=None),
        operation=dict(
            type='str',
            required=False,
            default='change_lifecycle_state',
            choices=['change_lifecycle_state', 'schedule_upgrade', 'get_upgrade_status']
        ),
        action=dict(
            type='str',
            required=False,
            default='InstallActivate',
            choices=['InstallActivate', 'Install']
        ),
        ts=dict(type='dict', required=False, default=None),
        version=dict(type='raw', required=False, default=None),
        role=dict(type='str', required=False, default='UnknownDeviceRole'),
        state=dict(
            type='str',
            required=False,
            default='present',
            choices=['present']
        ),
        detailed_logs=dict(
            type='bool',
            required=False,
            default=False
        )
    )

    # Create Ansible module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[['config_file', 'devices', 'device_name']],
        required_one_of=[['config_file', 'devices', 'device_name']]
    )
    
    # Validate required_together based on operation
    operation = module.params.get('operation', 'change_lifecycle_state')
    device_name = module.params.get('device_name')
    status = module.params.get('status')
    
    if operation == 'change_lifecycle_state' and device_name and not status:
        module.fail_json(msg="When operation is 'change_lifecycle_state' and device_name is provided, status is required")

    # Get parameters
    params = module.params
    operation = params.get('operation')
    state = params.get('state', 'present')
    config_file = params.get('config_file')
    devices = params.get('devices')
    device_name = params.get('device_name')
    status = params.get('status')
    
    # If device_name is provided, convert to devices format based on operation
    if device_name:
        if operation == 'change_lifecycle_state':
            # For change_lifecycle_state, status is required
            if not status:
                module.fail_json(msg="status is required when device_name is provided for change_lifecycle_state operation")
            devices = {device_name: {'status': status}}
        elif operation == 'schedule_upgrade':
            # For schedule_upgrade, version is required
            version = params.get('version')
            if not version:
                module.fail_json(msg="version is required when device_name is provided for schedule_upgrade operation")
            # Normalize version to dict format
            if isinstance(version, str):
                version = {'release': version}
            elif not isinstance(version, dict):
                module.fail_json(msg="version must be a string or dictionary with 'release' key")
            devices = {device_name: {'version': version}}
        elif operation == 'get_upgrade_status':
            # For get_upgrade_status, just use a list of device names
            devices = [device_name]

    # If operation is not specified, use state to determine operation
    if not operation:
        if state == 'present':
            operation = 'change_lifecycle_state'

    # Handle check mode
    if module.check_mode:
        if operation == 'get_upgrade_status':
            changed = False
            msg = f"Check mode: Would get upgrade status (no changes made)"
        elif operation == 'schedule_upgrade':
            changed = True
            if config_file:
                msg = f"Check mode: Would schedule upgrade from {config_file} (no changes made)"
            else:
                msg = f"Check mode: Would schedule upgrade for {len(devices) if devices else 0} device(s) (no changes made)"
        else:
            changed = True
            if config_file:
                msg = f"Check mode: Would change device lifecycle status from {config_file} (no changes made)"
            else:
                msg = f"Check mode: Would change device lifecycle status for {len(devices) if devices else 0} device(s) (no changes made)"

        result_dict = dict(
            changed=changed,
            msg=msg,
            operation=operation
        )
        if config_file:
            result_dict['config_file'] = config_file
        if devices:
            result_dict['devices'] = devices

        module.exit_json(**result_dict)

    try:
        # Get Graphiant connection
        connection = get_graphiant_connection(params)
        graphiant_config = connection.graphiant_config

        # Execute the requested operation
        changed = False
        result_msg = ""

        if operation == 'change_lifecycle_state':
            result = execute_with_logging(
                module,
                graphiant_config.device_lifecycle.change_lifecycle_state,
                config_yaml_file=config_file,
                devices=devices,
                success_msg="Device lifecycle status updated successfully"
            )
            changed = result['changed']
            result_data = result.get('result_data', {})
            
            # Build result message
            updated_count = len(result_data.get('updated_devices', []))
            failed_count = len(result_data.get('failed_devices', []))
            
            if updated_count > 0:
                result_msg = f"Successfully updated {updated_count} device(s) to new lifecycle status"
            if failed_count > 0:
                result_msg += f". {failed_count} device(s) failed to update"
            
            if not result_msg:
                result_msg = "No devices were updated"

        elif operation == 'schedule_upgrade':
            action = params.get('action', 'InstallActivate')
            ts = params.get('ts')
            
            result = execute_with_logging(
                module,
                graphiant_config.device_lifecycle.schedule_upgrade,
                config_yaml_file=config_file,
                devices=devices,
                action=action,
                ts=ts,
                success_msg="Device upgrade scheduled successfully"
            )
            changed = result['changed']
            result_data = result.get('result_data', {})
            
            # Build result message
            scheduled_count = len(result_data.get('scheduled_devices', []))
            failed_count = len(result_data.get('failed_devices', []))
            
            if scheduled_count > 0:
                result_msg = f"Successfully scheduled upgrade for {scheduled_count} device(s) with action: {action}"
            if failed_count > 0:
                result_msg += f". {failed_count} device(s) failed to schedule"
            
            if not result_msg:
                result_msg = "No devices were scheduled for upgrade"

        elif operation == 'get_upgrade_status':
            role = params.get('role', 'UnknownDeviceRole')
            
            # Convert devices dict to list if needed (for backward compatibility)
            devices_for_status = devices
            if devices and isinstance(devices, dict):
                # For get_upgrade_status, convert dict keys to list
                devices_for_status = list(devices.keys())
            
            result = execute_with_logging(
                module,
                graphiant_config.device_lifecycle.get_upgrade_status,
                config_yaml_file=config_file,
                devices=devices_for_status,
                device_name=device_name,
                role=role,
                success_msg="Device upgrade status retrieved successfully"
            )
            changed = False  # This is a read-only operation
            result_data = result.get('result_data', {})
            
            # Build result message
            devices_upgrade_status = result_data.get('devices_upgrade_status', {})
            status_count = len(devices_upgrade_status) if isinstance(devices_upgrade_status, dict) else len(devices_upgrade_status) if isinstance(devices_upgrade_status, list) else 0
            failed_count = len(result_data.get('failed_devices', []))
            
            if status_count > 0:
                result_msg = f"Retrieved upgrade status for {status_count} device(s)"
            if failed_count > 0:
                result_msg += f". {failed_count} device(s) failed to retrieve status"
            
            if not result_msg:
                result_msg = "No upgrade status information retrieved"

        else:
            module.fail_json(
                msg=f"Unsupported operation: {operation}. "
                    f"Supported operations are: change_lifecycle_state, schedule_upgrade, get_upgrade_status"
            )

        # Return success
        result_dict = dict(
            changed=changed,
            msg=result_msg,
            operation=operation
        )
        
        # Add operation-specific result fields
        if operation == 'change_lifecycle_state':
            result_dict.update({
                'updated_devices': result_data.get('updated_devices', []),
                'failed_devices': result_data.get('failed_devices', []),
                'skipped_devices': result_data.get('skipped_devices', [])
            })
        elif operation == 'schedule_upgrade':
            result_dict.update({
                'scheduled_devices': result_data.get('scheduled_devices', []),
                'failed_devices': result_data.get('failed_devices', []),
                'skipped_devices': result_data.get('skipped_devices', []),
                'action': params.get('action', 'InstallActivate')
            })
        elif operation == 'get_upgrade_status':
            result_dict.update({
                'devices_upgrade_status': result_data.get('devices_upgrade_status', {}),
                'failed_devices': result_data.get('failed_devices', []),
                'role': params.get('role', 'UnknownDeviceRole')
            })
            # Update msg with the result_msg we built
            if result_msg:
                result_dict['msg'] = result_msg
        if config_file:
            result_dict['config_file'] = config_file
        if devices:
            result_dict['devices'] = devices

        module.exit_json(**result_dict)

    except Exception as e:
        error_msg = handle_graphiant_exception(e, operation)
        module.fail_json(msg=error_msg, operation=operation)


if __name__ == '__main__':
    main()
