#!/usr/bin/python3

# Copyright (C) 2024-2025 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

import sys
import os
import subprocess
import shutil

# Constants
BBF_ERROR_CODE = 0
CURRENT_PATH = os.getcwd()

DM_JSON_FILE = os.path.join(CURRENT_PATH, "tools", "datamodel.json")

LIST_SUPPORTED_USP_DM = []
LIST_SUPPORTED_CWMP_DM = []

Array_Types = {
    "string": "DMT_STRING",
    "unsignedInt": "DMT_UNINT",
    "unsignedLong": "DMT_UNLONG",
    "int": "DMT_INT",
    "long": "DMT_LONG",
    "boolean": "DMT_BOOL",
    "dateTime": "DMT_TIME",
    "hexBinary": "DMT_HEXBIN",
    "base64": "DMT_BASE64",
    "command": "DMT_COMMAND",
    "event": "DMT_EVENT"
}


def remove_file(file_path):
    try:
        os.remove(file_path)
    except OSError:
        pass


def create_folder(folder_path):
    try:
        os.makedirs(folder_path, exist_ok=True)
    except OSError:
        pass


def remove_folder(folder_path):
    if os.path.isdir(folder_path):
        shutil.rmtree(folder_path)


def obj_has_child(value):
    if isinstance(value, dict):
        for _obj, val in value.items():
            if isinstance(val, dict):
                for obj1, val1 in val.items():
                    if obj1 == "type" and val1 == "object":
                        return True
    return False


def obj_has_param(value):
    if isinstance(value, dict):
        for _obj, val in value.items():
            if isinstance(val, dict):
                for obj1, val1 in val.items():
                    if obj1 == "type" and val1 != "object":
                        return True
    return False


def get_option_value(value, option, default=None):
    if isinstance(value, dict):
        for obj, val in value.items():
            if obj == option:
                return val
    return default


def get_param_type(value):
    param_type = get_option_value(value, "type")
    return Array_Types.get(param_type, None)


def get_description_from_json(value):
    description = get_option_value(value, "description", "")
    return description


def get_range_from_json(value):
    range_value = get_option_value(value, "range", [])
    return range_value


def get_list_from_json(value):
    list_value = get_option_value(value, "list", {})
    return list_value


def get_enum_from_json(value):
    enumerations = get_option_value(value, "enumerations", [])
    return enumerations


def is_proto_exist(value, proto):
    protocols = get_option_value(value, "protocols", [])
    return proto in protocols


def build_command(plugin, proto):
    service_name = get_option_value(plugin, "service_name")
    unified = get_option_value(plugin, "unified_daemon", False)
    daemon_name = get_option_value(plugin, "daemon_name", "")

    if not service_name:
        return None  # skip this plugin

    if unified:
        base_cmd = f"{daemon_name}"
    else:
        base_cmd = f"dm-service -m {service_name}"

    if proto == "cwmp":
        base_cmd += " -d"
    elif proto == "usp":
        base_cmd += " -dd"

    return base_cmd


def fill_list_dm(command, dm_list):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        output = result.stdout
        lines = output.strip().split('\n')

        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            path, n_type, data = parts[0], parts[1], parts[2]
            permission = "readWrite" if data == "1" else "readOnly"
            p_type = n_type[4:]
            entry = {
                "param": path,
                "permission": permission,
                "type": p_type,
            }
            dm_list.append(entry)

    except subprocess.CalledProcessError as e:
        print(f"Error running command '{command}': {e}")
        sys.exit(1)


def remove_duplicate_elements(input_list):
    unique_values = set()
    result_list = []

    for item in input_list:
        item_value = item["param"]
        if item_value not in unique_values:
            unique_values.add(item_value)
            result_list.append(item)

    return result_list


def fill_list_supported_dm(plugins):

    if plugins is None or not isinstance(plugins, list) or not plugins:
        print("No plugins provided.")
        return

    for proto, DB in [("usp", LIST_SUPPORTED_USP_DM), ("cwmp", LIST_SUPPORTED_CWMP_DM)]:
        for plugin in plugins:
            command = build_command(plugin, proto)
            if command:
                print(f"Running command for {proto}: {command}")
                fill_list_dm(command, DB)

        DB.sort(key=lambda x: x['param'], reverse=False)
        DB[:] = remove_duplicate_elements(DB)


def generate_supported_dm(plugins=None):
    '''
    Generates supported data models and performs necessary actions.

    Args:
        plugins (list, optional): List of plugin configurations.
    '''

    # Fill the list supported data model
    fill_list_supported_dm(plugins)
