#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import subprocess
import shutil
import json
from collections import OrderedDict

CURRENT_PATH = os.getcwd()
BBF_TR181_ROOT_FILE = "device.c"
BBF_TR104_ROOT_FILE = "servicesvoiceservice.c"
BBF_VENDOR_ROOT_FILE = "vendor.c"
BBF_VENDOR_PREFIX = "X_IOPSYS_EU_"
BBF_DMTREE_PATH = CURRENT_PATH + "/../dmtree"
BBF_DMTREE_PATH_TR181 = BBF_DMTREE_PATH + "/tr181"
BBF_DMTREE_PATH_TR104 = BBF_DMTREE_PATH + "/tr104"
BBF_DMTREE_PATH_TR143 = BBF_DMTREE_PATH + "/tr143"
BBF_DMTREE_PATH_TR181_JSON = BBF_DMTREE_PATH + "/json/tr181.json"
BBF_DMTREE_PATH_TR104_JSON = BBF_DMTREE_PATH + "/json/tr104.json"
DATA_MODEL_FILE = ".data_model.txt"
ARRAY_JSON_FILES = {"tr181": BBF_DMTREE_PATH_TR181_JSON,
                    "tr104": BBF_DMTREE_PATH_TR104_JSON}
LIST_DM_DIR = [BBF_DMTREE_PATH_TR181,
               BBF_DMTREE_PATH_TR104, BBF_DMTREE_PATH_TR143]
LIST_IGNORED_LINE = ['/*', '//', '#']
LIST_OBJ = []
LIST_PARAM = []
LIST_SUPPORTED_DM = []

Array_Types = {"string": "DMT_STRING",
               "unsignedInt": "DMT_UNINT",
               "unsignedLong": "DMT_UNLONG",
               "int": "DMT_INT",
               "long": "DMT_LONG",
               "boolean": "DMT_BOOL",
               "dateTime": "DMT_TIME",
               "hexBinary": "DMT_HEXBIN",
               "base64": "DMT_BASE64",
               "command": "DMT_COMMAND",
               "event": "DMT_EVENT"}


def rename_file(old_file_name, new_file_name):
    try:
        os.rename(old_file_name, new_file_name)
    except OSError:
        pass


def remove_file(file_name):
    try:
        os.remove(file_name)
    except OSError:
        pass


def create_folder(folder_name):
    try:
        os.makedirs(folder_name, exist_ok = True)
    except OSError:
        pass

# rmtree exception handler
def rmtree_handler(_func, path, _exc_info):
    print("Failed to remove %s" % path)

def remove_folder(folder_name):
    if os.path.isdir(folder_name):
        shutil.rmtree(folder_name, onerror = rmtree_handler)

def cd_dir(path):
    try:
        os.chdir(path)
    except OSError:
        pass


def obj_has_child(value):
    if isinstance(value, dict):
        for _obj, val in value.items():
            if isinstance(val, dict):
                for obj1, val1 in val.items():
                    if obj1 == "type" and val1 == "object":
                        return 1
    return 0


def obj_has_param(value):
    if isinstance(value, dict):
        for _obj, val in value.items():
            if isinstance(val, dict):
                for obj1, val1 in val.items():
                    if obj1 == "type" and val1 != "object":
                        return 1
    return 0


def get_option_value(value, option, default = None):
    if isinstance(value, dict):
        for obj, val in value.items():
            if obj == option:
                return val
    return default


def get_param_type(value):
    paramtype = get_option_value(value, "type")
    return Array_Types.get(paramtype, None)

def clean_supported_dm_list():
    LIST_SUPPORTED_DM.clear()

def fill_list_supported_dm():
    fp = open(DATA_MODEL_FILE, 'r')
    Lines = fp.readlines()

    for line in Lines:
        LIST_SUPPORTED_DM.append(line)


def fill_data_model_file():
    fp = open(DATA_MODEL_FILE, 'a')
    for value in LIST_SUPPORTED_DM:
        print("%s" % value, file=fp)
    fp.close()


def generate_datamodel_tree(filename):
    if filename.endswith('.c') is False:
        return

    obj_found = 0
    param_found = 0
    obj_found_in_list = 0
    table_name = ""
    parent_obj = ""

    fp = open(filename, 'r')
    for line in fp:

        if "DMOBJ" in line:
            table_name = line[:line.index('[]')].rstrip(
                '\n').replace("DMOBJ ", "")
            obj_found = 1
            continue

        if "DMLEAF" in line:
            table_name = line[:line.index('[]')].rstrip(
                '\n').replace("DMLEAF ", "")
            param_found = 1
            continue

        if obj_found == 0 and param_found == 0:
            continue

        if line.startswith(tuple(LIST_IGNORED_LINE)) is True:
            continue

        if "{0}" in line:
            obj_found = 0
            param_found = 0
            obj_found_in_list = 0
            table_name = ""
            parent_obj = ""
            continue

        # Object Table
        if obj_found == 1:
            if obj_found_in_list == 0:
                for value in LIST_OBJ:
                    val = value.split(":")
                    if val[1] == table_name:
                        parent_obj = val[0]
                        obj_found_in_list = 1
                        LIST_OBJ.remove(value)

            obj = line.rstrip('\n').split(", ")
            obj_name = parent_obj + obj[0].replace("{", "").replace("\"", "").replace(
                "BBF_VENDOR_PREFIX", BBF_VENDOR_PREFIX).replace(" ", "")
            obj_permission = obj[1].replace("&", "").replace(" ", "")
            obj_mulinst = obj[5].replace("&", "").replace(" ", "")

            if obj_mulinst == "NULL":
                full_obj_name = obj_name + "."
            else:
                full_obj_name = obj_name + ".{i}."

            LIST_SUPPORTED_DM.append(
                full_obj_name + "," + obj_permission + ",DMT_OBJ")

            if obj[8] != "NULL":
                LIST_OBJ.append(full_obj_name + ":" + obj[8])

            if obj[9] != "NULL":
                LIST_PARAM.append(full_obj_name + ":" + obj[9])

        # Parameter Table
        if param_found == 1:
            if obj_found_in_list == 0:
                for value in LIST_PARAM:
                    val = value.split(":")
                    if val[1] == table_name:
                        parent_obj = val[0]
                        obj_found_in_list = 1
                        LIST_PARAM.remove(value)

            param = line.rstrip('\n').split(", ")
            param_name = parent_obj + param[0].replace("{", "").replace(
                "\"", "").replace("BBF_VENDOR_PREFIX", BBF_VENDOR_PREFIX).replace(" ", "")
            param_permission = param[1].replace("&", "").replace(" ", "")
            param_type = param[2].replace(" ", "")

            LIST_SUPPORTED_DM.append(
                param_name + "," + param_permission + "," + param_type)

    fp.close()


def generate_dynamic_datamodel_tree(filename):
    if filename.endswith('.c') is False:
        return

    obj_found = 0

    fp = open(filename, 'r')
    for line in fp:

        if "DM_MAP_OBJ" in line:
            obj_found = 1
            continue

        if obj_found == 0:
            continue

        if line.startswith(tuple(LIST_IGNORED_LINE)) is True:
            continue

        if "{0}" in line:
            obj_found = 0
            continue

        # Object Table
        if obj_found == 1:
            obj = line.rstrip('\n').split(", ")
            obj_name = obj[0][1:].replace("\"", "")

            if obj[1] != "NULL":
                LIST_OBJ.append(obj_name + ":" + obj[1])

            if obj[2] != "NULL":
                LIST_PARAM.append(obj_name + ":" + obj[2].replace("},", ""))

    fp.close()


def parse_dynamic_json_datamodel_tree(obj, value):
    obj_permission = "DMWRITE" if get_option_value(
        value, "array") is True else "DMREAD"
    LIST_SUPPORTED_DM.append(obj + "," + obj_permission + ",DMT_OBJ")

    hasobj = obj_has_child(value)
    hasparam = obj_has_param(value)

    if hasparam and isinstance(value, dict):
        for k, v in value.items():
            if k != "mapping" and isinstance(v, dict):
                for k1, v1 in v.items():
                    if k1 == "type" and v1 != "object":
                        param_name = obj + k
                        param_type = get_param_type(v)
                        param_permission = "DMWRITE" if get_option_value(
                            v, "write") is True else "DMREAD"
                        LIST_SUPPORTED_DM.append(
                            param_name + "," + param_permission + "," + param_type)
                        break

    if hasobj and isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, dict):
                for k1, v1 in v.items():
                    if k1 == "type" and v1 == "object":
                        parse_dynamic_json_datamodel_tree(k, v)


def generate_dynamic_json_datamodel_tree(filename):
    if filename.endswith('.json') is False:
        return

    json_file = open(filename, "r")
    data = json.loads(json_file.read(), object_pairs_hook=OrderedDict)

    for obj, value in data.items():
        if obj is None or obj.startswith('Device.') is False:
            continue

        parse_dynamic_json_datamodel_tree(obj, value)


def generate_supported_dm(vendor_prefix=None, vendor_list=None, plugins=None):
    '''
    1/ Download Remote Data Model if needed
    2/ Parse all Standard Data Model
    3/ Parse all Vendor Data Model if needed
    4/ Generate the list of Supported Data Model 'LIST_SUPPORTED_DM'
    5/ Copy the supported data model in file 'DATA_MODEL_FILE'
    '''

    ############## SET BBF VENDOR PREFIX ##############
    if vendor_prefix is not None:
        global BBF_VENDOR_PREFIX
        BBF_VENDOR_PREFIX = vendor_prefix

    ############## GEN Local BBF Data Models TREE ##############
    print("Generating the local data models...")

    cd_dir(BBF_DMTREE_PATH_TR181)
    generate_datamodel_tree(BBF_TR181_ROOT_FILE)

    cd_dir(BBF_DMTREE_PATH_TR104)
    generate_datamodel_tree(BBF_TR104_ROOT_FILE)

    for DIR in LIST_DM_DIR:
        cd_dir(DIR)
        for _root, _dirs, files in os.walk("."):
            for filename in files:
                if filename.endswith('.c') is False or filename == BBF_TR181_ROOT_FILE or filename == BBF_TR104_ROOT_FILE:
                    continue

                generate_datamodel_tree(filename)

    ############## GEN Vendors BBF Data Models TREE ##############
    if vendor_list is not None and isinstance(vendor_list, list) and vendor_list:
        cd_dir(BBF_DMTREE_PATH)
        for vendor in vendor_list:
            vendor_dir = "vendor/" + vendor + "/tr181"
            if os.path.isdir(vendor_dir):
                cd_dir(vendor_dir)

                generate_dynamic_datamodel_tree(BBF_VENDOR_ROOT_FILE)
                if os.path.isfile(BBF_TR181_ROOT_FILE):
                    generate_datamodel_tree(BBF_TR181_ROOT_FILE)

                for _root, _dirs, files in os.walk("."):
                    for filename in files:
                        if filename.endswith('.c') is False or filename == BBF_VENDOR_ROOT_FILE or filename == BBF_TR181_ROOT_FILE:
                            continue

                        generate_datamodel_tree(filename)

                cd_dir(BBF_DMTREE_PATH)

            vendor_dir = "vendor/" + vendor + "/tr104"
            if os.path.isdir(vendor_dir):
                cd_dir(vendor_dir)

                for _root, _dirs, files in os.walk("."):
                    for filename in files:
                        if filename.endswith('.c') is False:
                            continue

                        generate_datamodel_tree(filename)

                cd_dir(BBF_DMTREE_PATH)

    ############## Download && Generate Plugins Data Models ##############
    if plugins is not None and isinstance(plugins, list) and plugins:
        print("Generating datamodels from defined plugins...")

        cd_dir(CURRENT_PATH)
        if isinstance(plugins, list):
            for plugin in plugins:
                repo = get_option_value(plugin, "repo")
                version = get_option_value(plugin, "version")

                remove_folder(".repo")
                try:
                    subprocess.run(["git", "clone", repo, ".repo"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check = True)
                except (OSError, subprocess.SubprocessError) as _e:
                    print("Failed to clone %s" % repo)

                if version is not None:
                    try:
                        subprocess.run(["git", "-C", ".repo", "checkout", version],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    except (OSError, subprocess.SubprocessError) as _e:
                        print("Failed to checkout git version %s" % version)

                if os.path.isdir(".repo"):
                    if version is None:
                        print('├── Processing ' + repo)
                    else:
                        print('├── Processing ' + repo + '^' + version)

                    dm_files = get_option_value(plugin, "dm_files")
                    if dm_files is not None and isinstance(dm_files, list):
                        for dm_file in dm_files:
                            generate_dynamic_datamodel_tree(".repo/" + dm_file)
                            generate_datamodel_tree(".repo/" + dm_file)
                            generate_dynamic_json_datamodel_tree(".repo/" + dm_file)
                    else:
                        files = os.popen('find .repo/ -name datamodel.c').read()
                        for file in files.split('\n'):
                            if os.path.isfile(file):
                                generate_dynamic_datamodel_tree(file)
                                generate_datamodel_tree(file)

                        files = os.popen('find .repo/ -name "*.json"').read()
                        for file in files.split('\n'):
                            if os.path.isfile(file):
                                generate_dynamic_json_datamodel_tree(file)

                    remove_folder(".repo")
            print('└── Processing of plugins done')

    ############## Remove Duplicated Element from List ##############
    global LIST_SUPPORTED_DM
    LIST_SUPPORTED_DM = list(set(LIST_SUPPORTED_DM))

    ############## Sort all elements in List ##############
    LIST_SUPPORTED_DM.sort(reverse=False)

    ############## Back to the current directory ##############
    cd_dir(CURRENT_PATH)

    ############### COPY SUPPORTED DATA MODEL TO FILE ###############
    remove_file(DATA_MODEL_FILE)
    fill_data_model_file()
