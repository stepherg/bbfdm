#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import subprocess
import shutil
import json
from collections import OrderedDict

CURRENT_PATH = os.getcwd()
ROOT = None
BBF_ERROR_CODE = 0
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

def get_root_node():
    return ROOT

def set_root_node(rootdm = "Device."):
    global ROOT
    ROOT = rootdm

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
    print(f'Failed to remove {path}')

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

def get_protocol_from_json(value):
    val = get_option_value(value, "protocols", ["cwmp", "usp"])
    if "cwmp" in val and "usp" in val:
        return "BBFDM_BOTH"
    elif "cwmp" in val:
        return "BBFDM_CWMP"
    else:
        return "BBFDM_USP"

def get_description_from_json(value):
    val = get_option_value(value, "description", "")
    return val

def get_range_from_json(value):
    val = get_option_value(value, "range", [])
    return val

def get_list_from_json(value):
    val = get_option_value(value, "list", {})
    return val

def get_enum_from_json(value):
    val = get_option_value(value, "enumerations", [])
    return val

def clean_supported_dm_list():
    LIST_SUPPORTED_DM.clear()

def fill_list_supported_dm():
    fp = open(DATA_MODEL_FILE, 'r', encoding='utf-8')
    Lines = fp.readlines()

    for line in Lines:
        LIST_SUPPORTED_DM.append(line)


def fill_data_model_file():
    fp = open(DATA_MODEL_FILE, 'a', encoding='utf-8')
    for value in LIST_SUPPORTED_DM:
        if (ROOT):
            js_val = json.loads(value)
            param = get_option_value(js_val, "param")
            if param is not None and (param.startswith(ROOT)):
                print(f"{value}", file=fp)
        else:
            print(f"{value}", file=fp)
    fp.close()


def reorganize_parent_child():
    organized_dm = []
    global LIST_SUPPORTED_DM

    for value in LIST_SUPPORTED_DM:
        obj = json.loads(value)
        o_type = get_option_value(obj, "type", None)
        if o_type != "DMT_OBJ":
            continue

        o_name = get_option_value(obj, "param", None)
        if o_name is None:
            continue

        organized_dm.append(value)
        for item in LIST_SUPPORTED_DM:
            param = json.loads(item)
            p_type = get_option_value(param, "type", None)
            if p_type is None or p_type == "DMT_OBJ":
                continue

            p_name = get_option_value(param, "param", None)
            if p_name is None:
                continue

            if p_name.find(o_name) != -1:
                ob_dot = o_name.count('.')
                pm_dot = p_name.count('.')
                if ob_dot == pm_dot:
                    organized_dm.append(item)

    LIST_SUPPORTED_DM.clear()
    LIST_SUPPORTED_DM = organized_dm


def generate_datamodel_tree(filename):
    if filename.endswith('.c') is False:
        return

    LIST_DEL_PARAM = []
    obj_found = 0
    param_found = 0
    obj_found_in_list = 0
    table_name = ""
    parent_obj = ""

    fp = open(filename, 'r', encoding='utf-8')
    for line in fp:
        line = line.lstrip()

        if line.startswith(tuple(LIST_IGNORED_LINE)) is True:
            continue

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

        if "{0}" in line.replace(" ", ""):
            obj_found = 0
            param_found = 0
            obj_found_in_list = 0
            table_name = ""
            parent_obj = ""
            for value in LIST_DEL_PARAM:
                LIST_PARAM.remove(value)
            LIST_DEL_PARAM.clear()
            continue

        # Object Table
        if obj_found == 1:
            if obj_found_in_list == 0:
                obj_list = LIST_OBJ
                for value in obj_list:
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
            obj_protocol = obj[11].replace("}", "").replace(" ", "").replace(",", "")

            if obj_mulinst == "NULL":
                full_obj_name = obj_name + "."
            else:
                full_obj_name = obj_name + ".{i}."

            LIST_SUPPORTED_DM.append(
                "{\"param\":\"" + full_obj_name + "\",\"permission\":\"" + obj_permission + "\",\"type\":\"DMT_OBJ\",\"protocol\":\"" + obj_protocol + "\"}")

            if obj[8] != "NULL":
                LIST_OBJ.append(full_obj_name + ":" + obj[8])

            if obj[9] != "NULL":
                LIST_PARAM.append(full_obj_name + ":" + obj[9])

        # Parameter Table
        if param_found == 1:
            param_list = LIST_PARAM
            for value in param_list:
                val = value.split(":")
                if val[1] == table_name:
                    parent_obj = val[0]

                    param = line.rstrip('\n').split(",")
                    param_name = parent_obj + param[0].replace("{", "").replace(
                        "\"", "").replace("BBF_VENDOR_PREFIX", BBF_VENDOR_PREFIX).replace(" ", "")
                    param_permission = param[1].replace("&", "").replace(" ", "")
                    param_type = param[2].replace(" ", "")
                    param_protocol = param[5].replace("}", "").replace(" ", "")

                    LIST_SUPPORTED_DM.append(
                        "{\"param\":\"" + param_name + "\",\"permission\":\"" + param_permission + "\",\"type\":\"" + param_type + "\",\"protocol\":\"" + param_protocol + "\"}")
                    if value not in LIST_DEL_PARAM:
                        LIST_DEL_PARAM.append(value)

    fp.close()


def generate_dynamic_datamodel_tree(filename):
    if filename.endswith('.c') is False:
        return

    obj_found = 0

    fp = open(filename, 'r', encoding='utf-8')
    for line in fp:
        line = line.lstrip()

        if line.startswith(tuple(LIST_IGNORED_LINE)) is True:
            continue

        if "DM_MAP_OBJ" in line:
            obj_found = 1
            continue

        if obj_found == 0:
            continue
        
        if "{0}" in line.replace(" ", ""):
            obj_found = 0
            continue

        # Object Table
        if obj_found == 1:
            obj = line.rstrip('\n').split(", ")
            obj_name = obj[0][1:].replace("\"", "").replace(" ", "").replace("BBF_VENDOR_PREFIX", BBF_VENDOR_PREFIX)

            if obj[1] != "NULL":
                LIST_OBJ.append(obj_name + ":" + obj[1])

            if obj[2] != "NULL":
                LIST_PARAM.append(obj_name + ":" + obj[2].replace("},", "").replace(" ", ""))

    fp.close()


def parse_dynamic_json_datamodel_tree(obj, value):
    obj_permission = "DMWRITE" if get_option_value(
        value, "access") is True else "DMREAD"
    obj_protocols = get_protocol_from_json(value)
    obj_description = get_description_from_json(value)

    obj_name = obj.replace("{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX)
    LIST_SUPPORTED_DM.append("{\"param\":\"" + obj_name + "\",\"permission\":\"" + obj_permission + "\",\"type\":\"DMT_OBJ\",\"protocol\":\"" + obj_protocols + "\",\"description\":\"" + obj_description + "\"}")

    hasobj = obj_has_child(value)
    hasparam = obj_has_param(value)

    if hasparam and isinstance(value, dict):
        for k, v in value.items():
            if k != "mapping" and isinstance(v, dict):
                for k1, v1 in v.items():
                    if k1 == "type" and v1 != "object":
                        param_name = obj_name + k.replace("{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX)
                        param_type = get_param_type(v)
                        param_permission = "DMWRITE" if get_option_value(
                            v, "write") is True else "DMREAD"
                        param_protocols = get_protocol_from_json(v)
                        param_list = get_list_from_json(v)
                        param_enums = get_enum_from_json(v)
                        param_desc = get_description_from_json(v)
                        param_range = get_range_from_json(v)

                        LIST_SUPPORTED_DM.append(
                            "{\"param\":\"" + param_name + "\",\"permission\":\"" + param_permission + "\",\"type\":\"" + param_type + "\",\"protocol\":\"" + param_protocols + "\",\"description\":\"" + param_desc + "\",\"list\":" + json.dumps(param_list) + ",\"range\":" + json.dumps(param_range) + ",\"enum\":" + json.dumps(param_enums) + "}")
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

    json_file = open(filename, "r", encoding='utf-8')
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
            vendor_dir = f'vendor/{vendor}/tr181'
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

            vendor_dir = f'vendor/{vendor}/tr104'
            if os.path.isdir(vendor_dir):
                cd_dir(vendor_dir)

                for _root, _dirs, files in os.walk("."):
                    for filename in files:
                        if filename.endswith('.c') is False:
                            continue

                        generate_datamodel_tree(filename)

                cd_dir(BBF_DMTREE_PATH)

    ############## Download && Generate Plugins Data Models ##############
    global BBF_ERROR_CODE
    if plugins is not None and isinstance(plugins, list) and plugins:
        print("Generating datamodels from defined plugins...")

        cd_dir(CURRENT_PATH)
        if isinstance(plugins, list):
            for plugin in plugins:
                proto = get_option_value(plugin, "proto")
                repo = get_option_value(plugin, "repo")

                if repo is None:
                    BBF_ERROR_CODE += 1
                    continue

                if proto is not None and proto == "local":
                    print(f' - Processing plugin: {plugin} at {repo}')

                    if os.path.isdir(f"{repo}"):
                        print(f'    Processing {repo}')
                        
                        dm_files = get_option_value(plugin, "dm_files")
                        if dm_files is not None and isinstance(dm_files, list):
                            for dm_file in dm_files:
                                if os.path.isfile(f"{repo}/{dm_file}"):
                                    generate_dynamic_datamodel_tree(f"{repo}/{dm_file}")
                                    generate_datamodel_tree(f"{repo}/{dm_file}")
                                    generate_dynamic_json_datamodel_tree(f"{repo}/{dm_file}")
                                else:
                                    BBF_ERROR_CODE += 1  
                        else:
                            files = os.popen(f'find {repo}/ -name datamodel.c').read()
                            for file in files.split('\n'):
                                if os.path.isfile(file):
                                    generate_dynamic_datamodel_tree(file)
                                    generate_datamodel_tree(file)
                            
                            files = os.popen(f'find {repo}/ -name "*.json"').read()
                            for file in files.split('\n'):
                                if os.path.isfile(file):
                                    generate_dynamic_json_datamodel_tree(file)
                    else:
                        print(f'    {repo} is not a  directory !!!!!')
                        BBF_ERROR_CODE += 1

                else:
                    print(f' - Processing plugin: {plugin}')
                    
                    version = get_option_value(plugin, "version")

                    remove_folder(".repo")
                    try:
                        subprocess.run(["git", "clone", repo, ".repo"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check = True)
                    except (OSError, subprocess.SubprocessError) as _e:
                        print(f'    Failed to clone {repo} !!!!!')
                        BBF_ERROR_CODE += 1
    
                    if version is not None:
                        try:
                            subprocess.run(["git", "-C", ".repo", "checkout", version],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                        except (OSError, subprocess.SubprocessError) as _e:
                            print(f'    Failed to checkout git version {version} !!!!!')
                            BBF_ERROR_CODE += 1
    
                    if os.path.isdir(".repo"):
                        if version is None:
                            print(f'    Processing {repo}')
                        else:
                            print(f'    Processing {repo}^{version}')
    
                        dm_files = get_option_value(plugin, "dm_files")
                        if dm_files is not None and isinstance(dm_files, list):
                            for dm_file in dm_files:
                                if os.path.isfile(".repo/" + dm_file):
                                    generate_dynamic_datamodel_tree(".repo/" + dm_file)
                                    generate_datamodel_tree(".repo/" + dm_file)
                                    generate_dynamic_json_datamodel_tree(".repo/" + dm_file)
                                else:
                                    BBF_ERROR_CODE += 1
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
                    else:
                        BBF_ERROR_CODE += 1

        print('Generating of plugins done')

    ############## Remove Duplicated Element from List ##############
    global LIST_SUPPORTED_DM
    LIST_SUPPORTED_DM = list(set(LIST_SUPPORTED_DM))

    ############## Sort all elements in List ##############
    LIST_SUPPORTED_DM.sort(reverse=False)

    ### Reorganize objects and params based on parent-child ###
    reorganize_parent_child()

    ############## Back to the current directory ##############
    cd_dir(CURRENT_PATH)

    ############### COPY SUPPORTED DATA MODEL TO FILE ###############
    remove_file(DATA_MODEL_FILE)
    fill_data_model_file()


def get_param_info_from_json(data, dm_json_files=None, info="description"):
    arr = data.split(".")
    list_data = []
    if len(arr) == 0:
        return None

    for i in range(0, len(arr)):
        string = ""
        if i == 0:
            string=arr[i] + "."
        elif i == (len(arr) - 1):
            string=arr[i]
        else:
            for j in range(0, i + 1):
                string=string + arr[j]
                string=string + "."

        if len(string) != 0:
            list_data.append(string)

    if len(list_data) == 0:
        return None

    found = False
    res = None
    if dm_json_files is not None and isinstance(dm_json_files, list) and dm_json_files:
        for fl in dm_json_files:
            if os.path.exists(fl):
                f = open(fl, 'r', encoding='utf-8')
                try:
                    ob = json.load(f)
                except json.decoder.JSONDecodeError:
                    continue

                index = -1
                for key in ob.keys():
                    if key in list_data:
                        index = list_data.index(key)
                        break

                if index == -1:
                    continue

                for i in range(index, len(list_data)):
                    if i != (len(list_data) - 1) and list_data[i + 1] == list_data[i] + "{i}.":
                        continue
                    try:
                        if str(list_data[i]).find(BBF_VENDOR_PREFIX) != -1:
                            param = str(list_data[i]).replace(BBF_VENDOR_PREFIX, "{BBF_VENDOR_PREFIX}")
                        else:
                            param = str(list_data[i])

                        ob = ob[param]
                        found = True
                    except KeyError:
                        found = False
                        break

                if found is True:
                    try:
                        res = ob[info]
                        break
                    except KeyError:
                        res = None

    return res

