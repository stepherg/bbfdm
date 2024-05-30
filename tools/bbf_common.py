#!/usr/bin/python3

# Copyright (C) 2024 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

import sys
import os
import subprocess
import shutil
import json
import glob

# Constants
BBF_ERROR_CODE = 0
CURRENT_PATH = os.getcwd()
DM_JSON_FILE = os.path.join(CURRENT_PATH, "libbbfdm", "dmtree", "json", "datamodel.json")

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


def rename_file(old_path, new_path):
    try:
        os.rename(old_path, new_path)
    except OSError:
        pass


def move_file(source_path, destination_path):
    shutil.move(source_path, destination_path)


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


def rmtree_handler(_func, path, _exc_info):
    print(f'Failed to remove {path}')


def remove_folder(folder_path):
    if os.path.isdir(folder_path):
        shutil.rmtree(folder_path, onerror=rmtree_handler)


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


def get_vendor_list(val):
    vendor_list = ""
    if isinstance(val, list):
        for vendor in val:
            vendor_list = vendor if not vendor_list else (
                vendor_list + "," + vendor)
    return vendor_list


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


def clear_list(input_list):
    input_list.clear()


def generate_shared_library(output_library, source_files, vendor_prefix, extra_dependencies):
    # Return if source_files (list) is empty
    if len(source_files) == 0:
        return

    # Set vendor prefix
    if vendor_prefix is not None:
        VENDOR_PREFIX = vendor_prefix
    else:
        VENDOR_PREFIX = "X_IOPSYS_EU_"

    # Ensure that the source files exist
    for source_file in source_files:
        if not os.path.exists(source_file):
            print(f"     Error: Source file {source_file} does not exist.")
            return False

    cmd = ['gcc', '-shared', '-o', output_library, '-fPIC', '-DBBF_VENDOR_PREFIX=\\"{}\\"'.format(VENDOR_PREFIX)] + source_files + extra_dependencies
    # Compile the shared library
    try:
        cmdstr = ' '.join(str(e) for e in cmd)
        subprocess.run(cmdstr, shell=True, check=True)
        print(f"     Shared library {output_library} successfully created.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"     Error during compilation: {e}")
        return False


def build_and_install_bbfdm(vendor_prefix, vendor_list):
    print("Compiling and installing bbfdmd in progress ...")

    create_folder(os.path.join(CURRENT_PATH, "build"))
    cd_dir(os.path.join(CURRENT_PATH, "build"))

    # Set vendor prefix
    if vendor_prefix is not None:
        VENDOR_PREFIX = vendor_prefix
    else:
        VENDOR_PREFIX = "X_IOPSYS_EU_"

    # Set vendor list
    if vendor_list is None:
        VENDOR_LIST = "iopsys"
    else:
        VENDOR_LIST = get_vendor_list(vendor_list)

    # Build and install bbfdm
    cmake_command = [
        "cmake",
        "../",
        "-DBBF_SCHEMA_FULL_TREE=ON",
        f"-DBBF_VENDOR_LIST={VENDOR_LIST}",
        f"-DBBF_VENDOR_PREFIX={VENDOR_PREFIX}",
        "-DBBF_MAX_OBJECT_INSTANCES=255",
        "-DBBFDMD_MAX_MSG_LEN=1048576",
        "-DCMAKE_INSTALL_PREFIX=/"
    ]
    make_command = ["make"]
    make_install_command = ["make", "install"]

    try:
        subprocess.check_call(cmake_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(make_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(make_install_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"Error running commands: {e}")
        sys.exit(1)

    cd_dir(CURRENT_PATH)
    remove_folder(os.path.join(CURRENT_PATH, "build"))
    print('Compiling and installing bbfdmd done')


def create_bbfdm_input_json_file(proto):
    data = {
        "daemon": {
        },
        "cli": {
            "config": {
                "proto": proto,
                "instance_mode": 0
            },
            "input": {
                "type": "DotSo",
                "name": "/usr/share/bbfdm/libbbfdm.so",
                "plugin_dir": "/usr/share/bbfdm/plugins"
            },
            "output": {
                "type": "CLI"
            }
        }
    }
    
    file_path = '/tmp/bbfdm/input.json'
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Open the file in 'w' mode (create or truncate)
    with open(file_path, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=4)


def fill_list_dm(proto, dm_list):
    create_bbfdm_input_json_file(proto)
    
    command = "bbfdmd -c schema Device."
    try:
        # Run the command
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        
        # Get the output from the result
        output = result.stdout

        # Split the output into lines
        lines = output.strip().split('\n')
        
        # Iterate through each line and parse the information
        for line in lines:
            parts = line.split()
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
        # Handle subprocess errors here
        print(f"Error running command: {e}")
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


def fill_list_supported_dm():

    fill_list_dm("usp", LIST_SUPPORTED_USP_DM)
    LIST_SUPPORTED_USP_DM.sort(key=lambda x: x['param'], reverse=False)
    LIST_SUPPORTED_USP_DM[:] = remove_duplicate_elements(LIST_SUPPORTED_USP_DM)

    fill_list_dm("cwmp", LIST_SUPPORTED_CWMP_DM)
    LIST_SUPPORTED_CWMP_DM.sort(key=lambda x: x['param'], reverse=False)
    LIST_SUPPORTED_CWMP_DM[:] = remove_duplicate_elements(LIST_SUPPORTED_CWMP_DM)


def clone_git_repository(repo, version=None):
    repo_path='.repo/'+os.path.basename(repo)
    if os.path.exists(repo_path):
        print(f'    {repo} already exists at {repo_path} !')
        return True
    try:
        cmd = ["git", "clone", repo, repo_path]
        if version is not None:
            cmd.extend(["-b", version])
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        print(f'    Failed to clone {repo} !!!!!')
        return False


def get_repo_version_info(repo, version=None):
    if version is None:
        return repo
    return f'{repo}^{version}'


def download_and_build_plugins(plugins, vendor_prefix):
    global BBF_ERROR_CODE

    if plugins is None or not isinstance(plugins, list) or not plugins:
        print("No plugins provided.")
        return

    print("Generating data models from defined plugins...")

    remove_folder(".repo")

    for plugin_index, plugin in enumerate(plugins):

        repo = get_option_value(plugin, "repo")
        proto = get_option_value(plugin, "proto")
        dm_files = get_option_value(plugin, "dm_files")
        extra_dependencies = get_option_value(plugin, "extra_dependencies", [])
        repo_path = None

        if repo is None or proto is None or dm_files is None or not isinstance(dm_files, list):
            print("Necessary input missing")
            BBF_ERROR_CODE += 1
            continue

        print(f' - Processing plugin: {plugin}')

        if proto == "git":
            repo_path = ".repo/"+os.path.basename(repo)
            version = get_option_value(plugin, "version")


            if not clone_git_repository(repo, version):
                print(f"Failed to clone {repo}")
                BBF_ERROR_CODE += 1
                continue
                
            print(f'    Processing {get_repo_version_info(repo, version)}')
        elif proto == "local":
            repo_path = repo
            print(f'    Processing {get_repo_version_info(repo, proto)}')
            
        if repo_path is None:
            print("Repository path not defined!!!")
            BBF_ERROR_CODE += 1
            continue			

        LIST_FILES = []
        os.chdir(repo_path)
        for dm_file in dm_files:
            filename = dm_file
            if filename.endswith('*.c'):
                LIST_FILES.extend(glob.glob(filename))
            else:
                if os.path.isfile(filename):
                    if filename.endswith('.c'):
                        LIST_FILES.append(filename)
                    elif filename.endswith('.json'):
                        move_file(filename, "/usr/share/bbfdm/plugins")
                    else:
                        print(f"Unknown file format {filename}")
                        BBF_ERROR_CODE += 1
                else:
                    print(f"Error: File not accessible {filename} !!!!!!")
                    BBF_ERROR_CODE += 1

        if len(LIST_FILES) > 0:
            if not generate_shared_library(f"/usr/share/bbfdm/plugins/lib{plugin_index}.so", LIST_FILES, vendor_prefix, extra_dependencies):
                BBF_ERROR_CODE += 1

        clear_list(LIST_FILES)
        cd_dir(CURRENT_PATH)

    print('Generating plugins completed.')


def generate_supported_dm(vendor_prefix=None, vendor_list=None, plugins=None):
    '''
    Generates supported data models and performs necessary actions.

    Args:
        vendor_prefix (str, optional): Vendor prefix for shared libraries.
        vendor_list (list, optional): List of vendor data models.
        plugins (list, optional): List of plugin configurations.
    '''

    # Build && Install bbfdm
    build_and_install_bbfdm(vendor_prefix, vendor_list)

    # Download && Build Plugins Data Models
    download_and_build_plugins(plugins, vendor_prefix)

    # Fill the list supported data model
    fill_list_supported_dm()

