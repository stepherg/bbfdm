#!/usr/bin/python3

# Copyright (C) 2024 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

import sys
import json
import bbf_common as bbf
import generate_dm_xml as bbf_xml
import generate_dm_excel as bbf_excel
import glob


def print_dm_usage():
    print("Usage: " + sys.argv[0] + " <input json file>")
    print("Examples:")
    print("  - " + sys.argv[0] + " tools_input.json")
    print("    ==> Generate all required files defined in tools_input.json file")
    print("")
    exit(1)


### main ###
if len(sys.argv) < 2:
    print_dm_usage()

VENDOR_PREFIX = None
VENDOR_LIST = None
PLUGINS = None
OUTPUT = None
DM_JSON_FILES = None

json_file = open(sys.argv[1], "r", encoding='utf-8')
json_data = json.loads(json_file.read())

for option, value in json_data.items():
    if option is None:
        print("!!!! %s : Wrong JSON format!" % sys.argv[1])
        print_dm_usage()
        exit(1)

    elif option == "manufacturer":
        bbf_xml.MANUFACTURER = value
        continue

    elif option == "protocol":
        bbf_xml.DEVICE_PROTOCOL = value
        continue

    elif option == "manufacturer_oui":
        bbf_xml.MANUFACTURER_OUI = value
        continue

    elif option == "product_class":
        bbf_xml.PRODUCT_CLASS = value
        continue

    elif option == "model_name":
        bbf_xml.MODEL_NAME = value
        continue

    elif option == "software_version":
        bbf_xml.SOFTWARE_VERSION = value
        continue

    elif option == "vendor_prefix":
        VENDOR_PREFIX = value
        continue

    elif option == "vendor_list":
        VENDOR_LIST = value
        continue

    elif option == "dm_json_files":
        DM_JSON_FILES = value
        continue

    elif option == "plugins":
        PLUGINS = value
        continue

    elif option == "output":
        OUTPUT = value
        continue

    else:
        print_dm_usage()
        exit(1)

if OUTPUT is None:
    bbf.download_and_build_plugins(PLUGINS, VENDOR_PREFIX)
else:
    bbf.generate_supported_dm(VENDOR_PREFIX, VENDOR_LIST, PLUGINS)

    file_format = bbf.get_option_value(OUTPUT, "file_format", ['xml'])
    output_file_prefix = bbf.get_option_value(OUTPUT, "output_file_prefix", "datamodel")
    output_dir = bbf.get_option_value(OUTPUT, "output_dir", "./out")
    
    bbf.create_folder(output_dir)

    print("Dumping default DM_JSON_FILES")
    print(DM_JSON_FILES)
    DM_JSON_FILES.extend(glob.glob('/tmp/repo/dm_info/*.json'))
    print("Dumping all")
    print(DM_JSON_FILES)


    if isinstance(file_format, list):
        for _format in file_format:
    
            if _format == "xml":
                acs = bbf.get_option_value(OUTPUT, "acs", ['default'])
                if isinstance(acs, list):
                    for acs_format in acs:
    
                        output_file_name = output_dir + '/' + output_file_prefix + '_' + acs_format + '.xml'
                        if acs_format == "hdm":
                            bbf_xml.generate_xml('HDM', DM_JSON_FILES, output_file_name)
    
                        if acs_format == "default":
                            bbf_xml.generate_xml('default', DM_JSON_FILES, output_file_name)
    
            if _format == "xls":
                output_file_name = output_dir + '/' + output_file_prefix + '.xls'
                bbf_excel.generate_excel(output_file_name)
    
    print("Datamodel generation completed, aritifacts shall be available in out directory or as per input json configuration")

sys.exit(bbf.BBF_ERROR_CODE)
