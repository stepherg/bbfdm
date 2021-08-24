#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import sys
import json
import bbf_common as bbf
import generate_dm_xml as bbf_xml
import generate_dm_excel as bbf_excel


def print_dm_usage():
    print("Usage: " + sys.argv[0] + " <input json file>")
    print("Examples:")
    print("  - " + sys.argv[0] + " tools_input.json")
    print("    ==> Generate all required files defined in tools_input.json file")
    print("")
    exit(1)


def get_vendor_list(val):
    vendor_list = ""
    if isinstance(val, list):
        for vendor in val:
            vendor_list = vendor if not vendor_list else (
                vendor_list + "," + vendor)
    return vendor_list


### main ###
if len(sys.argv) < 2:
    print_dm_usage()

VENDOR_PREFIX = None
VENDOR_LIST = None
PLUGINS = None
OUTPUT = None

json_file = open(sys.argv[1], "r", encoding='utf-8')
json_data = json.loads(json_file.read())

for option, value in json_data.items():
    if option is None:
        print("!!!! %s : Wrong JSON format!" % sys.argv[1])
        exit(1)

    if option == "manufacturer":
        bbf_xml.MANUFACTURER = value
        continue

    if option == "protocol":
        bbf_xml.DEVICE_PROTOCOL = value
        continue

    if option == "manufacturer_oui":
        bbf_xml.MANUFACTURER_OUI = value
        continue

    if option == "product_class":
        bbf_xml.PRODUCT_CLASS = value
        continue

    if option == "model_name":
        bbf_xml.MODEL_NAME = value
        continue

    if option == "software_version":
        bbf_xml.SOFTWARE_VERSION = value
        continue

    if option == "vendor_prefix":
        VENDOR_PREFIX = value
        continue

    if option == "vendor_list":
        VENDOR_LIST = value
        continue

    if option == "plugins":
        PLUGINS = value
        continue

    if option == "output":
        OUTPUT = value
        continue

bbf.generate_supported_dm(VENDOR_PREFIX, VENDOR_LIST, PLUGINS)

file_format = bbf.get_option_value(OUTPUT, "file_format", ['xml'])
output_file_prefix = bbf.get_option_value(OUTPUT, "output_file_prefix", "datamodel")
output_dir = bbf.get_option_value(OUTPUT, "output_dir", "./out")

bbf.create_folder(output_dir)

if isinstance(file_format, list):
    for _format in file_format:

        if _format == "xml":
            acs = bbf.get_option_value(OUTPUT, "acs", ['default'])
            if isinstance(acs, list):
                for acs_format in acs:

                    bbf.clean_supported_dm_list()
                    output_file_name = output_dir + '/' + output_file_prefix + '_' + acs_format + '.xml'
                    if acs_format == "hdm":
                        bbf_xml.generate_xml('HDM', output_file_name)

                    if acs_format == "default":
                        bbf_xml.generate_xml('default', output_file_name)


        if _format == "xls":
            bbf.clean_supported_dm_list()
            output_file_name = output_dir + '/' + output_file_prefix + '.xls'
            bbf_excel.generate_excel(['tr181', 'tr104'], output_file_name)

bbf.remove_file(bbf.DATA_MODEL_FILE)
print("Datamodel generation completed, aritifacts shall be available in out directory or as per input json configuration")
