#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

from collections import OrderedDict

import os
import json
import argparse
import xlwt
import bbf_common as bbf


LIST_DM = []

def getprotocols(value):
    if isinstance(value, dict):
        for obj, val in value.items():
            if obj == "protocols" and isinstance(val, list):
                if len(val) == 2:
                    return "CWMP+USP"
                elif val[0] == "usp":
                    return "USP"
                else:
                    return "CWMP"
    return "CWMP+USP"


def check_param_obj_command(dmobject):
    for value in bbf.LIST_SUPPORTED_DM:
        obj = value.split(",")
        if obj[0] == dmobject:
            bbf.LIST_SUPPORTED_DM.remove(value)
            return "Yes"
    return "No"


def add_data_to_list_dm(obj, supported, protocols, types):
    LIST_DM.append(obj + "," + protocols + "," + supported + "," + types)


def parse_standard_object(dmobject, value):
    hasobj = bbf.obj_has_child(value)
    hasparam = bbf.obj_has_param(value)

    supported = check_param_obj_command(dmobject)
    add_data_to_list_dm(dmobject, supported, getprotocols(value), "object")

    if hasparam:
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "mapping":
                    continue
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if k1 == "type" and v1 != "object":
                            supported = check_param_obj_command(dmobject + k)
                            add_data_to_list_dm(dmobject + k, supported, getprotocols(v), "operate" if "()" in k else "parameter")
                            break

    if hasobj:
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if k1 == "type" and v1 == "object":
                            parse_standard_object(k, v)


def parse_dynamic_object(dm_name_list):
    if isinstance(dm_name_list, list) is False:
        return None

    for value in bbf.LIST_SUPPORTED_DM:
        obj = value.split(",")

        for dm in dm_name_list:

            JSON_FILE = bbf.ARRAY_JSON_FILES.get(dm, None)

            if JSON_FILE is None:
                continue

            if dm == "tr181" and ".Services." in obj[0]:
                continue

            if dm == "tr104" and ".Services." not in obj[0]:
                continue

            if dm == "tr135" and ".Services." not in obj[0]:
                continue

            dmType = "object" if obj[2] == "DMT_OBJ" else "parameter"
            add_data_to_list_dm(obj[0], "Yes", "CWMP+USP", dmType)


def parse_object_tree(dm_name_list):
    if isinstance(dm_name_list, list) is False:
        return None

    for dm in dm_name_list:

        JSON_FILE = bbf.ARRAY_JSON_FILES.get(dm, None)

        if JSON_FILE is not None:
            file = open(JSON_FILE, "r")
            data = json.loads(file.read(), object_pairs_hook=OrderedDict)

            for obj, value in data.items():
                if obj is None:
                    print("!!!! %s : Wrong JSON Data model format!" % dm)
                    continue

                parse_standard_object(obj, value)
        else:
            print("!!!! %s : Data Model doesn't exist" % dm)

    parse_dynamic_object(dm_name_list)


def generate_excel_file(output_file):
    bbf.remove_file(output_file)

    LIST_DM.sort(reverse=False)

    wb = xlwt.Workbook(style_compression=2)
    sheet = wb.add_sheet('CWMP-USP')

    xlwt.add_palette_colour("custom_colour_yellow", 0x10)
    xlwt.add_palette_colour("custom_colour_green", 0x20)
    xlwt.add_palette_colour("custom_colour_grey", 0x30)

    wb.set_colour_RGB(0x10, 255, 255, 153)
    wb.set_colour_RGB(0x20, 102, 205, 170)
    wb.set_colour_RGB(0x30, 153, 153, 153)

    style_title = xlwt.easyxf(
        'pattern: pattern solid, fore_colour custom_colour_grey;''font: bold 1, color black;''alignment: horizontal center;')
    sheet.write(0, 0, 'OBJ/PARAM/OPERATE', style_title)
    sheet.write(0, 1, 'Protocols', style_title)
    sheet.write(0, 2, 'Supported', style_title)

    i = 0
    for value in LIST_DM:
        param = value.split(",")
        i += 1

        if param[3] == "object":
            style_name = xlwt.easyxf(
                'pattern: pattern solid, fore_colour custom_colour_yellow')
            style = xlwt.easyxf(
                'pattern: pattern solid, fore_colour custom_colour_yellow;''alignment: horizontal center;')
        elif param[3] == "operate":
            style_name = xlwt.easyxf(
                'pattern: pattern solid, fore_colour custom_colour_green')
            style = xlwt.easyxf(
                'pattern: pattern solid, fore_colour custom_colour_green;''alignment: horizontal center;')
        else:
            style_name = None
            style = xlwt.easyxf('alignment: horizontal center;')

        if style_name is not None:
            sheet.write(i, 0, param[0], style_name)
        else:
            sheet.write(i, 0, param[0])

        sheet.write(i, 1, param[1], style)
        sheet.write(i, 2, param[2], style)

    sheet.col(0).width = 1300*20
    sheet.col(1).width = 175*20
    sheet.col(2).width = 175*20

    wb.save(output_file)


def generate_excel(dm_name_list, output_file="datamodel.xml"):
    print("Generating BBF Data Models in Excel format...")

    bbf.fill_list_supported_dm()
    parse_object_tree(dm_name_list)
    generate_excel_file(output_file)

    if os.path.isfile(output_file):
        print("└── Excel file generated: %s" % output_file)
    else:
        print("└── Error in excel file generation %s" % output_file)


### main ###
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to generate list of supported and non-supported parameter in xls format',
        epilog='Part of BBF-tools, refer Readme for more examples'
    )

    parser.add_argument(
        '-d', '--datamodel',
        action = 'append',
        metavar='tr181',
        choices= ['tr181', 'tr104'],
        required= True,
    )

    parser.add_argument(
        '-r', '--remote-dm',
        action='append',
		metavar = 'https://dev.iopsys.eu/iopsys/stunc.git^devel',
        help= 'Includes OBJ/PARAM defined under remote repositories defined as bbf plugin'
    )

    parser.add_argument(
        '-v', '--vendor-list',
        metavar='iopsys',
        action = 'append',
        help='Generate data model tree with vendor extension OBJ/PARAM'
    )

    parser.add_argument(
        '-p', '--vendor-prefix',
		default = 'iopsys',
		metavar = 'X_IOPSYS_EU_',
		help = 'Generate data model tree using provided vendor prefix for vendor defined objects'
    )

    parser.add_argument(
        '-o', '--output',
        default = "datamodel.xls",
        metavar = "supported_datamodel.xls",
		help = 'Generate the output file with given name'
    )

    args = parser.parse_args()
    plugins = []

    if isinstance(args.remote_dm, list) is True:
        for f in args.remote_dm:
            x = f.split('^')
            r = {}
            r["repo"] = x[0]
            if len(x) == 2:
                r["version"] = x[1]

            plugins.append(r)

    bbf.generate_supported_dm(args.vendor_prefix, args.vendor_list, plugins)
    bbf.clean_supported_dm_list()
    generate_excel(args.datamodel, args.output)
    print("Datamodel generation completed, aritifacts available in %s" %args.output)
