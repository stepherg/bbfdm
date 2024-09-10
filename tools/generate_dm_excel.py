#!/usr/bin/python3

# Copyright (C) 2024 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

from collections import OrderedDict

import os
import sys
import json
import argparse
import xlwt
import bbf_common as bbf

LIST_USP_DM = []
LIST_CWMP_DM = []

def is_dm_supported(supported_dm_list, dmobject):
    for entry in supported_dm_list:
        param = entry.get("param")
        if param == dmobject:
            supported_dm_list.remove(entry)
            return "Yes"
    return "No"


def add_data_to_list_dm(dm_list, obj, supported, obsoleted):
    dm_list.append(obj + "," + supported + "," + obsoleted)

def parse_standard_object(list_read, list_write, dmobject, value, proto):
    hasobj = bbf.obj_has_child(value)
    hasparam = bbf.obj_has_param(value)

    if bbf.is_proto_exist(value, proto) is True:
        supported = is_dm_supported(list_read, dmobject)
        obsolete = bbf.get_option_value(value, "obsolete", False)
        add_data_to_list_dm(list_write, dmobject, supported, "Yes" if obsolete else "No")
    
        if hasparam:
            if isinstance(value, dict):
                for k, v in value.items():
                    if k == "mapping":
                        continue
                    if isinstance(v, dict):
                        for k1, v1 in v.items():
                            if k1 == "type" and v1 != "object":
                                if bbf.is_proto_exist(v, proto) is False:
                                    continue
                                supported = is_dm_supported(list_read, dmobject + k)
                                obsolete = bbf.get_option_value(v, "obsolete", False)
                                add_data_to_list_dm(list_write, dmobject + k, supported, "Yes" if obsolete else "No")
                                break
    
        if hasobj:
            if isinstance(value, dict):
                for k, v in value.items():
                    if isinstance(v, dict):
                        for k1, v1 in v.items():
                            if k1 == "type" and v1 == "object":
                                parse_standard_object(list_read, list_write, k, v, proto)
                            

def parse_vendor_object(list_read, list_write):
    for entry in list_read:
        param = entry.get("param")
        add_data_to_list_dm(list_write, param, "Yes", "No")
    

def parse_object(list_read, list_write, proto):
    with open(bbf.DM_JSON_FILE, "r", encoding='utf-8') as file:
        data = json.load(file, object_pairs_hook=OrderedDict)
        if data is not None:
            for obj, value in data.items():
                if obj is None:
                    print(f'!!!! {bbf.DM_JSON_FILE} : Wrong JSON Data model format!')
                else:
                    parse_standard_object(list_read, list_write, obj, value, proto)

    parse_vendor_object(list_read, list_write)


def parse_object_tree():
    # Usage for USP Data Model
    LIST_SUPPORTED_USP_DM = bbf.LIST_SUPPORTED_USP_DM
    parse_object(LIST_SUPPORTED_USP_DM, LIST_USP_DM, "usp")
    
    # Usage for CWMP Data Model
    LIST_SUPPORTED_CWMP_DM = bbf.LIST_SUPPORTED_CWMP_DM[:]
    parse_object(LIST_SUPPORTED_CWMP_DM, LIST_CWMP_DM, "cwmp")

def generate_excel_sheet(sheet, title, data, style_mapping):
    style_title = style_mapping["title"]
    style_default = style_mapping["default"]
    style_suffix = style_mapping["suffix"]
    style_obsolete_name = style_mapping["obsolete_name"]
    style_obsolete = style_mapping["obsolete"]

    sheet.write(0, 0, title, style_title)
    sheet.write(0, 1, 'Supported', style_title)

    for i, value in enumerate(data):
        param = value.split(",")
        suffix = None

        for suffix_candidate, suffix_style in style_suffix.items():
            if param[0].endswith(suffix_candidate):
                suffix = suffix_style
                break

        if param[2] == "Yes":
            style_name, style = style_obsolete_name, style_obsolete
        else:
            style_name, style = suffix or (None, style_default)

        if style_name is not None:
            sheet.write(i + 1, 0, param[0], style_name)
        else:
            sheet.write(i + 1, 0, param[0])

        sheet.write(i + 1, 1, param[1], style)

    sheet.col(0).width = 1300 * 20
    sheet.col(1).width = 175 * 20


def generate_excel_file(output_file):
    bbf.remove_file(output_file)

    LIST_USP_DM.sort(reverse=False)
    LIST_CWMP_DM.sort(reverse=False)

    wb = xlwt.Workbook(style_compression=2)

    xlwt.add_palette_colour("custom_colour_yellow", 0x10)
    xlwt.add_palette_colour("custom_colour_green", 0x20)
    xlwt.add_palette_colour("custom_colour_grey", 0x30)
    xlwt.add_palette_colour("custom_colour_obsolete", 0x08)
    
    wb.set_colour_RGB(0x10, 255, 255, 153)
    wb.set_colour_RGB(0x20, 102, 205, 170)
    wb.set_colour_RGB(0x30, 153, 153, 153)
    wb.set_colour_RGB(0x08, 221, 221, 221)

    style_mapping = {
        "title": xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_grey;' +
                             'font: bold 1, color black;' + 'alignment: horizontal center;'),
        "default": xlwt.easyxf('alignment: horizontal center;'),
        "obsolete_name": xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_obsolete'),
        "obsolete": xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_obsolete;' +
                             'alignment: horizontal center;'),
        "suffix": {
            ".": (xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_yellow'),
                  xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_yellow;' +
                              'alignment: horizontal center;')),
            "()" : (xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green'),
                    xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green;' +
                                'alignment: horizontal center;')),
            "!" : (xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green'),
                   xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green;' +
                               'alignment: horizontal center;')),
        }
    }
    
    usp_sheet = wb.add_sheet('USP')
    generate_excel_sheet(usp_sheet, 'OBJ/PARAM/OPERATE/EVENT', LIST_USP_DM, style_mapping)

    cwmp_sheet = wb.add_sheet('CWMP')
    generate_excel_sheet(cwmp_sheet, 'OBJ/PARAM', LIST_CWMP_DM, style_mapping)

    wb.save(output_file)


def generate_excel(output_file="datamodel.xml"):
    print("Generating BBF Data Models in Excel format...")

    parse_object_tree()
    generate_excel_file(output_file)

    if os.path.isfile(output_file):
        print(f' - Excel file generated: {output_file}')
    else:
        print(f' - Error in excel file generation {output_file}')


### main ###
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to generate list of supported and non-supported parameter in xls format',
        epilog='Part of BBF-tools, refer Readme for more examples'
    )

    parser.add_argument(
        '-r', '--remote-dm',
        action='append',
		metavar = 'git^https://dev.iopsys.eu/bbf/stunc.git^devel',
        help= 'Includes OBJ/PARAM defined under remote repositories defined as bbf plugin'
    )

    parser.add_argument(
        '-p', '--vendor-prefix',
		default = 'X_IOPSYS_EU_',
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
            r["proto"] = x[0]
            if len(x) > 1:
                r["repo"] = x[1]
            if len(x) == 3:
                r["version"] = x[2]

            plugins.append(r)

    bbf.generate_supported_dm(args.vendor_prefix, plugins)
    generate_excel(args.output)
    print(f'Datamodel generation completed, aritifacts available in {args.output}')
    sys.exit(bbf.BBF_ERROR_CODE)
