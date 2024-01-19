#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import sys
import argparse
import xml.etree.ElementTree as ET
import xml.dom.minidom as MD
import bbf_common as bbf
import json

DM_OBJ_COUNT = 0
DM_PARAM_COUNT = 0
DEVICE_PROTOCOL = "DEVICE_PROTOCOL_DSLFTR069v1"
MANUFACTURER = "iopsys"
MANUFACTURER_OUI = "002207"
PRODUCT_CLASS = "DG400PRIME"
MODEL_NAME = "DG400PRIME-A"
SOFTWARE_VERSION = "1.2.3.4"

ARRAY_TYPES = [ "string",
                "unsignedInt",
                "unsignedLong",
                "int",
                "long",
                "boolean",
                "dateTime",
                "hexBinary",
                "base64"]

LIST_SUPPORTED_DM = []

def pretty_format(elem):
    elem_string = ET.tostring(elem, 'UTF-8')
    reparsed = MD.parseString(elem_string)
    return reparsed.toprettyxml(indent="  ")


def organize_parent_child(dm_list):
    organized_dm = []

    for parent_item in dm_list:
        parent_type = parent_item.get("type")
        if parent_type != "object":
            continue

        parent_name = parent_item.get("param")

        organized_dm.append(parent_item)

        for child_item in dm_list:
            child_type = child_item.get("type")
            if child_type is None or child_type == "object":
                continue

            child_name = child_item.get("param")

            if child_name.find(parent_name) != -1:
                parent_dot_count = parent_name.count('.')
                child_dot_count = child_name.count('.')
                if parent_dot_count == child_dot_count:
                    organized_dm.append(child_item)

    return organized_dm
    

def get_info_from_json(data, dm_json_files=None):
    entry = {}
    list_data = []
    
    arr = data.split(".")
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
        return entry

    found = False
    if dm_json_files is not None and isinstance(dm_json_files, list) and dm_json_files:
        for fl in dm_json_files:
            if os.path.exists(fl):
                fo = open(fl, 'r', encoding='utf-8')
                try:
                    ob = json.load(fo)
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
                        if str(list_data[i]).find("X_IOPSYS_EU_") != -1:
                            param = str(list_data[i]).replace("X_IOPSYS_EU_", "{BBF_VENDOR_PREFIX}")
                        else:
                            param = str(list_data[i])

                        ob = ob[param]
                        found = True
                    except KeyError:
                        found = False
                        break

                if found is True:
                    entry["description"] = ob['description'] if "description" in ob else None
                    entry["enumerations"] = ob['enumerations'] if "enumerations" in ob else None
                    entry["range"] = ob['range'] if "range" in ob else None
                    entry["list"] = ob["list"] if "list" in ob else None
                    break

    return entry


def generate_bbf_xml_file(output_file, dm_json_files=None):
    global DM_OBJ_COUNT
    global DM_PARAM_COUNT

    bbf.remove_file(output_file)
    root = ET.Element("dm:document")
    root.set("xmlns:dm", "urn:broadband-forum-org:cwmp:datamodel-1-8")
    root.set("xmlns:dmr", "urn:broadband-forum-org:cwmp:datamodel-report-0-1")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xsi:schemaLocation", "urn:broadband-forum-org:cwmp:datamodel-1-8 https://www.broadband-forum.org/cwmp/cwmp-datamodel-1-8.xsd urn:broadband-forum-org:cwmp:datamodel-report-0-1 https://www.broadband-forum.org/cwmp/cwmp-datamodel-report.xsd")
    root.set("spec", "urn:broadband-forum-org:tr-181-2-14-1-cwmp")
    root.set("file", "tr-181-2-17-0-cwmp-full.xml")

    model = ET.SubElement(root, "model")
    model.set("name", "Device:2.17")

    for entry in LIST_SUPPORTED_DM:
        name = entry.get("param")
        p_type = entry.get("type")
        access = entry.get("permission")
        
        info = get_info_from_json(name, dm_json_files)
        desc = info.get("description")
        list_ob = info.get("list")
        enum = info.get("enumerations")
        rang = info.get("range")

        if p_type == "object":
            # Object
            objec = ET.SubElement(model, "object")
            objec.set("name", name)
            objec.set("access", access)
            objec.set("minEntries", "0")
            objec.set("maxEntries", "20")

            ob_description = ET.SubElement(objec, "description")
            ob_description.text = desc.replace("<", "{").replace(">", "}") if desc is not None else ""

            DM_OBJ_COUNT += 1
        else:
            # Parameter
            subtype = None
            list_datatype = None
            parameter = ET.SubElement(objec, "parameter")
            parameter.set("name", name[name.rindex('.')+1:])
            parameter.set("access", access)

            p_description = ET.SubElement(parameter, "description")
            p_description.text = desc.replace("<", "{").replace(">", "}") if desc is not None else ""
            
            syntax = ET.SubElement(parameter, "syntax")

            if list_ob is not None and len(list_ob) != 0:
                listtag = ET.SubElement(syntax, "list")

                # Handle items in list
                item_ob = list_ob["item"] if "item" in list_ob else None

                if item_ob is not None:
                    minval = item_ob["min"] if "min" in item_ob else None
                    maxval = item_ob["max"]if "max" in item_ob else None

                    if minval is not None:
                        listtag.set("minItems", str(minval))

                    if maxval is not None:
                        listtag.set("maxItems", str(maxval))

                # Handle maxsize in list
                maxsize = list_ob["maxsize"] if "maxsize" in list_ob else None

                if maxsize is not None:
                    sizetag = ET.SubElement(listtag, "size")
                    sizetag.set("maxLength", str(maxsize))

                if enum is None or len(enum) == 0:
                    enum = list_ob["enumerations"] if "enumerations" in list_ob else None

                list_datatype = list_ob["datatype"] if "datatype" in list_ob else None

                if list_datatype is not None and list_datatype in ARRAY_TYPES:
                    subtype = ET.SubElement(syntax, list_datatype)
                else:
                    subtype = ET.SubElement(syntax, p_type)
            else:
                subtype = ET.SubElement(syntax, p_type)

            if enum is not None:
                for val in enum:
                    enumeration = ET.SubElement(subtype, "enumeration")
                    enumeration.set("value", str(val))

            # handle range
            if rang is None and list_ob is not None:
                rang = list_ob["range"] if "range" in list_ob else None

            if rang is not None and len(rang) != 0:
                for i in range(len(rang)):
                    range_min = rang[i]["min"] if "min" in rang[i] else None
                    range_max = rang[i]["max"] if "max" in rang[i] else None
                    val_type = list_datatype  if list_datatype is not None else p_type

                    if val_type == "string" or val_type == "hexBinary" or val_type == "base64":
                        size_tag = ET.SubElement(subtype, "size")
                        if range_min is not None:
                            size_tag.set("minLength", str(range_min))
                        if range_max is not None:
                            size_tag.set("maxLength", str(range_max))
                    if val_type == "unsignedInt" or val_type == "unsignedLong" or val_type == "int" or val_type == "long":
                        range_tag = ET.SubElement(subtype, "range")
                        if range_min is not None:
                            range_tag.set("minInclusive", str(range_min))
                        if range_max is not None:
                            range_tag.set("maxInclusive", str(range_max))

            DM_PARAM_COUNT += 1

    xml_file = open(output_file, "w", encoding='utf-8')
    xml_file.write(pretty_format(root))
    xml_file.close()


def generate_hdm_xml_file(output_file):
    global DM_OBJ_COUNT
    global DM_PARAM_COUNT

    bbf.remove_file(output_file)
    root = ET.Element("deviceType")
    root.set("xmlns", "urn:dslforum-org:hdm-0-0")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xsi:schemaLocation", "urn:dslforum-org:hdm-0-0 deviceType.xsd")

    protocol = ET.SubElement(root, "protocol")
    protocol.text = str(DEVICE_PROTOCOL)
    manufacturer = ET.SubElement(root, "manufacturer")
    manufacturer.text = str(MANUFACTURER)
    manufacturerOUI = ET.SubElement(root, "manufacturerOUI")
    manufacturerOUI.text = str(MANUFACTURER_OUI)
    productClass = ET.SubElement(root, "productClass")
    productClass.text = str(PRODUCT_CLASS)
    modelName = ET.SubElement(root, "modelName")
    modelName.text = str(MODEL_NAME)
    softwareVersion = ET.SubElement(root, "softwareVersion")
    softwareVersion.text = str(SOFTWARE_VERSION)
    dm_type = ET.SubElement(root, "type")
    dm_type.text = str("Device:2")

    dataModel = ET.SubElement(root, "dataModel")
    attributes = ET.SubElement(dataModel, "attributes")
    parameters = ET.SubElement(dataModel, "parameters")

    attribute_notification = ET.SubElement(attributes, "attribute")
    attributeName = ET.SubElement(attribute_notification, "attributeName")
    attributeName.text = str("notification")
    attributeType = ET.SubElement(attribute_notification, "attributeType")
    attributeType.text = str("int")
    minValue = ET.SubElement(attribute_notification, "minValue")
    minValue.text = str("0")
    maxValue = ET.SubElement(attribute_notification, "maxValue")
    maxValue.text = str("2")

    attribute_access_list = ET.SubElement(attributes, "attribute")
    attributeName = ET.SubElement(attribute_access_list, "attributeName")
    attributeName.text = str("accessList")
    attributeType = ET.SubElement(attribute_access_list, "attributeType")
    attributeType.text = str("string")
    array = ET.SubElement(attribute_access_list, "array")
    array.text = str("true")
    attributeLength = ET.SubElement(attribute_access_list, "attributeLength")
    attributeLength.text = str("64")

    attribute_visibility = ET.SubElement(attributes, "attribute")
    attributeName = ET.SubElement(attribute_visibility, "attributeName")
    attributeName.text = str("visibility")
    attributeType = ET.SubElement(attribute_visibility, "attributeType")
    attributeType.text = str("string")
    array = ET.SubElement(attribute_visibility, "array")
    array.text = str("true")
    attributeLength = ET.SubElement(attribute_visibility, "attributeLength")
    attributeLength.text = str("64")

    param_array = [ET.Element] * 15
    param_array[0] = parameters
    root_dot_count = 0

    for entry in LIST_SUPPORTED_DM:

        name = entry.get("param")
        p_type = entry.get("type")

        if p_type == "object":
            # Object
            obj_tag = ET.SubElement(param_array[name.replace(".{i}", "").count('.') - root_dot_count -1], "parameter")
            obj_name = ET.SubElement(obj_tag, "parameterName")
            obj_name.text = str(name.replace(".{i}", "").split('.')[-2])
            obj_type = ET.SubElement(obj_tag, "parameterType")
            obj_type.text = str("object")
            obj_array = ET.SubElement(obj_tag, "array")
            obj_array.text = str("true" if name.endswith(".{i}.") else "false")
            parameters = ET.SubElement(obj_tag, "parameters")
            param_array[name.replace(".{i}", "").count('.') - root_dot_count] = parameters
            DM_OBJ_COUNT += 1
        else:
            # Parameter
            param_tag = ET.SubElement(param_array[name.replace(".{i}", "").count('.') - root_dot_count], "parameter")
            param_name = ET.SubElement(param_tag, "parameterName")
            param_name.text = str(name[name.rindex('.')+1:])
            param_type = ET.SubElement(param_tag, "parameterType")
            param_type.text = str(p_type)
            DM_PARAM_COUNT += 1

    xml_file = open(output_file, "w", encoding='utf-8')
    xml_file.write(pretty_format(root))
    xml_file.close()

def generate_xml(acs = 'default', dm_json_files=None, output_file="datamodel.xml"):
    global LIST_SUPPORTED_DM
    global DM_OBJ_COUNT
    global DM_PARAM_COUNT

    DM_OBJ_COUNT = 0
    DM_PARAM_COUNT = 0

    LIST_SUPPORTED_DM = organize_parent_child(bbf.LIST_SUPPORTED_CWMP_DM)

    print(f'Generating BBF Data Models in xml format for {acs} acs...')

    if acs == "HDM":
        generate_hdm_xml_file(output_file)
    else:
        generate_bbf_xml_file(output_file, dm_json_files)

    if os.path.isfile(output_file):
        print(f' - XML file generated: {output_file}')
    else:
        print(' - Error in generating xml file')

    print(f' - Number of BBF Data Models objects is {DM_OBJ_COUNT}')
    print(f' - Number of BBF Data Models parameters is {DM_PARAM_COUNT}')

### main ###
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to generate list of supported and non-supported parameter in xml format',
        epilog='Part of BBF-tools, refer Readme for more examples'
    )

    parser.add_argument(
        '-r', '--remote-dm',
        action='append',
		metavar = 'git^https://dev.iopsys.eu/bbf/stunc.git^devel',
        help= 'Includes OBJ/PARAM defined under remote repositories defined as bbf plugin'
    )

    parser.add_argument(
        '-v', '--vendor-list',
        metavar='iopsys',
        action = 'append',
        help='Generate data model tree with vendor extension OBJ/PARAM.'
    )

    parser.add_argument(
        '-p', '--vendor-prefix',
		default = 'X_IOPSYS_EU_',
		metavar = 'X_IOPSYS_EU_',
		help = 'Generate data model tree using provided vendor prefix for vendor defined objects.'
    )

    parser.add_argument(
        '-d', '--device-protocol',
		default = 'DEVICE_PROTOCOL_DSLFTR069v1',
		metavar = 'DEVICE_PROTOCOL_DSLFTR069v1',
		help = 'Generate data model tree using this device protocol.'
    )

    parser.add_argument(
        "-m", "--manufacturer",
		default = 'IOPSYS',
		metavar = 'IOPSYS',
		help = 'Generate data model tree using this manufacturer.'
    )

    parser.add_argument(
        "-u", "--manufacturer-oui",
		default = '002207',
		metavar = '002207',
		help = 'Generate data model tree using this manufacturer oui.'
    )

    parser.add_argument(
        "-c", "--product-class",
		default = 'DG400PRIME',
		metavar = 'DG400PRIME',
		help = 'Generate data model tree using this product class.'
    )

    parser.add_argument(
        "-n", "--model-name",
		default = 'DG400PRIME-A',
		metavar = 'DG400PRIME-A',
		help = 'Generate data model tree using this model name.'
    )

    parser.add_argument(
        "-s", "--software-version",
		default = '1.2.3.4',
		metavar = '1.2.3.4',
		help = 'Generate data model tree using this software version.'
    )

    parser.add_argument(
        "-f", "--format",
		metavar = 'BBF',
        default = 'BBF',
        choices=['HDM', 'BBF', 'default'],
		help = 'Generate data model tree with HDM format.'
    )

    parser.add_argument(
        '-o', '--output',
        default = "datamodel.xml",
        metavar = "datamodel.xml",
		help = 'Generate the output file with given name'
    )

    args = parser.parse_args()
    MANUFACTURER = args.manufacturer
    DEVICE_PROTOCOL = args.device_protocol
    MANUFACTURER_OUI = args.manufacturer_oui
    PRODUCT_CLASS = args.product_class
    MODEL_NAME = args.model_name
    SOFTWARE_VERSION = args.software_version

    plugins = []

    if isinstance(args.remote_dm, list):
        for f in args.remote_dm:
            x = f.split('^')
            r = {}
            r["proto"] = x[0]
            if len(x) > 1:
                r["repo"] = x[1]
            if len(x) == 3:
                r["version"] = x[2]

            plugins.append(r)

    bbf.generate_supported_dm(args.vendor_prefix, args.vendor_list, plugins)
    generate_xml(args.format, args.dm_json_files, args.output)
    print(f'Datamodel generation completed, aritifacts available in {args.output}')
    sys.exit(bbf.BBF_ERROR_CODE)
