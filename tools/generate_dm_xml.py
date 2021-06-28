#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import argparse
import xml.etree.ElementTree as ET
import xml.dom.minidom as MD
import bbf_common as bbf

DM_OBJ_COUNT = 0
DM_PARAM_COUNT = 0
DEVICE_PROTOCOL = "DEVICE_PROTOCOL_DSLFTR069v1"
MANUFACTURER = "iopsys"
MANUFACTURER_OUI = "002207"
PRODUCT_CLASS = "DG400PRIME"
MODEL_NAME = "DG400PRIME-A"
SOFTWARE_VERSION = "1.2.3.4"

ARRAY_TYPES = {"DMT_STRING": "string",
               "DMT_UNINT": "unsignedInt",
               "DMT_UNLONG": "unsignedLong",
               "DMT_INT": "int",
               "DMT_LONG": "long",
               "DMT_BOOL": "boolean",
               "DMT_TIME": "dateTime",
               "DMT_HEXBIN": "hexBinary",
               "DMT_BASE64": "base64"}


def pretty_format(elem):
    elem_string = ET.tostring(elem, 'UTF-8')
    reparsed = MD.parseString(elem_string)
    return reparsed.toprettyxml(indent="  ")


def generate_bbf_xml_file(output_file):
    global DM_OBJ_COUNT
    global DM_PARAM_COUNT

    bbf.remove_file(output_file)
    root = ET.Element("dm:document")
    root.set("xmlns:dm", "urn:broadband-forum-org:cwmp:datamodel-1-8")
    root.set("xmlns:dmr", "urn:broadband-forum-org:cwmp:datamodel-report-0-1")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xsi:schemaLocation", "urn:broadband-forum-org:cwmp:datamodel-1-8 https://www.broadband-forum.org/cwmp/cwmp-datamodel-1-8.xsd urn:broadband-forum-org:cwmp:datamodel-report-0-1 https://www.broadband-forum.org/cwmp/cwmp-datamodel-report.xsd")
    root.set("spec", "urn:broadband-forum-org:tr-181-2-14-1-cwmp")
    root.set("file", "tr-181-2-14-1-cwmp-full.xml")

    model = ET.SubElement(root, "model")
    model.set("name", "Device:2.14")

    for value in bbf.LIST_SUPPORTED_DM:

        if "()" in value:
            continue

        obj = value.strip().split(",")
        access = "readOnly" if obj[1] == "DMREAD" else "readWrite"

        if obj[2] == "DMT_OBJ":
            # Object
            objec = ET.SubElement(model, "object")
            objec.set("name", obj[0])
            objec.set("access", access)
            objec.set("minEntries", "0")
            objec.set("maxEntries", "20")
            DM_OBJ_COUNT += 1
        else:
            # Parameter
            parameter = ET.SubElement(objec, "parameter")
            parameter.set("name", obj[0][obj[0].rindex('.')+1:])
            parameter.set("access", access)
            description = ET.SubElement(parameter, "description")
            description.text = str(
                "parameter " + obj[0][obj[0].rindex('.')+1:])
            syntax = ET.SubElement(parameter, "syntax")
            ET.SubElement(syntax, ARRAY_TYPES.get(obj[2], None))
            DM_PARAM_COUNT += 1

    xml_file = open(output_file, "w")
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

    #param_array = np.empty(15, dtype=ET.Element)
    param_array = [ET.Element] * 15
    param_array[0] = parameters

    for value in bbf.LIST_SUPPORTED_DM:

        if "()" in value:
            continue

        obj = value.strip().split(",")

        if obj[2] == "DMT_OBJ":
            # Object
            obj_tag = ET.SubElement(
                param_array[obj[0].replace(".{i}", "").count('.')-1], "parameter")
            obj_name = ET.SubElement(obj_tag, "parameterName")
            obj_name.text = str(obj[0].replace(".{i}", "").split('.')[-2])
            obj_type = ET.SubElement(obj_tag, "parameterType")
            obj_type.text = str("object")
            obj_array = ET.SubElement(obj_tag, "array")
            obj_array.text = str(
                "true" if obj[0].endswith(".{i}.") else "false")
            parameters = ET.SubElement(obj_tag, "parameters")
            param_array[obj[0].replace(".{i}", "").count('.')] = parameters
            DM_OBJ_COUNT += 1
        else:
            # Parameter
            param_tag = ET.SubElement(
                param_array[obj[0].replace(".{i}", "").count('.')], "parameter")
            param_name = ET.SubElement(param_tag, "parameterName")
            param_name.text = str(obj[0][obj[0].rindex('.')+1:])
            param_type = ET.SubElement(param_tag, "parameterType")
            param_type.text = str(ARRAY_TYPES.get(obj[2], None))
            DM_PARAM_COUNT += 1

    xml_file = open(output_file, "w")
    xml_file.write(pretty_format(root))
    xml_file.close()

def generate_xml(acs = 'default', output_file="datamodel.xml"):
    global DM_OBJ_COUNT
    global DM_PARAM_COUNT

    DM_OBJ_COUNT = 0
    DM_PARAM_COUNT = 0

    print("Generating BBF Data Models in xml format for %s acs..." % acs)
    bbf.fill_list_supported_dm()

    if acs == "HDM":
        generate_hdm_xml_file(output_file)
    else:
        generate_bbf_xml_file(output_file)

    if os.path.isfile(output_file):
        print("├── XML file generated: %s" % output_file)
    else:
        print("├── Error in generating xml file")

    print("├── Number of BBF Data Models objects is %d" % DM_OBJ_COUNT)
    print("└── Number of BBF Data Models parameters is %d" % DM_PARAM_COUNT)

### main ###
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to generate list of supported and non-supported parameter in xml format',
        epilog='Part of BBF-tools, refer Readme for more examples'
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
        help='Generate data model tree with vendor extension OBJ/PARAM.'
    )

    parser.add_argument(
        '-p', '--vendor-prefix',
		default = 'iopsys',
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
		default = 'iopsys',
		metavar = 'iopsys',
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
            r["repo"] = x[0]
            if len(x) == 2:
                r["version"] = x[1]

            plugins.append(r)

    bbf.generate_supported_dm(args.vendor_prefix, args.vendor_list, plugins)
    bbf.clean_supported_dm_list()
    generate_xml(args.format, args.output)
    print("Datamodel generation completed, aritifacts available in %s" %args.output)
