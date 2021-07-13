#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import sys
import getopt
import bbf_common as bbf
import xml.etree.ElementTree as ET
import xml.dom.minidom as MD
import numpy as np

BBF_REMOTE_DM = None
BBF_VENDOR_LIST = None
DM_OBJ_COUNT = 0
DM_PARAM_COUNT = 0
DEVICE_PROTOCOL = "DEVICE_PROTOCOL_DSLFTR069v1"
MANUFACTURER = "iopsys"
MANUFACTURER_OUI = "002207"
PRODUCT_CLASS = "DG400PRIME"
MODEL_NAME = "DG400PRIME-A"
SOFTWARE_VERSION = "1.2.3.4"
XML_FORMAT = "BBF"
XML_FILE = "datamodel.xml"

ARRAY_TYPES = { "DMT_STRING" : "string",
			 	"DMT_UNINT" : "unsignedInt",
			 	"DMT_UNLONG" : "unsignedLong",
			 	"DMT_INT" : "int",
			 	"DMT_LONG" : "long",
			 	"DMT_BOOL" : "boolean",
			 	"DMT_TIME" : "dateTime",
			 	"DMT_HEXBIN" : "hexBinary",
			 	"DMT_BASE64" : "base64"}

def print_dmxml_usage():
	print("Usage: " + sys.argv[0] + " [options...] <urls>")
	print("Options: ")
	print(" -r, --remote-dm              Check OBJ/PARAM under these repositories if it is not found under bbf repo")
	print(" -v, --vendor-list            Generate data model tree with vendor extension OBJ/PARAM")
	print(" -p, --vendor-prefix          Generate data model tree using this vendor prefix. Default vendor prefix: %s" % bbf.BBF_VENDOR_PREFIX)
	print(" -f, --format                 Generate data model tree with HDM format. Default format: %s" % XML_FORMAT)
	print(" -d, --device-protocol        Generate data model tree using this device protocol. Default device protocol: %s" % DEVICE_PROTOCOL)
	print(" -m, --manufacturer           Generate data model tree using this manufacturer. Default manufacturer: %s" % MANUFACTURER)
	print(" -o, --manufacturer-oui       Generate data model tree using this manufacturer oui. Default manufacturer oui: %s" % MANUFACTURER_OUI)
	print(" -c, --product-class          Generate data model tree using this product class. Default product class: %s" % PRODUCT_CLASS)
	print(" -n, --model-name             Generate data model tree using this model name. Default model name: %s" % MODEL_NAME)
	print(" -s, --software-version       Generate data model tree using this software version. Default software version: %s" % SOFTWARE_VERSION)
	
	
	print(" -h, --help                   This help text")
	print("Urls: ")
	print(" url^(branch,hash,tag)        The url with branch, hash or tag to be used")
	print("")
	print("Examples: ")
	print("  - python " + sys.argv[0])
	print("    ==> Generate xml file in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -f HDM")
	print("    ==> Generate xml file with HDM format in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -v iopsys")
	print("    ==> Generate xml file using iopsys extension in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -r https://dev.iopsys.eu/feed/iopsys.git^devel,https://dev.iopsys.eu/iopsys/mydatamodel.git^5c8e7cb740dc5e425adf53ea574fb529d2823f88")
	print("    ==> Generate xml file in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -v iopsys,openwrt,test -r https://dev.iopsys.eu/feed/iopsys.git^6.0.0ALPHA1 -p X_TEST_COM_")
	print("    ==> Generate xml file in %s" % XML_FILE)

def pretty_format( elem ):
	elem_string = ET.tostring(elem, 'UTF-8')
	reparsed = MD.parseString(elem_string)
	return reparsed.toprettyxml(indent="  ")

def generate_bbf_xml_file():
	global DM_OBJ_COUNT
	global DM_PARAM_COUNT

	bbf.remove_file(XML_FILE)
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

		obj = value.split(",")
		access = "readOnly" if obj[1] == "DMREAD" else "readWrite"

		if obj[2] == "DMT_OBJ":
			## Object
			objec = ET.SubElement(model, "object")
			objec.set("name", obj[0])
			objec.set("access", access)
			objec.set("minEntries", "0")
			objec.set("maxEntries", "20")
			DM_OBJ_COUNT += 1
		else:
			## Parameter
			parameter = ET.SubElement(objec, "parameter")
			parameter.set("name", obj[0][obj[0].rindex('.')+1:])
			parameter.set("access", access)
			description = ET.SubElement(parameter, "description")
			description.text = str("parameter " + obj[0][obj[0].rindex('.')+1:])
			syntax = ET.SubElement(parameter, "syntax")
			ET.SubElement(syntax, ARRAY_TYPES.get(obj[2], None))
			DM_PARAM_COUNT += 1
	
	xml_file = open(XML_FILE, "w")
	xml_file.write(pretty_format(root))
	xml_file.close()

def generate_hdm_xml_file():
	global DM_OBJ_COUNT
	global DM_PARAM_COUNT

	bbf.remove_file(XML_FILE)
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
	type = ET.SubElement(root, "type")
	type.text = str("Device:2")

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

	param_array = np.empty(15, dtype=ET.Element)
	param_array[0] = parameters

	for value in bbf.LIST_SUPPORTED_DM:

		obj = value.split(",")

		if obj[2] == "DMT_OBJ":			
			## Object
			obj_tag = ET.SubElement(param_array[obj[0].replace(".{i}", "").count('.')-1], "parameter")
			obj_name = ET.SubElement(obj_tag, "parameterName")
			obj_name.text = str(obj[0].replace(".{i}", "").split('.')[-2])
			obj_type = ET.SubElement(obj_tag, "parameterType")
			obj_type.text = str("object")
			obj_array = ET.SubElement(obj_tag, "array")
			obj_array.text = str("true" if obj[0].endswith(".{i}.") else "false")
			parameters = ET.SubElement(obj_tag, "parameters")
			param_array[obj[0].replace(".{i}", "").count('.')] = parameters
			DM_OBJ_COUNT += 1
		else:
			## Parameter
			param_tag = ET.SubElement(param_array[obj[0].replace(".{i}", "").count('.')], "parameter")
			param_name = ET.SubElement(param_tag, "parameterName")
			param_name.text = str(obj[0][obj[0].rindex('.')+1:])
			param_type = ET.SubElement(param_tag, "parameterType")
			param_type.text = str(ARRAY_TYPES.get(obj[2], None))
			DM_PARAM_COUNT += 1

	xml_file = open(XML_FILE, "w")
	xml_file.write(pretty_format(root))
	xml_file.close()

try:
	opts, args = getopt.getopt(sys.argv[1:], "hr:v:p:d:m:o:c:n:s:f:", ["remote-dm=", "vendor-list=", "vendor-prefix=", "device-protocol=", "manufacturer=", "manufacturer-oui=", "product-class=", "model-name=", "software-version=", "format="])
except getopt.GetoptError:
	print_dmxml_usage()
	exit(1)

for opt, arg in opts:
	if opt in ("-h", "--help"):
		print_dmxml_usage()
		exit(1)
	elif opt in ("-r", "--remote-dm"):
		BBF_REMOTE_DM = arg
	elif opt in ("-v", "--vendor-list"):
		BBF_VENDOR_LIST = arg
	elif opt in ("-p", "--vendor-prefix"):
		bbf.BBF_VENDOR_PREFIX = arg
	elif opt in ("-d", "--device-protocol"):
		DEVICE_PROTOCOL = arg
	elif opt in ("-m", "--manufacturer"):
		MANUFACTURER = arg
	elif opt in ("-o", "--manufacturer-oui"):
		MANUFACTURER_OUI = arg
	elif opt in ("-c", "--product-class"):
		PRODUCT_CLASS = arg
	elif opt in ("-n", "--model-name"):
		MODEL_NAME = arg
	elif opt in ("-s", "--software-version"):
		SOFTWARE_VERSION = arg
	elif opt in ("-f", "--format"):
		XML_FORMAT = arg

bbf.generate_supported_dm(BBF_REMOTE_DM, BBF_VENDOR_LIST)

if XML_FORMAT == "HDM":
	generate_hdm_xml_file()
else:
	generate_bbf_xml_file()

print("Number of BBF Data Models objects is %d" % DM_OBJ_COUNT)
print("Number of BBF Data Models parameters is %d" % DM_PARAM_COUNT)
print("End of BBF Data Models Generation")

if (os.path.isfile(XML_FILE)):
	print("XML file generated: %s" % XML_FILE)
else:
	print("No XML file generated!")