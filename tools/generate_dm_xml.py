#!/usr/bin/python

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import sys
import getopt
import bbf_common as bbf
import xml.etree.ElementTree as ET

BBF_REMOTE_DM = None
BBF_VENDOR_LIST = None
DM_OBJ_COUNT = 0
DM_PARAM_COUNT = 0
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
	print(" -h, --help                   This help text")
	print("Urls: ")
	print(" url^(branch,hash,tag)        The url with branch, hash or tag to be used")
	print("")
	print("Examples: ")
	print("  - python " + sys.argv[0])
	print("    ==> Generate xml file in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -v iopsys")
	print("    ==> Generate xml file in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -r https://dev.iopsys.eu/feed/iopsys.git^devel,https://dev.iopsys.eu/iopsys/mydatamodel.git^5c8e7cb740dc5e425adf53ea574fb529d2823f88")
	print("    ==> Generate xml file in %s" % XML_FILE)
	print("  - python " + sys.argv[0] + " -v iopsys,openwrt,test -r https://dev.iopsys.eu/feed/iopsys.git^6.0.0ALPHA1 -p X_TEST_COM_")
	print("    ==> Generate xml file in %s" % XML_FILE)

def generate_xml_file():
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

	tree = ET.ElementTree(root)

	tree.write(XML_FILE, encoding ='UTF-8', xml_declaration = True)

try:
	opts, args = getopt.getopt(sys.argv[1:], "hr:v:p:", ["remote-dm=", "vendor-list=", "vendor-prefix="])
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

bbf.generate_supported_dm(BBF_REMOTE_DM, BBF_VENDOR_LIST)

generate_xml_file()

print("Number of BBF Data Models objects is %d" % DM_OBJ_COUNT)
print("Number of BBF Data Models parameters is %d" % DM_PARAM_COUNT)
print("End of BBF Data Models Generation")

if (os.path.isfile(XML_FILE)):
	print("XML file generated: %s" % XML_FILE)
else:
	print("No XML file generated!")