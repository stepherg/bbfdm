#!/usr/bin/python

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import sys
import getopt
import json
import xlwt
from xlwt import Workbook 
from collections import OrderedDict
import bbf_common as bbf

BBF_REMOTE_DM = None
BBF_VENDOR_LIST = None
EXCEL_FILE = "datamodel.xls"
LIST_DM = []

def print_dmexcel_usage():
	print("Usage: " + sys.argv[0] + " <data model name> [options...] <urls>")
	print("data model name:              The data model(s) to be used, for ex: tr181 or tr181,tr104")
	print("Options: ")
	print(" -r, --remote-dm              Check OBJ/PARAM under these repositories if it is not found under bbf repo")
	print(" -v, --vendor-list            Generate data model tree with vendor extension OBJ/PARAM")
	print(" -p, --vendor-prefix          Generate data model tree using this vendor prefix. Default vendor prefix: %s" % bbf.BBF_VENDOR_PREFIX)
	print(" -h, --help                   This help text")
	print("Urls: ")
	print(" url^(branch,hash,tag)        The url with branch, hash or tag to be used")
	print("")
	print("Examples: ")
	print("  - python " + sys.argv[0] + " tr181")
	print("    ==> Generate excel file in %s" % EXCEL_FILE)
	print("  - python " + sys.argv[0] + " tr104")
	print("    ==> Generate excel file in %s" % EXCEL_FILE)
	print("  - python " + sys.argv[0] + " tr181,tr104 -r https://dev.iopsys.eu/feed/iopsys.git^release-5.3,https://dev.iopsys.eu/iopsys/mydatamodel.git^5c8e7cb740dc5e425adf53ea574fb529d2823f88")
	print("    ==> Generate excel file in %s" % EXCEL_FILE)
	print("  - python " + sys.argv[0] + " tr181,tr104 -v iopsys,openwrt,test -r https://dev.iopsys.eu/feed/iopsys.git^6.0.0ALPHA1 -p X_TEST_COM_")
	print("    ==> Generate excel file in %s" % EXCEL_FILE)

def getprotocols( value ):
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

def check_param_obj( dmobject ):
	for value in bbf.LIST_SUPPORTED_DM:
		obj = value.split(",")
		if obj[0] == dmobject:
			bbf.LIST_SUPPORTED_DM.remove(value)
			return "Yes"
	return "No"

def check_commands( param ):
	cmd = 'awk \'/static const struct op_cmd operate_helper/,/^};$/\' ../dmoperate.c'
	param = param.replace(".{i}.", ".*.").replace("()", "")

	res = os.popen(cmd).read()
	string = "\n\t{\n\t\t\"%s\"," % param

	return "Yes" if string in res else "No"

def add_data_to_list_dm( obj, supported, protocols, types ):
	LIST_DM.append(obj + "," + protocols + "," + supported + "," + types)

def parse_standard_object( dmobject , value ):
	hasobj = bbf.obj_has_child(value)
	hasparam = bbf.obj_has_param(value)

	supported = check_param_obj(dmobject)
	add_data_to_list_dm(dmobject, supported, getprotocols(value), "object")		

	if hasparam:
		if isinstance(value,dict):
			for k,v in value.items():
				if k == "mapping":
					continue
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 != "object":
							if "()" in k:
								supported = check_commands(dmobject + k)
								add_data_to_list_dm(dmobject + k, supported, getprotocols(v), "operate")
							else:
								supported = check_param_obj(dmobject + k)
								add_data_to_list_dm(dmobject + k, supported, getprotocols(v), "parameter")
							break

	if hasobj:
		if isinstance(value,dict):
			for k,v in value.items():
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 == "object":
							parse_standard_object(k , v)

def parse_dynamic_object():
	for value in bbf.LIST_SUPPORTED_DM:
		obj = value.split(",")

		dm_name = sys.argv[1].split(",")
		for i in range(sys.argv[1].count(',') + 1):

			JSON_FILE = bbf.ARRAY_JSON_FILES.get(dm_name[i], None)

			if JSON_FILE == None:
				continue

			if "tr181" == dm_name[i] and ".Services." in obj[0]:
				continue

			if "tr104" == dm_name[i] and ".Services." not in obj[0]:
				continue

			type = "object" if obj[2] == "DMT_OBJ" else "parameter"
			add_data_to_list_dm(obj[0], "Yes", "CWMP+USP", type)

def parse_object_tree():
	print("Start Generation of BBF Data Models Excel...")
	print("Please wait...")

	dm_name = sys.argv[1].split(",")
	for i in range(sys.argv[1].count(',') + 1):

		JSON_FILE = bbf.ARRAY_JSON_FILES.get(dm_name[i], None)

		if JSON_FILE != None:
			file = open(JSON_FILE, "r")
			data = json.loads(file.read(), object_pairs_hook=OrderedDict)

			for obj, value in data.items():
				if obj == None:
					print("!!!! %s : Wrong JSON Data model format!" % dm_name[i])
					continue

				parse_standard_object(obj, value)
		else:
			print("!!!! %s : Data Model doesn't exist" % dm_name[i])
		
	parse_dynamic_object()

def generate_excel_file():
	bbf.remove_file(EXCEL_FILE)

	LIST_DM.sort(reverse=False)

	wb = Workbook(style_compression=2)
	sheet = wb.add_sheet('CWMP-USP')

	xlwt.add_palette_colour("custom_colour_yellow", 0x10)
	xlwt.add_palette_colour("custom_colour_green", 0x20)
	xlwt.add_palette_colour("custom_colour_grey", 0x30)

	wb.set_colour_RGB(0x10, 255, 255, 153)
	wb.set_colour_RGB(0x20, 102, 205, 170)
	wb.set_colour_RGB(0x30, 153, 153, 153)

	style_title = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_grey;''font: bold 1, color black;''alignment: horizontal center;')
	sheet.write(0, 0, 'OBJ/PARAM/OPERATE', style_title)
	sheet.write(0, 1, 'Protocols', style_title)
	sheet.write(0, 2, 'Supported', style_title)

	i = 0
	for value in LIST_DM:
		param = value.split(",")
		i += 1

		if param[3] == "object":
			style_name = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_yellow')
			style = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_yellow;''alignment: horizontal center;')
		elif param[3] == "operate":
			style_name = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green')
			style = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green;''alignment: horizontal center;')
		else:
			style_name = None
			style = xlwt.easyxf('alignment: horizontal center;')

		if style_name != None:
			sheet.write(i, 0, param[0], style_name)
		else:
			sheet.write(i, 0, param[0])

		sheet.write(i, 1, param[1], style)
		sheet.write(i, 2, param[2], style)

	sheet.col(0).width = 1300*20
	sheet.col(1).width = 175*20
	sheet.col(2).width = 175*20

	wb.save(EXCEL_FILE)

### main ###
if len(sys.argv) < 2:
	print_dmexcel_usage()
	exit(1)

try:
	opts, args = getopt.getopt(sys.argv[2:], "hr:v:p:", ["remote-dm=", "vendor-list=", "vendor-prefix="])
except getopt.GetoptError:
	print_dmexcel_usage()
	exit(1)

for opt, arg in opts:
	if opt in ("-h", "--help"):
		print_dmexcel_usage()
		exit(1)
	elif opt in ("-r", "--remote-dm"):
		BBF_REMOTE_DM = arg
	elif opt in ("-v", "--vendor-list"):
		BBF_VENDOR_LIST = arg
	elif opt in ("-p", "--vendor-prefix"):
		bbf.BBF_VENDOR_PREFIX = arg

bbf.generate_supported_dm(BBF_REMOTE_DM, BBF_VENDOR_LIST)

parse_object_tree()

generate_excel_file()

if (os.path.isfile(EXCEL_FILE)):
	print("Excel file generated: %s" % EXCEL_FILE)
else:
	print("No Excel file generated!")
