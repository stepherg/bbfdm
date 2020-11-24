#!/usr/bin/python

# Copyright (C) 2020 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os, sys, shutil, subprocess, getopt, time, json, xlwt
from xlwt import Workbook 
from collections import OrderedDict

def removefile( filename ):
	try:
		os.remove(filename)
	except OSError:
		pass

def removefolder( foldername ):
	try:
		shutil.rmtree(foldername)
	except:
		pass

def objhaschild( value ):
	if isinstance(value,dict):
		for k,v in value.items():
			if isinstance(v,dict):
				for k1,v1 in v.items():
					if k1 == "type" and v1 == "object":
						return 1
	return 0

def objhasparam( value ):
	if isinstance(value,dict):
		for k,v in value.items():
			if isinstance(v,dict):
				for k1,v1 in v.items():
					if k1 == "type" and v1 != "object":
						return 1
	return 0

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

def check_obj(dmobject):
	dmobject = dmobject.replace(".{i}.", ".")
	count = dmobject.count('.')
	obj = dmobject.split(".")
	array_name = ""

	if "tr181" in sys.argv[1] and count == 2:
		cmd = 'awk \'/DMOBJ tDeviceObj/,/^{0}$/\' ../dmtree/tr181/device.c'
	elif "tr104" in sys.argv[1] and count == 3:
		cmd = 'awk \'/DMOBJ tServicesObj/,/^{0}$/\' ../dmtree/tr104/servicesvoiceservice.c'
	else:
		if "Device.IP.Diagnostics." == dmobject:
			obj_name = obj[1].lower()
		elif "Device.IP.Diagnostics." in dmobject:
			obj_name = obj[2].lower()
		else:
			obj_name = obj[1].lower()

		for i in range(count-2):
			array_name += obj[i+1]
		cmd = 'find ../dmtree/ -name *%s*.c -exec awk \'/DMOBJ t%sObj/,/^{0}$/\' {} \;' % (obj_name, array_name)

	res = os.popen(cmd).read()
	string = "\n{\"%s\"," % obj[count - 1]
	supported = "Yes" if string in res else "No"

	if remotedm != None and res != "" and supported == "No":
		for i in range(remotedm.count(',') + 1):
			if os.path.isdir("./.repo" + str(i)):
				cmd = 'find ./.repo%s/ -name datamodel.c -exec awk \'/DMOBJ tDevice%sObj/,/^{0}$/\' {} \;' % (str(i), obj[count - 1])
				res = os.popen(cmd).read()
				if res != "":
					break;

	if res == "" and remotedm != None:
		for i in range(remotedm.count(',') + 1):
			if os.path.isdir("./.repo" + str(i)):
				cmd = 'find ./.repo%s/ -name datamodel.c -exec awk \'/DMOBJ t%sObj/,/^{0}$/\' {} \;' % (str(i), array_name)
				res = os.popen(cmd).read()
				if res != "":
					break;

	return "Yes" if string in res else "No"

def load_param_array(dmobject):
	dmobject = dmobject.replace(".{i}.", ".")
	count = dmobject.count('.')
	obj = dmobject.split(".")

	if "tr181" in sys.argv[1] and count == 1:
		cmd = 'awk \'/DMLEAF tDeviceParams/,/^{0}$/\' ../dmtree/tr181/device.c'
	elif "tr104" in sys.argv[1] and  count == 3:
		cmd = 'awk \'/DMLEAF tServicesVoiceServiceParams/,/^{0}$/\' ../dmtree/tr104/servicesvoiceservice.c'
	else:
		array_name = ""
		for i in range(count-1):
			array_name += obj[i+1]
		cmd = 'find ../dmtree/ -name *%s*.c -exec awk \'/DMLEAF t%sParams/,/^{0}$/\' {} \;' % (obj[2].lower() if "Device.IP.Diagnostics." in dmobject else obj[1].lower(), array_name)

	res = os.popen(cmd).read()
	if res == "" and remotedm != None:
		for i in range(remotedm.count(',') + 1):
			if os.path.isdir("./.repo" + str(i)):
				cmd = 'find ./.repo%s/ -name datamodel.c -exec awk \'/DMLEAF t%sParams/,/^{0}$/\' {} \;' % (str(i), array_name)
				res = os.popen(cmd).read()
				if res != "":
					break;

	return res

def check_param(param, res):
	string = "\n{\"%s\"," % param
	return "Yes" if string in res else "No"

def check_commands(param):
	cmd = 'awk \'/static const struct op_cmd operate_helper/,/^};$/\' ../dmoperate.c'
	param = param.replace(".{i}.", ".*.").replace("()", "")

	res = os.popen(cmd).read()
	string = "\n\t{\n\t\t\"%s\"," % param

	return "Yes" if string in res else "No"

def printOBJPARAM(obj, supported, protocols, types):
	fp = open('./.tmp', 'a')
	print("%s::%s::%s::%s::" % (obj, protocols, "Yes" if CUSTOM_PREFIX in obj else supported, types), file=fp)
	fp.close()

def printusage():
	print("Usage: " + sys.argv[0] + " <json data model> [options...] <urls>")
	print("JSON data models: ")
	print(" tr181.json or tr104.json     The JSON data model to be parsed")
	print("Options: ")
	print(" -r, --remote-dm              Check OBJ/PARAM under these repositories if it is not found under bbf repo")
	print(" -h, --help                   This help text")
	print("Urls: ")
	print(" url^(branch,hash,tag)        The url with branch, hash or tag to be used")
	print("")
	print("Examples: ")
	print("  - python " + sys.argv[0] + " tr181.json")
	print("    ==> Generate excel file in tr181.xls")
	print("  - python " + sys.argv[0] + " tr104.json")
	print("    ==> Generate excel file in tr104.xls")
	print("  - python " + sys.argv[0] + " tr181.json -r https://dev.iopsys.eu/feed/iopsys.git^release-5.3,https://dev.iopsys.eu/iopsys/mydatamodel.git^5c8e7cb740dc5e425adf53ea574fb529d2823f88")
	print("    ==> Generate excel file in tr181.xls")
	print("  - python " + sys.argv[0] + " tr181.json --remote-dm https://dev.iopsys.eu/feed/iopsys.git^6.0.0ALPHA1")
	print("    ==> Generate excel file in tr181.xls")

def object_parse_childs( dmobject , value ):
	hasobj = objhaschild(value)
	hasparam = objhasparam(value)

	if dmobject.count('.') == 1:
		printOBJPARAM(dmobject, "Yes", "CWMP+USP", "object")
	else:
		supported = check_obj(dmobject)
		printOBJPARAM(dmobject, supported, getprotocols(value), "object")		

	if hasparam:
		res = load_param_array(dmobject)
		if isinstance(value,dict):
			for k,v in value.items():
				if k == "mapping":
					continue
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 != "object":
							if "()" in k:
								supported = check_commands(dmobject + k)
								printOBJPARAM(dmobject + k, supported, getprotocols(v), "operate")
							else:
								supported = check_param(k, res)
								printOBJPARAM(dmobject + k, supported, getprotocols(v), "parameter")
							break

	if hasobj:
		if isinstance(value,dict):
			for k,v in value.items():
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 == "object":
							object_parse_childs(k , v)

def generatecfromobj(excel_file, pobj, pvalue):
	print("Start Generation of BBF Data Models Excel...")
	print("Please wait...")
	removefile("./.tmp")
	removefile("./"+excel_file)
	object_parse_childs(pobj, pvalue)

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
	file = open("./.tmp", "r")
	for line in file:
		param = line.split("::")
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
	wb.save(excel_file)

### main ###
if len(sys.argv) < 2:
	printusage()
	exit(1)

try:
	opts, args = getopt.getopt(sys.argv[2:], "hr:", ["remote-dm="])
except getopt.GetoptError:
	printusage()
	exit(1)

CUSTOM_PREFIX = "X_IOPSYS_EU"
remotedm = None

for opt, arg in opts:
	if opt in ("-h", "--help"):
		printusage()
		exit(1)
	elif opt in ("-r", "--remote-dm"):
		remotedm = arg

if remotedm != None:
	print("Start downloading remote data models...")
	print("Download in progress........")
	dm_url = remotedm.split(",")
	for i in range(remotedm.count(',') + 1):
		url = dm_url[i].split("^")
		subprocess.run(["git", "clone", url[0], ".repo" + str(i)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		if url.count("^") == 1:
			subprocess.run(["git", "-C", ".repo" + str(i), "checkout", url[1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if "tr181" in sys.argv[1]:
	excel_file = "tr181.xls"
elif "tr104" in sys.argv[1]:
	excel_file = "tr104.xls"

with open(sys.argv[1]) as file:
	data = json.loads(file.read(), object_pairs_hook=OrderedDict)

for obj, value in data.items():
	if obj == None:
		print("Wrong JSON Data model format!")
		exit(1)

	generatecfromobj(excel_file, obj, value)

if remotedm != None:
	for i in range(remotedm.count(',') + 1):
		removefolder("./.repo" + str(i))

removefile("./.tmp")

if (os.path.isfile(excel_file)):
	print("%s Excel file generated" % excel_file)
else:
	print("No Excel file generated!")
