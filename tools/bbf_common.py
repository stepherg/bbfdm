#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import subprocess
import shutil

CURRENT_PATH = os.getcwd()
BBF_TR181_ROOT_FILE = "device.c"
BBF_TR104_ROOT_FILE = "servicesvoiceservice.c"
BBF_VENDOR_ROOT_FILE = "vendor.c"
BBF_VENDOR_PREFIX = "X_IOPSYS_EU_"
BBF_DMTREE_PATH = CURRENT_PATH + "/../dmtree"
BBF_DMTREE_PATH_TR181 = BBF_DMTREE_PATH + "/tr181"
BBF_DMTREE_PATH_TR104 = BBF_DMTREE_PATH + "/tr104"
BBF_DMTREE_PATH_TR143 = BBF_DMTREE_PATH + "/tr143"
BBF_DMTREE_PATH_TR181_JSON = BBF_DMTREE_PATH + "/json/tr181.json"
BBF_DMTREE_PATH_TR104_JSON = BBF_DMTREE_PATH + "/json/tr104.json"
ARRAY_JSON_FILES = { "tr181" : BBF_DMTREE_PATH_TR181_JSON,
			 		 "tr104" : BBF_DMTREE_PATH_TR104_JSON}
LIST_DM_DIR = [BBF_DMTREE_PATH_TR181, BBF_DMTREE_PATH_TR104, BBF_DMTREE_PATH_TR143]
LIST_IGNORED_LINE = ['/*', '//', '#']
LIST_OBJ = []
LIST_PARAM = []
LIST_SUPPORTED_DM = []

def remove_file( file_name ):
	try:
		os.remove(file_name)
	except OSError:
		pass

def create_folder( folder_name ):
	try:
		os.mkdir(folder_name)
	except OSError:
		pass

def remove_folder( folder_name ):
	try:
		shutil.rmtree(folder_name)
	except:
		pass

def cd_dir( path ):
	try:
		os.chdir(path)
	except OSError:
		pass

def obj_has_child( value ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if isinstance(val, dict):
				for obj1, val1 in val.items():
					if obj1 == "type" and val1 == "object":
						return 1
	return 0

def obj_has_param( value ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if isinstance(val, dict):
				for obj1,val1 in val.items():
					if obj1 == "type" and val1 != "object":
						return 1
	return 0

def generate_datamodel_tree( filename ):
	obj_found = 0
	param_found = 0
	obj_found_in_list = 0
	table_name = ""
	parent_obj = ""

	fp = open(filename, 'r')
	for line in fp:

		if "DMOBJ" in line:
			table_name = line[:line.index('[]')].rstrip('\n').replace("DMOBJ ", "")
			obj_found = 1
			continue

		if "DMLEAF" in line:
			table_name = line[:line.index('[]')].rstrip('\n').replace("DMLEAF ", "")
			param_found = 1
			continue

		if obj_found == 0 and param_found == 0:
			continue

		if line.startswith(tuple(LIST_IGNORED_LINE)) == True:
			continue

		if "{0}" in line:
			obj_found = 0
			param_found = 0
			obj_found_in_list = 0
			table_name = ""
			parent_obj = ""
			continue

		## Object Table
		if obj_found == 1:
			if obj_found_in_list == 0:
				for value in LIST_OBJ:
					val = value.split(":")
					if val[1] == table_name:
						parent_obj = val[0]
						obj_found_in_list = 1
						LIST_OBJ.remove(value)

			obj = line.rstrip('\n').split(", ")
			obj_name = parent_obj + obj[0].replace("{", "").replace("\"", "").replace("BBF_VENDOR_PREFIX", BBF_VENDOR_PREFIX)
			obj_permission = obj[1].replace("&", "")
			obj_mulinst = obj[5].replace("&", "")

			if obj_mulinst == "NULL":
				full_obj_name = obj_name + "."
			else:
				full_obj_name = obj_name + ".{i}."

			LIST_SUPPORTED_DM.append(full_obj_name + "," + obj_permission + ",DMT_OBJ")

			if obj[8] != "NULL":
				LIST_OBJ.append(full_obj_name + ":" + obj[8])

			if obj[9] != "NULL":
				LIST_PARAM.append(full_obj_name + ":" + obj[9])

		## Parameter Table
		if param_found == 1:
			if obj_found_in_list == 0:
				for value in LIST_PARAM:
					val = value.split(":")
					if val[1] == table_name:
						parent_obj = val[0]
						obj_found_in_list = 1
						LIST_PARAM.remove(value)

			param = line.rstrip('\n').split(", ")
			param_name = parent_obj + param[0].replace("{", "").replace("\"", "").replace("BBF_VENDOR_PREFIX", BBF_VENDOR_PREFIX)
			param_permission = param[1].replace("&", "")
			param_type = param[2]

			LIST_SUPPORTED_DM.append(param_name + "," + param_permission + "," + param_type)


	fp.close()



def generate_dynamic_datamodel_tree( filename ):
	obj_found = 0
	table_name = ""

	fp = open(filename, 'r')
	for line in fp:

		if "DM_MAP_OBJ" in line:
			table_name = line[:line.index('[]')].rstrip('\n').replace("DM_MAP_OBJ ", "")
			obj_found = 1
			continue

		if obj_found == 0:
			continue

		if line.startswith(tuple(LIST_IGNORED_LINE)) == True:
			continue

		if "{0}" in line:
			obj_found = 0
			table_name = ""
			continue

		## Object Table
		if obj_found == 1:
			obj = line.rstrip('\n').split(", ")
			obj_name = obj[0][1:].replace("\"", "")

			if obj[1] != "NULL":
				LIST_OBJ.append(obj_name + ":" + obj[1])

			if obj[2] != "NULL":
				LIST_PARAM.append(obj_name + ":" + obj[2].replace("},", ""))

	fp.close()




def generate_supported_dm( remote_dm, vendor_list ):

	'''
	1/ Download Remote Data Model if needed
	2/ Parse all Standard Data Model
	3/ Parse all Vendor Data Model if needed
	4/ Parse all Remote Data Model if needed
	5/ Generate the list of Supported Data Model 'LIST_SUPPORTED_DM'
	'''

	############## Download Remote Data Models ##############
	if remote_dm != None:
		print("Start downloading remote data models...")
		print("Download in progress........")
		dm_url = remote_dm.split(",")
		for i in range(remote_dm.count(',') + 1):
			url = dm_url[i].split("^")
			subprocess.run(["git", "clone", "--depth=1", url[0], ".repo" + str(i)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			if url.count("^") == 1:
				subprocess.run(["git", "-C", ".repo" + str(i), "checkout", url[1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


	############## GEN Standard BBF Data Models TREE ##############
	print("Start Generation of Supported Data Models...")
	print("Please wait...")

	cd_dir(BBF_DMTREE_PATH_TR181)
	generate_datamodel_tree(BBF_TR181_ROOT_FILE)

	cd_dir(BBF_DMTREE_PATH_TR104)
	generate_datamodel_tree(BBF_TR104_ROOT_FILE)

	for DIR in LIST_DM_DIR:
		cd_dir(DIR)
		for root, dirs, files in os.walk("."):
			for filename in files:
				if ".h" in filename or filename == BBF_TR181_ROOT_FILE or filename == BBF_TR104_ROOT_FILE:
					continue

				generate_datamodel_tree(filename)


	############## GEN Vendors BBF Data Models TREE ##############
	if vendor_list != None:
		cd_dir(BBF_DMTREE_PATH)
		vendor = vendor_list.split(",")
		for i in range(vendor_list.count(',') + 1):
			vendor_dir = "vendor/" + vendor[i] + "/tr181"
			if os.path.isdir(vendor_dir):
				cd_dir(vendor_dir)

				generate_dynamic_datamodel_tree(BBF_VENDOR_ROOT_FILE)
				if os.path.isfile(BBF_TR181_ROOT_FILE):
					generate_datamodel_tree(BBF_TR181_ROOT_FILE)

				for root, dirs, files in os.walk("."):
					for filename in files:
						if ".h" in filename or filename == BBF_VENDOR_ROOT_FILE or filename == BBF_TR181_ROOT_FILE:
							continue

						generate_datamodel_tree(filename)

				cd_dir(BBF_DMTREE_PATH)


	############## GEN External BBF Data Models TREE ##############
	if remote_dm != None:
		cd_dir(CURRENT_PATH)

		for i in range(remote_dm.count(',') + 1):
			if os.path.isdir("./.repo" + str(i)):

				cmd = 'find ./.repo%s/ -name datamodel.c' % str(i)
				files = os.popen(cmd).read()

				for file in files.split('\n'):
					if os.path.isfile(file):
						generate_dynamic_datamodel_tree(file)
						generate_datamodel_tree(file)


	############## Remove Duplicated Element from List ##############
	global LIST_SUPPORTED_DM
	LIST_SUPPORTED_DM = list(set(LIST_SUPPORTED_DM))


	############## Sort all elements in List ##############
	LIST_SUPPORTED_DM.sort(reverse=False)


	############## Back to the current directory ##############
	cd_dir(CURRENT_PATH)


	############## Remove Remote Data Models ##############
	if remote_dm != None:
		for i in range(remote_dm.count(',') + 1):
			remove_folder("./.repo" + str(i))
