#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

from __future__ import print_function

import os
import sys
import json
from collections import OrderedDict
import bbf_common as bbf

DMC_DIR = "datamodel"


def getlastname(name):
    return name.replace(".{i}", "").split('.')[-2]


def getname(objname):
    OBJSname = objname
    if (objname.count('.') > 1 and (objname.count('.') != 2 or objname.count('{i}') != 1)):
        OBJSname = objname.replace("Device", "", 1)
    OBJSname = OBJSname.replace("{i}", "").replace(".", "")
    if objname.count('.') == 1:
        return OBJSname
    if (objname.count('.') == 2 and objname.count('{i}') == 1):
        OBJSname = "Services" + OBJSname
        return OBJSname
    return OBJSname


def getarrayoptionparam(value, option):
    if isinstance(value, dict):
        for obj, val in value.items():
            if obj == option and isinstance(val, list):
                return val
    return None


def getprotocolsparam(value, option):
    if isinstance(value, dict):
        for obj, val in value.items():
            if obj == option and isinstance(val, list):
                if len(val) == 2:
                    return "BBFDM_BOTH"
                elif val[0] == "usp":
                    return "BBFDM_USP"
                else:
                    return "BBFDM_CWMP"
    return "BBFDM_BOTH"


def getuniquekeys(value, option):
    if isinstance(value, dict):
        for obj, val in value.items():
            if obj == option and isinstance(val, list):
                buf = "LIST_KEY{"
                for key in val:
                    buf = buf + "\"%s\"" % key + ", "
                buf = buf + "NULL" + "}"
                return buf
    return None


def getargsparam(value):
    if isinstance(value, dict):
        for obj, val in value.items():
            return obj, val
    return None, None


def get_mapping_param(mappingobj):
    dm_type = bbf.get_option_value(mappingobj, "type")
    if dm_type == "uci":
        uciobj = bbf.get_option_value(mappingobj, "uci")
        file = bbf.get_option_value(uciobj, "file")
        sectionobj = bbf.get_option_value(uciobj, "section")
        sectiontype = bbf.get_option_value(sectionobj, "type")
        sectionname = bbf.get_option_value(sectionobj, "name")
        sectionindex = bbf.get_option_value(sectionobj, "index")
        optionobj = bbf.get_option_value(uciobj, "option")
        optionname = bbf.get_option_value(optionobj, "name")
        path = bbf.get_option_value(uciobj, "path")
        ref = bbf.get_option_value(uciobj, "ref")
        return dm_type, file, sectiontype, sectionname, sectionindex, optionname, path, ref
    elif dm_type == "ubus":
        ubusobj = bbf.get_option_value(mappingobj, "ubus")
        dm_object = bbf.get_option_value(ubusobj, "object")
        method = bbf.get_option_value(ubusobj, "method")
        argsobj = bbf.get_option_value(ubusobj, "args")
        arg1, arg2 = getargsparam(argsobj)
        key = bbf.get_option_value(ubusobj, "key")
        return dm_type, dm_object, method, arg1, arg2, key, None, None
    elif dm_type == "procfs" or dm_type == "sysfs":
        file = bbf.get_option_value(mappingobj, "file")
        return dm_type, file, None, None, None, None, None, None
    else:
        cliobj = bbf.get_option_value(mappingobj, "cli")
        command = bbf.get_option_value(cliobj, "command")
        argsobj = bbf.get_option_value(cliobj, "args")
        i = 0
        value = ""
        list_length = len(argsobj)
        while i < list_length:
            if value == "":
                value = "\"" + argsobj[i] + "\", "
            elif i == list_length-1:
                value = value + "\"" + argsobj[i] + "\""
            else:
                value = value + "\"" + argsobj[i] + "\", "
            i += 1
        return dm_type, command, list_length, value, None, None, None, None


def printGlobalstrCommon(str_exp):
    fp = open(DMC_DIR + "/common.c", 'a')
    print("%s" % str_exp, file=fp)
    fp.close()


def get_mapping_obj(mappingobj):
    dm_type = bbf.get_option_value(mappingobj, "type")
    if dm_type == "uci":
        uciobj = bbf.get_option_value(mappingobj, "uci")
        file = bbf.get_option_value(uciobj, "file")
        sectionobj = bbf.get_option_value(uciobj, "section")
        sectiontype = bbf.get_option_value(sectionobj, "type")
        dmmapfile = bbf.get_option_value(uciobj, "dmmapfile")
        return dm_type, file, sectiontype, dmmapfile, None, None
    elif dm_type == "ubus":
        ubusobj = bbf.get_option_value(mappingobj, "ubus")
        dm_object = bbf.get_option_value(ubusobj, "object")
        method = bbf.get_option_value(ubusobj, "method")
        argsobj = bbf.get_option_value(ubusobj, "args")
        arg1, arg2 = getargsparam(argsobj)
        key = bbf.get_option_value(ubusobj, "key")
        return dm_type, dm_object, method, arg1, arg2, key
    else:
        return dm_type, None, None, None, None, None


def generate_validate_value(dmparam, value):
    validate_value = ""
    maxsizeparam = "-1"
    itemminparam = "-1"
    itemmaxparam = "-1"
    rangeminparam = "NULL"
    rangemaxparam = "NULL"

    listparam = bbf.get_option_value(value, "list")
    if listparam is not None:
        datatypeparam = bbf.get_option_value(listparam, "datatype")
        maxsizeparam = bbf.get_option_value(listparam, "maxsize")
        if maxsizeparam is None:
            maxsizeparam = "-1"
        itemparam = bbf.get_option_value(listparam, "item")
        if itemparam is not None:
            itemminparam = bbf.get_option_value(itemparam, "min")
            if itemminparam is None:
                itemminparam = "-1"
            itemmaxparam = bbf.get_option_value(itemparam, "max")
            if itemmaxparam is None:
                itemmaxparam = "-1"

        rangeparam = getarrayoptionparam(listparam, "range")
        if rangeparam is not None:
            range_length = len(rangeparam)
            rangeargs = "RANGE_ARGS{"
            for i in range(range_length - 1):
                rangeminparam = bbf.get_option_value(rangeparam[i], "min")
                if rangeminparam is None:
                    rangeminparam = "NULL"
                rangemaxparam = bbf.get_option_value(rangeparam[i], "max")
                if rangemaxparam is None:
                    rangemaxparam = "NULL"
                rangeargs += "{\"%s\",\"%s\"}," % (
                    rangeminparam, rangemaxparam)
            rangeminparam = bbf.get_option_value(
                rangeparam[range_length - 1], "min")
            if rangeminparam is None:
                rangeminparam = "NULL"
            rangemaxparam = bbf.get_option_value(
                rangeparam[range_length - 1], "max")
            if rangemaxparam is None:
                rangemaxparam = "NULL"
            rangeargs += "{\"%s\",\"%s\"}}, %s" % (
                rangeminparam, rangemaxparam, range_length)
        else:
            rangeargs = "RANGE_ARGS{{NULL,NULL}}, 1"

        enumarationsparam = getarrayoptionparam(listparam, "enumerations")
        if enumarationsparam is not None:
            list_enumarationsparam = enumarationsparam
            enum_length = len(list_enumarationsparam)
            enumarationsparam = dmparam if datatypeparam == "string" else datatypeparam
            str_enum = "char *%s[] = {" % enumarationsparam
            for i in range(enum_length):
                str_enum += "\"%s\", " % list_enumarationsparam[i]
            str_enum += "NULL};"
            printGlobalstrCommon(str_enum)
        else:
            enumarationsparam = "NULL"

        patternparam = getarrayoptionparam(listparam, "pattern")
        if patternparam is not None:
            list_patternparam = patternparam
            pattern_length = len(list_patternparam)
            patternparam = dmparam if datatypeparam == "string" else datatypeparam
            str_pattern = "char *%s[] = {" % patternparam
            for i in range(pattern_length):
                str_pattern += "\"^%s$\", " % list_patternparam[i]
            str_pattern += "NULL};"
            printGlobalstrCommon(str_pattern)
        elif datatypeparam == "IPAddress":
            patternparam = "IPAddress"
        elif datatypeparam == "IPv6Address":
            patternparam = "IPv6Address"
        elif datatypeparam == "IPPrefix":
            patternparam = "IPPrefix"
        elif datatypeparam == "IPv6Prefix":
            patternparam = "IPv6Prefix"
        else:
            patternparam = "NULL"

        if datatypeparam == "unsignedInt":
            validate_value += "			if (dm_validate_unsignedInt_list(value, %s, %s, %s, %s))\n" % (
                itemminparam, itemmaxparam, maxsizeparam, rangeargs)
        else:
            if rangeminparam == "NULL":
                rangeminparam = "-1"
            if rangemaxparam == "NULL":
                rangemaxparam = "-1"
            validate_value += "			if (dm_validate_string_list(value, %s, %s, %s, %s, %s, %s, %s))\n" % (
                itemminparam, itemmaxparam, maxsizeparam, rangeminparam, rangemaxparam, enumarationsparam, patternparam)
    else:
        datatypeparam = bbf.get_option_value(value, "datatype")
        rangeparam = getarrayoptionparam(value, "range")
        if rangeparam is not None:
            range_length = len(rangeparam)
            rangeargs = "RANGE_ARGS{"
            for i in range(range_length - 1):
                rangeminparam = bbf.get_option_value(rangeparam[i], "min")
                if rangeminparam is None:
                    rangeminparam = "NULL"
                rangemaxparam = bbf.get_option_value(rangeparam[i], "max")
                if rangemaxparam is None:
                    rangemaxparam = "NULL"
                rangeargs += "{\"%s\",\"%s\"}," % (
                    rangeminparam, rangemaxparam)
            rangeminparam = bbf.get_option_value(
                rangeparam[range_length - 1], "min")
            if rangeminparam is None:
                rangeminparam = "NULL"
            rangemaxparam = bbf.get_option_value(
                rangeparam[range_length - 1], "max")
            if rangemaxparam is None:
                rangemaxparam = "NULL"
            rangeargs += "{\"%s\",\"%s\"}}, %s" % (
                rangeminparam, rangemaxparam, range_length)
        else:
            rangeargs = "RANGE_ARGS{{NULL,NULL}}, 1"

        enumarationsparam = getarrayoptionparam(value, "enumerations")
        if enumarationsparam is not None:
            list_enumarationsparam = enumarationsparam
            enum_length = len(list_enumarationsparam)
            enumarationsparam = dmparam if datatypeparam == "string" else datatypeparam
            str_enum = "char *%s[] = {" % enumarationsparam
            for i in range(enum_length):
                str_enum += "\"%s\", " % list_enumarationsparam[i]
            str_enum += "NULL};"
            printGlobalstrCommon(str_enum)
        else:
            enumarationsparam = "NULL"

        patternparam = getarrayoptionparam(value, "pattern")
        if patternparam is not None:
            list_patternparam = patternparam
            pattern_length = len(list_patternparam)
            patternparam = dmparam if datatypeparam == "string" else datatypeparam
            str_pattern = "char *%s[] = {" % patternparam
            for i in range(pattern_length):
                str_pattern += "\"^%s$\", " % list_patternparam[i]
            str_pattern += "NULL};"
            printGlobalstrCommon(str_pattern)
        elif datatypeparam == "IPAddress":
            patternparam = "IPAddress"
        elif datatypeparam == "IPv6Address":
            patternparam = "IPv6Address"
        elif datatypeparam == "IPPrefix":
            patternparam = "IPPrefix"
        elif datatypeparam == "IPv6Prefix":
            patternparam = "IPv6Prefix"
        else:
            patternparam = "NULL"

        if datatypeparam == "boolean":
            validate_value += "			if (dm_validate_boolean(value))\n"
        elif datatypeparam == "unsignedInt":
            validate_value += "			if (dm_validate_unsignedInt(value, %s))\n" % rangeargs
        elif datatypeparam == "int":
            validate_value += "			if (dm_validate_int(value, %s))\n" % rangeargs
        elif datatypeparam == "unsignedLong":
            validate_value += "			if (dm_validate_unsignedLong(value, %s))\n" % rangeargs
        elif datatypeparam == "long":
            validate_value += "			if (dm_validate_long(value, %s))\n" % rangeargs
        elif datatypeparam == "dateTime":
            validate_value += "			if (dm_validate_dateTime(value))\n"
        elif datatypeparam == "hexBinary":
            if rangeminparam == "NULL":
                rangeminparam = "-1"
            if rangemaxparam == "NULL":
                rangemaxparam = "-1"
            validate_value += "			if (dm_validate_hexBinary(value, %s))\n" % rangeargs
        else:
            if rangeminparam == "NULL":
                rangeminparam = "-1"
            if rangemaxparam == "NULL":
                rangemaxparam = "-1"
            validate_value += "			if (dm_validate_string(value, %s, %s, %s, %s))\n" % (
                rangeminparam, rangemaxparam, enumarationsparam, patternparam)
    validate_value += "				return FAULT_9007;"
    validate_value = validate_value.replace("\"NULL\"", "NULL")
    return validate_value


def printheaderObjCommon(objname):
    fp = open('./.objparamarray.c', 'a')
    print("/* *** %s *** */" % objname, file=fp)
    fp.close()


def cprintheaderOBJS(objname):
    fp = open('./.objparamarray.c', 'a')
    print("DMOBJ %s[] = {" % ("t" + getname(objname) + "Obj"), file=fp)
    print("/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/", file=fp)
    fp.close()


def hprintheaderOBJS(objname):
    fp = open('./.objparamarray.h', 'a')
    print("extern DMOBJ %s[];" % ("t" + getname(objname) + "Obj"), file=fp)
    fp.close()


def cprinttopfile(fp, filename):
    print("/*", file=fp)
    print(" * Copyright (C) 2020 iopsys Software Solutions AB", file=fp)
    print(" *", file=fp)
    print(" * This program is free software; you can redistribute it and/or modify", file=fp)
    print(" * it under the terms of the GNU Lesser General Public License version 2.1", file=fp)
    print(" * as published by the Free Software Foundation", file=fp)
    print(" *", file=fp)
    print(" *	Author: <Name> <Surname> <name.surname@iopsys.eu>", file=fp)
    print(" */", file=fp)
    print("", file=fp)
    print("#include \"%s.h\"" % filename.lower(), file=fp)
    print("", file=fp)


def hprinttopfile(fp, filename):
    print("/*", file=fp)
    print(" * Copyright (C) 2020 iopsys Software Solutions AB", file=fp)
    print(" *", file=fp)
    print(" * This program is free software; you can redistribute it and/or modify", file=fp)
    print(" * it under the terms of the GNU Lesser General Public License version 2.1", file=fp)
    print(" * as published by the Free Software Foundation", file=fp)
    print(" *", file=fp)
    print(" *	Author: <Name> <Surname> <name.surname@iopsys.eu>", file=fp)
    print(" */", file=fp)
    print("", file=fp)
    print("#ifndef __%s_H" % filename.upper(), file=fp)
    print("#define __%s_H" % filename.upper(), file=fp)
    print("", file=fp)
    print("#include <libbbf_api/dmcommon.h>", file=fp)
    print("", file=fp)


def hprintfootfile(fp, filename):
    print("", file=fp)
    print("#endif //__%s_H" % filename.upper(), file=fp)
    print("", file=fp)


def cprintAddDelObj(faddobj, fdelobj, name, mappingobj, _dmobject):
    fp = open('./.objadddel.c', 'a')
    print("static int %s(char *refparam, struct dmctx *ctx, void *data, char **instance)" %
          faddobj, file=fp)
    print("{", file=fp)
    if mappingobj is not None:
        dm_type, file, sectiontype, dmmapfile, _path, _ref = get_mapping_obj(
            mappingobj)
        if dm_type == "uci":
            print("	struct uci_section *dmmap = NULL, *s = NULL;", file=fp)
            print("", file=fp)
            print("	char *inst = get_last_instance_bbfdm(\"%s\", \"%s\", \"%s\");" %
                  (dmmapfile, sectiontype, name+"instance"), file=fp)
            print("	dmuci_add_section(\"%s\", \"%s\", &s);" %
                  (file, sectiontype), file=fp)
            print("	//dmuci_set_value_by_section(s, \"option\", \"value\");", file=fp)
            print("", file=fp)
            print("	dmuci_add_section_bbfdm(\"%s\", \"%s\", &dmmap);" %
                  (dmmapfile, sectiontype), file=fp)
            print(
                "	dmuci_set_value_by_section(dmmap, \"section_name\", section_name(s));", file=fp)
            print("	*instance = update_instance(inst, 2, dmmap, \"%s\");" %
                  (name+"instance"), file=fp)
    else:
        print("	//TODO", file=fp)
    print("	return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)
    print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)" % fdelobj, file=fp)
    print("{", file=fp)
    if mappingobj is not None:
        if dm_type == "uci":
            print(
                "	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;", file=fp)
            print("	int found = 0;", file=fp)
            print("", file=fp)
    print("	switch (del_action) {", file=fp)
    if mappingobj is not None:
        if dm_type == "uci":
            print("		case DEL_INST:", file=fp)
            print("			get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name((struct uci_section *)data), &dmmap_section);" %
                  (dmmapfile, sectiontype), file=fp)
            print("			if (dmmap_section != NULL)", file=fp)
            print("				dmuci_delete_by_section(dmmap_section, NULL, NULL);", file=fp)
            print(
                "			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);", file=fp)
            print("			break;", file=fp)
            print("		case DEL_ALL:", file=fp)
            print("			uci_foreach_sections(\"%s\", \"%s\", s) {" % (
                file, sectiontype), file=fp)
            print("				if (found != 0) {", file=fp)
            print("					get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name(ss), &dmmap_section);" % (
                dmmapfile, sectiontype), file=fp)
            print("					if (dmmap_section != NULL)", file=fp)
            print("						dmuci_delete_by_section(dmmap_section, NULL, NULL);", file=fp)
            print("					dmuci_delete_by_section(ss, NULL, NULL);", file=fp)
            print("				}", file=fp)
            print("				ss = s;", file=fp)
            print("				found++;", file=fp)
            print("			}", file=fp)
            print("			if (ss != NULL) {", file=fp)
            print("				get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name(ss), &dmmap_section);" % (
                dmmapfile, sectiontype), file=fp)
            print("				if (dmmap_section != NULL)", file=fp)
            print("					dmuci_delete_by_section(dmmap_section, NULL, NULL);", file=fp)
            print("				dmuci_delete_by_section(ss, NULL, NULL);", file=fp)
            print("			}", file=fp)
            print("			break;", file=fp)
    else:
        print("		case DEL_INST:", file=fp)
        print("			//TODO", file=fp)
        print("			break;", file=fp)
        print("		case DEL_ALL:", file=fp)
        print("			//TODO", file=fp)
        print("			break;", file=fp)
    print("	}", file=fp)
    print("	return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)
    fp.close()


def cprintBrowseObj(fbrowse, name, mappingobj, dmobject):
    # Open file
    fp = open('./.objbrowse.c', 'a')

    # Mapping Parameter
    if mappingobj is not None:
        dm_type, res1, res2, res3, res4, res5 = get_mapping_obj(mappingobj)
        if dm_type == "uci":
            print("/*#%s!%s:%s/%s/%s*/" %
                  (dmobject, dm_type.upper(), res1, res2, res3), file=fp)
        elif dm_type == "ubus":
            print("/*#%s!%s:%s/%s/%s,%s/%s*/" %
                  (dmobject, dm_type.upper(), res1, res2, res3, res4, res5), file=fp)

    print("static int %s(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)" % fbrowse, file=fp)
    print("{", file=fp)

    # Mapping exist
    if mappingobj is not None:

        ############################## UCI ########################################
        if dm_type == "uci":
            print("	char *inst = NULL, *max_inst = NULL;", file=fp)
            print("	struct dmmap_dup *p = NULL;", file=fp)
            print("	LIST_HEAD(dup_list);", file=fp)
            print("", file=fp)
            print("	synchronize_specific_config_sections_with_dmmap(\"%s\", \"%s\", \"%s\", &dup_list);" % (
                res1, res2, res3), file=fp)
            print("	list_for_each_entry(p, &dup_list, list) {", file=fp)
            print("", file=fp)
            print(
                "		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,", file=fp)
            print("			   p->dmmap_section, \"%s\", \"%s\");" %
                  (name+"instance", name+"alias"), file=fp)
            print("", file=fp)
            print("		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)", file=fp)
            print("			break;", file=fp)
            print("	}", file=fp)
            print("	free_dmmap_config_dup_list(&dup_list);", file=fp)

        ############################## UBUS ########################################
        elif dm_type == "ubus":
            print("	json_object *res = NULL, *obj = NULL, *arrobj = NULL;", file=fp)
            print("	char *inst = NULL, *max_inst = NULL;", file=fp)
            print("	int id = 0, i = 0;", file=fp)
            print("", file=fp)
            if res3 is None and res4 is None:
                print("	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{}, 0, &res);" %
                      (res1, res2), file=fp)
            else:
                print("	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", \"%s\", String}}, 1, &res);" % (
                    res1, res2, res3, res4), file=fp)
            print("	if (res) {", file=fp)
            print(
                "		dmjson_foreach_obj_in_array(res, arrobj, obj, i, 1, \"%s\") {" % res5, file=fp)
            print("", file=fp)
            print("			inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);", file=fp)
            print("", file=fp)
            print(
                "			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)obj, inst) == DM_STOP)", file=fp)
            print("				break;", file=fp)
            print("		}", file=fp)
            print("	}", file=fp)

    # Mapping doesn't exist
    else:
        print("	//TODO", file=fp)
    print("	return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)

    # Close file
    fp.close()


def cprintGetSetValue(getvalue, setvalue, mappingparam, instance, typeparam, parentname, dmparam, value):
    # Open file
    fp = open('./.getstevalue.c', 'a')

    # Generate Validate value
    validate_value = ""
    if setvalue != "NULL":
        validate_value = generate_validate_value(dmparam, value)

    # Mapping exist
    if mappingparam is not None:
        count = len(mappingparam)
        i = 0
        mapping = ""
        tmpgetvalue = ""
        tmpsetvalue = ""
        set_value = ""
        for element in mappingparam:
            dm_type, res1, res2, res3, res4, res5, res6, res7 = get_mapping_param(
                element)
            get_value = ""
            i += 1

            ############################## UCI ########################################
            if dm_type == "uci":
                # Mapping Parameter
                if res3 is not None:
                    mapping = "%s:%s/%s,%s/%s" % (dm_type.upper(),
                                                  res1, res2, res3, res5)
                else:
                    mapping = "%s:%s/%s,%s/%s" % (dm_type.upper(),
                                                  res1, res2, res4, res5)

                # GET VALUE Parameter
                if "NumberOfEntries" in dmparam:
                    get_value += "	struct uci_section *s = NULL;\n"
                    get_value += "	int cnt = 0;\n"
                    get_value += "\n"
                    get_value += "	uci_foreach_sections(\"%s\", \"%s\", s) {\n" % (
                        res1, res2)
                    get_value += "		cnt++;\n"
                    get_value += "	}\n"
                    get_value += "	dmasprintf(value, \"%d\", cnt);"
                elif "Alias" in dmparam:
                    get_value += "	struct uci_section *dmmap_section = NULL;\n"
                    get_value += "\n"
                    get_value += "	get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name((struct uci_section *)data), &dmmap_section);\n" % (
                        res1, res2)
                    get_value += "	dmuci_get_value_by_section_string(dmmap_section, \"%s\", value);\n" % res5
                    get_value += "	if ((*value)[0] == '\\0')\n"
                    get_value += "		dmasprintf(value, \"cpe-%s\", instance);"
                elif instance == "TRUE" and res6 is not None:
                    get_value += "	char uci_type[32] = {0};\n"
                    get_value += "\n"
                    get_value += "	snprintf(uci_type, sizeof(uci_type), \"@%s[%s]\", instance ? atoi(instance)-1 : 0);\n" % (
                        res2, "%d")
                    get_value += "	*value = bbf_uci_get_value(\"%s\", \"%s\", uci_type, \"%s\");" % (
                        res6, res1, res5)
                elif instance == "TRUE" and res7 is not None:
                    get_value += "	char *linker = dmstrdup(*value);\n"
                    get_value += "	adm_entry_get_linker_param(ctx, \"%s\", linker, value);\n" % res7
                    get_value += "	dmfree(linker);\n"
                    get_value += "	if (*value == NULL)\n"
                    get_value += "		*value = \"\";"
                elif res6 is not None:
                    get_value += "	*value = bbf_uci_get_value(\"%s\", \"%s\", \"%s\", \"%s\");" % (
                        res6, res1, res3, res5)
                elif instance == "TRUE":
                    get_value += "	dmuci_get_value_by_section_string((struct uci_section *)data, \"%s\", value);" % res5
                else:
                    get_value += "	dmuci_get_option_value_string(\"%s\", \"%s\", \"%s\", value);" % (
                        res1, res3, res5)

                # SET VALUE Parameter
                set_value += "	switch (action)	{\n"
                set_value += "		case VALUECHECK:\n"
                set_value += "%s\n" % validate_value
                set_value += "			break;\n"
                set_value += "		case VALUESET:\n"
                if typeparam == "boolean":
                    set_value += "			string_to_bool(value, &b);\n"
                    if instance == "TRUE":
                        set_value += "			dmuci_set_value_by_section((struct uci_section *)data, \"%s\", b ? \"1\" : \"0\");" % res5
                    else:
                        set_value += "			dmuci_set_value(\"%s\", \"%s\", \"%s\", b ? \"1\" : \"0\");" % (
                            res1, res3, res5)
                elif instance == "TRUE":
                    set_value += "			dmuci_set_value_by_section((struct uci_section *)data, \"%s\", value);" % res5
                else:
                    set_value += "			dmuci_set_value(\"%s\", \"%s\", \"%s\", value);" % (
                        res1, res3, res5)

            ############################## UBUS ########################################
            elif dm_type == "ubus":
                # Mapping Parameter
                if res3 is not None and res4 is not None:
                    mapping = "%s:%s/%s/%s,%s/%s" % (
                        dm_type.upper(), res1, res2, res3, res4, res5)
                else:
                    mapping = "%s:%s/%s//%s" % (dm_type.upper(), res1, res2, res5)

                # GET VALUE Parameter
                if instance == "TRUE":
                    options = res5.split(".")
                    if len(options) == 3:
                        get_value += "	*value = dmjson_get_value((json_object *)data, 2, \"%s\", \"%s\");\n" % (
                            options[1], options[2])
                    elif len(options) == 2:
                        get_value += "	*value = dmjson_get_value((json_object *)data, 1, \"%s\");\n" % options[
                            1]
                else:
                    get_value += "	json_object *res;\n"
                    if res3 is None and res4 is None:
                        get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{}, 0, &res);\n" % (
                            res1, res2)
                    else:
                        if i == 2 and res4 == "prev_value":
                            get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", *value, String}}, 1, &res);\n" % (
                                res1, res2, res3)

                        elif i == 2 and res4 == "@Name":
                            get_value += "	if (*value[0] == '\\0')\n"
                            get_value += "	{\n"
                            get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", section_name((struct uci_section *)data), String}}, 1, &res);\n" % (
                                res1, res2, res3)
                        elif res4 == "@Name":
                            get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", section_name((struct uci_section *)data), String}}, 1, &res);\n" % (
                                res1, res2, res3)
                        else:
                            get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", \"%s\", String}}, 1, &res);\n" % (
                                res1, res2, res3, res4)

                    get_value += "	DM_ASSERT(res, *value = \"\");\n"
                    option = res5.split(".")
                    if "." in res5:
                        if option[0] == "@Name":
                            get_value += "	*value = dmjson_get_value(res, 2, section_name((struct uci_section *)data), \"%s\");" % (
                                option[1])
                        else:
                            get_value += "	*value = dmjson_get_value(res, 2, \"%s\", \"%s\");" % (
                                option[0], option[1])
                    else:
                        get_value += "	*value = dmjson_get_value(res, 1, \"%s\");" % option[0]
                    if i == 2 and res4 == "@Name":
                        get_value += "\n	}"

                # SET VALUE Parameter
                set_value += "	switch (action)	{\n"
                set_value += "		case VALUECHECK:\n"
                set_value += "%s\n" % validate_value
                set_value += "			break;\n"
                set_value += "		case VALUESET:\n"
                set_value += "			//TODO"

            ############################## SYSFS ########################################
            elif dm_type == "sysfs":
                # Mapping Parameter
                mapping = "%s:%s" % (dm_type.upper(), res1)

                # GET VALUE Parameter
                if res1[:15] == "/sys/class/net/" and res1[15:20] == "@Name":
                    get_value += "	get_net_device_sysfs(section_name((struct uci_section *)data), \"%s\", value);" % res1[
                        21:]
                else:
                    get_value += "	char val[64];\n"
                    get_value += "\n"
                    get_value += "	dm_read_sysfs_file(\"%s\", val, sizeof(val));\n" % res1
                    get_value += "	*value = dmstrdup(val);"

            ############################## PROCFS ########################################
            elif dm_type == "procfs":
                # Mapping Parameter
                mapping = "%s:%s" % (dm_type.upper(), res1)

                # GET VALUE Parameter
                get_value += "	char val[64];\n"
                get_value += "\n"
                get_value += "	dm_read_sysfs_file(\"%s\", val, sizeof(val));\n" % res1
                get_value += "	*value = dmstrdup(val);"

            ############################## CLI ########################################
            elif dm_type == "cli":
                # GET VALUE Parameter
                get_value += "	dmcmd(\"%s\", %s, %s);" % (res1, res2, res3)

            if count == 2 and i == 1:
                tmpmapping = mapping
                tmpgetvalue = get_value
                tmpsetvalue = set_value
            elif count == 2 and i == 2:
                print("/*#%s!%s&%s*/" %
                      (parentname+dmparam, tmpmapping, mapping), file=fp)
                print(
                    "static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getvalue, file=fp)
                print("{", file=fp)
                print("%s" % tmpgetvalue, file=fp)
                print("%s" % get_value, file=fp)
                print("	return 0;", file=fp)
                print("}", file=fp)
                print("", file=fp)
                if setvalue != "NULL":
                    print(
                        "static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % setvalue, file=fp)
                    print("{", file=fp)
                    print("%s" % tmpsetvalue, file=fp)
                    print("			break;", file=fp)
                    print("	}", file=fp)
                    print("	return 0;", file=fp)
                    print("}", file=fp)
                    print("", file=fp)
            else:
                print("/*#%s!%s*/" % (parentname+dmparam, mapping), file=fp)
                print(
                    "static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getvalue, file=fp)
                print("{", file=fp)
                print("%s" % get_value, file=fp)
                print("	return 0;", file=fp)
                print("}", file=fp)
                print("", file=fp)
                if setvalue != "NULL":
                    print(
                        "static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % setvalue, file=fp)
                    print("{", file=fp)
                    print("%s" % set_value, file=fp)
                    print("			break;", file=fp)
                    print("	}", file=fp)
                    print("	return 0;", file=fp)
                    print("}", file=fp)
                    print("", file=fp)

    # Mapping doesn't exist
    else:
        print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getvalue, file=fp)
        print("{", file=fp)
        print("	//TODO", file=fp)
        print("	return 0;", file=fp)
        print("}", file=fp)
        print("", file=fp)
        if setvalue != "NULL":
            print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % setvalue, file=fp)
            print("{", file=fp)
            print("	switch (action)	{", file=fp)
            print("		case VALUECHECK:", file=fp)
            print("%s" % validate_value, file=fp)
            print("			break;", file=fp)
            print("		case VALUESET:", file=fp)
            print("			//TODO", file=fp)
            print("			break;", file=fp)
            print("	}", file=fp)
            print("	return 0;", file=fp)
            print("}", file=fp)
            print("", file=fp)

    # Close file
    fp.close()


def cprintOperateCommands(getoperateargs, operate, in_args, out_args, struct_name):
    # Open file
    fp = open('./.operatecommands.c', 'a')
    
    if in_args != None or out_args != None:
        ############################## OPERATE ARGUMENTS ########################################
        print("static operation_args %s = {" % struct_name, file=fp)
        
        if in_args != None:
            if isinstance(in_args, dict):
                print("    .in = (const char *[]) {", file=fp)
                for obj, _val in in_args.items():
                    print("        \"%s\"," % obj, file=fp)
                print("        NULL", file=fp)
                print("    %s" % ("}," if out_args != None else "}"), file=fp)

        if out_args != None:
            if isinstance(out_args, dict):
                print("    .out = (const char *[]) {", file=fp)
                for obj, _val in out_args.items():
                    print("        \"%s\"," % obj, file=fp)
                print("        NULL", file=fp)
                print("    }", file=fp)
        
        print("};", file=fp)
        print("", file=fp)
    
        print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getoperateargs, file=fp)
        print("{", file=fp)
        print("    *value = (char *)&%s;" % struct_name, file=fp)
        print("    return 0;", file=fp)
        print("}", file=fp)
        print("", file=fp)

    ############################## OPERATE ########################################
    print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % operate, file=fp)
    print("{", file=fp)
    print("    //TODO", file=fp)
    print("    return CMD_SUCCESS;", file=fp)
    print("}", file=fp)
    print("", file=fp)

    # Close file
    fp.close()  


def cprintEvent(geteventargs, param_args, struct_name):
    # Open file
    fp = open('./.events.c', 'a')
    
    if param_args != None:
        ############################## OPERATE ARGUMENTS ########################################
        print("static event_args %s = {" % struct_name, file=fp)
        if isinstance(param_args, dict):
            print("    .param = (const char *[]) {", file=fp)
            for obj, _val in param_args.items():
                print("        \"%s\"," % obj, file=fp)
            print("        NULL", file=fp)
            print("    }", file=fp)
    
        print("};", file=fp)
        print("", file=fp)
    
        print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % geteventargs, file=fp)
        print("{", file=fp)
        print("    *value = (char *)&%s;" % struct_name, file=fp)
        print("    return 0;", file=fp)
        print("}", file=fp)
        print("", file=fp)

    # Close file
    fp.close()  


def cprintheaderPARAMS(objname):
    fp = open('./.objparamarray.c', 'a')
    print("DMLEAF %s[] = {" % ("t" + getname(objname) + "Params"), file=fp)
    print("/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/", file=fp)
    fp.close()


def hprintheaderPARAMS(objname):
    fp = open('./.objparamarray.h', 'a')
    print("extern DMLEAF %s[];" % ("t" + getname(objname) + "Params"), file=fp)
    fp.close()


def printPARAMline(parentname, dmparam, value):
    commonname = getname(parentname) + "_" + dmparam
    ptype = bbf.get_param_type(value)
    getvalue = "get_" + commonname
    mappingparam = bbf.get_option_value(value, "mapping")
    typeparam = bbf.get_option_value(value, "type")
    bbfdm = getprotocolsparam(value, "protocols")
    accessparam = bbf.get_option_value(value, "write")

    if accessparam:
        access = "&DMWRITE"
        setvalue = "set_" + commonname
    else:
        access = "&DMREAD"
        setvalue = "NULL"

    if parentname.endswith(".{i}."):
        instance = "TRUE"
    else:
        instance = "FALSE"

    cprintGetSetValue(getvalue, setvalue, mappingparam,
                      instance, typeparam, parentname, dmparam, value)

    fp = open('./.objparamarray.c', 'a')
    print("{\"%s\", %s, %s, %s, %s, %s}," %
          (dmparam, access, ptype, getvalue, setvalue, bbfdm), file=fp)
    fp.close()


def printCOMMANDline( parentname, dmparam, value ):
    commonname = getname(parentname) + "_" + dmparam
    ptype = bbf.get_param_type(value)
    operate = "operate_" + commonname.replace("()", "")
    bbfdm = getprotocolsparam(value, "protocols")
    asyncparam = bbf.get_option_value(value, "async")
    in_args = bbf.get_option_value(value, "input")
    out_args = bbf.get_option_value(value, "output")

    if asyncparam:
        c_type = "&DMASYNC"
    else:
        c_type = "&DMSYNC"
        
    if in_args != None or out_args != None:
        getoperateargs = "get_operate_args_" + commonname.replace("()", "")
    else:
        getoperateargs = "NULL"

    cprintOperateCommands(getoperateargs, operate, in_args, out_args, commonname.replace("()", "").lower()+"_args")

    fp = open('./.objparamarray.c', 'a')
    print("{\"%s\", %s, %s, %s, %s, %s}," % (dmparam, c_type, ptype, getoperateargs, operate, bbfdm), file=fp)
    fp.close()


def printEVENTline( parentname, dmparam, value ):
    commonname = getname(parentname) + "_" + dmparam
    ptype = bbf.get_param_type(value)
    bbfdm = getprotocolsparam(value, "protocols")
    hasparam = bbf.obj_has_param(value)
        
    if hasparam:
        geteventargs = "get_event_args_" + commonname.replace("!", "")
        cprintEvent(geteventargs, value, commonname.replace("!", "").lower()+"_args")
    else:
        geteventargs = "NULL"

    fp = open('./.objparamarray.c', 'a')
    print("{\"%s\", &DMREAD, %s, %s, NULL, %s}," % (dmparam, ptype, geteventargs, bbfdm), file=fp)
    fp.close()


def printtailArray():
    fp = open('./.objparamarray.c', 'a')
    print("{0}", file=fp)
    print("};", file=fp)
    print("", file=fp)
    fp.close()


def printOBJline(dmobject, value):
    commonname = getname(dmobject)
    hasobj = bbf.obj_has_child(value)
    hasparam = bbf.obj_has_param(value)
    accessobj = bbf.get_option_value(value, "access")
    mappingobj = bbf.get_option_value(value, "mapping")
    bbfdm = getprotocolsparam(value, "protocols")
    uniquekeys = getuniquekeys(value, "uniqueKeys")

    if accessobj:
        access = "&DMWRITE"
        faddobj = "addObj" + commonname
        fdelobj = "delObj" + commonname
        cprintAddDelObj(faddobj, fdelobj, (getlastname(
            dmobject)).lower(), mappingobj, dmobject)
    else:
        access = "&DMREAD"
        faddobj = "NULL"
        fdelobj = "NULL"

    if dmobject.endswith(".{i}."):
        fbrowse = "browse" + commonname + "Inst"
        cprintBrowseObj(fbrowse, (getlastname(dmobject)
                                  ).lower(), mappingobj, dmobject)
    else:
        fbrowse = "NULL"

    if hasobj:
        objchildarray = "t" + commonname + "Obj"
    else:
        objchildarray = "NULL"

    if hasparam:
        paramarray = "t" + commonname + "Params"
    else:
        paramarray = "NULL"

    fp = open('./.objparamarray.c', 'a')
    if uniquekeys:
        print("{\"%s\", %s, %s, %s, NULL, %s, NULL, NULL, %s, %s, NULL, %s, %s}," % (getlastname(
            dmobject), access, faddobj, fdelobj, fbrowse, objchildarray, paramarray, bbfdm, uniquekeys), file=fp)
    else:
        print("{\"%s\", %s, %s, %s, NULL, %s, NULL, NULL, %s, %s, NULL, %s}," % (getlastname(
            dmobject), access, faddobj, fdelobj, fbrowse, objchildarray, paramarray, bbfdm), file=fp)
    fp.close()


def print_dmc_usage():
    print("Usage: " + sys.argv[0] + " <data model name>" + " [Object path]")
    print("data model name:   The data model(s) to be used, for ex: tr181 or tr181,tr104")
    print("Examples:")
    print("  - " + sys.argv[0] + " tr181")
    print("    ==> Generate the C code of tr181 data model in datamodel/ folder")
    print("  - " + sys.argv[0] + " tr104")
    print("    ==> Generate the C code of tr104 data model in datamodel/ folder")
    print("  - " + sys.argv[0] + " tr181,tr104")
    print("    ==> Generate the C code of tr181 and tr104 data model in datamodel/ folder")
    print("  - " + sys.argv[0] + " tr181" + " Device.DeviceInfo.")
    print("    ==> Generate the C code of Device.DeviceInfo object in datamodel/ folder")
    print("  - " + sys.argv[0] + " tr104" +
          " Device.Services.VoiceService.{i}.Capabilities.")
    print(
        "    ==> Generate the C code of Device.Services.VoiceService.{i}.Capabilities. object in datamodel/ folder")


def object_parse_childs(dmobject, value, nextlevel):
    hasobj = bbf.obj_has_child(value)
    hasparam = bbf.obj_has_param(value)

    if hasobj or hasparam:
        printheaderObjCommon(dmobject)

    if hasobj:
        cprintheaderOBJS(dmobject)
        hprintheaderOBJS(dmobject)

        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if k1 == "type" and v1 == "object":
                            printOBJline(k, v)
                            break
        printtailArray()

    if hasparam:
        cprintheaderPARAMS(dmobject)
        hprintheaderPARAMS(dmobject)
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "mapping":
                    continue
                if isinstance(v, dict):
                    for k1, v1 in v.items():

                        if k1 == "type" and v1 == "command":
                            printCOMMANDline(dmobject, k, v)
                            break

                        if k1 == "type" and v1 == "event":
                            printEVENTline(dmobject, k, v)
                            break

                        if k1 == "type" and v1 != "object":
                            printPARAMline(dmobject, k, v)
                            break

        printtailArray()

    if hasobj and nextlevel == 0:
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if k1 == "type" and v1 == "object":
                            object_parse_childs(k, v, 0)


def generatecfromobj(pobj, pvalue, pdir, nextlevel):
    bbf.create_folder(pdir)
    removetmpfiles()
    object_parse_childs(pobj, pvalue, nextlevel)

    dmfpc = open(pdir + "/" + getname(pobj).lower() + ".c", "w")
    dmfph = open(pdir + "/" + getname(pobj).lower() + ".h", "w")
    cprinttopfile(dmfpc, getname(pobj).lower())
    hprinttopfile(dmfph, getname(pobj).lower())

    try:
        exists = os.path.isfile("./.objbrowse.c")
        if exists:
            print(
                "/*************************************************************", file=dmfpc)
            print("* ENTRY METHOD", file=dmfpc)
            print(
                "**************************************************************/", file=dmfpc)
        tmpf = open("./.objbrowse.c", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        exists = os.path.isfile("./.objadddel.c")
        if exists:
            print(
                "/*************************************************************", file=dmfpc)
            print("* ADD & DEL OBJ", file=dmfpc)
            print(
                "**************************************************************/", file=dmfpc)
        tmpf = open("./.objadddel.c", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        exists = os.path.isfile("./.getstevalue.c")
        if exists:
            print(
                "/*************************************************************", file=dmfpc)
            print("* GET & SET PARAM", file=dmfpc)
            print(
                "**************************************************************/", file=dmfpc)
        tmpf = open("./.getstevalue.c", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        exists = os.path.isfile("./.operatecommands.c")
        if exists:
            print("/*************************************************************", file=dmfpc)
            print("* OPERATE COMMANDS", file=dmfpc)
            print("**************************************************************/", file=dmfpc)
        tmpf = open("./.operatecommands.c", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        exists = os.path.isfile("./.events.c")
        if exists:
            print("/*************************************************************", file=dmfpc)
            print("* EVENTS", file=dmfpc)
            print("**************************************************************/", file=dmfpc)
        tmpf = open("./.events.c", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        print("/**********************************************************************************************************************************", file=dmfpc)
        print("*                                            OBJ & PARAM DEFINITION", file=dmfpc)
        print("***********************************************************************************************************************************/", file=dmfpc)
        tmpf = open("./.objparamarray.c", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        tmpf = open("./.objparamarray.h", "r")
        tmpd = tmpf.read()
        tmpf.close()
        dmfph.write(tmpd)
        print("", file=dmfph)
    except IOError:
        pass

    hprintfootfile(dmfph, getname(pobj).lower())
    removetmpfiles()


def removetmpfiles():
    bbf.remove_file("./.objparamarray.c")
    bbf.remove_file("./.objparamarray.h")
    bbf.remove_file("./.objadddel.c")
    bbf.remove_file("./.objbrowse.c")
    bbf.remove_file("./.getstevalue.c")
    bbf.remove_file("./.operatecommands.c")
    bbf.remove_file("./.events.c")


### main ###
if len(sys.argv) < 2:
    print_dmc_usage()
    exit(1)

if (sys.argv[1]).lower() == "-h" or (sys.argv[1]).lower() == "--help":
    print_dmc_usage()
    exit(1)

bbf.remove_folder(DMC_DIR)
dm_name = sys.argv[1].split(",")
for index in range(sys.argv[1].count(',') + 1):

    JSON_FILE = bbf.ARRAY_JSON_FILES.get(dm_name[index], None)

    if JSON_FILE is not None:
        j_file = open(JSON_FILE, "r")
        data = json.loads(j_file.read(), object_pairs_hook=OrderedDict)

        for dm_obj, dm_value in data.items():
            if dm_obj is None:
                print("Wrong JSON Data model format!")
                continue

            # Generate the object file if it is defined by "sys.argv[2]" argument
            if len(sys.argv) > 2:
                if sys.argv[2] != dm_obj:
                    if isinstance(dm_value, dict):
                        for obj1, value1 in dm_value.items():
                            if obj1 == sys.argv[2]:
                                if isinstance(value1, dict):
                                    for obj2, value2 in value1.items():
                                        if obj2 == "type" and value2 == "object":
                                            generatecfromobj(
                                                obj1, value1, DMC_DIR, 0)
                                            break
                                break
                    break

            # Generate the root object tree file if amin does not exist
            generatecfromobj(dm_obj, dm_value, DMC_DIR, 1)

            # Generate the sub object tree file if amin does not exist
            if isinstance(dm_value, dict):
                for obj1, value1 in dm_value.items():
                    if isinstance(value1, dict):
                        for obj2, value2 in value1.items():
                            if obj2 == "type" and value2 == "object":
                                generatecfromobj(obj1, value1, DMC_DIR, 0)
    else:
        print("!!!! %s : Data Model doesn't exist" % dm_name[index])

if os.path.isdir(DMC_DIR):
    print("Source code generated under \"%s\" folder" % DMC_DIR)
else:
    print("No source code generated!")
