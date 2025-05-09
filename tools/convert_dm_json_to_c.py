#!/usr/bin/python3

# Copyright (C) 2024 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

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
    fp = open(DMC_DIR + "/common.c", 'a', encoding='utf-8')
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
            validate_value += "			if (bbfdm_validate_unsignedInt_list(ctx, value, %s, %s, %s, %s))\n" % (
                itemminparam, itemmaxparam, maxsizeparam, rangeargs)
        else:
            if rangeminparam == "NULL":
                rangeminparam = "-1"
            if rangemaxparam == "NULL":
                rangemaxparam = "-1"
            validate_value += "			if (bbfdm_validate_string_list(ctx, value, %s, %s, %s, %s, %s, %s, %s))\n" % (
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
            validate_value += "			if (bbfdm_validate_boolean(ctx, value))\n"
        elif datatypeparam == "unsignedInt":
            validate_value += "			if (bbfdm_validate_unsignedInt(ctx, value, %s))\n" % rangeargs
        elif datatypeparam == "int":
            validate_value += "			if (bbfdm_validate_int(ctx, value, %s))\n" % rangeargs
        elif datatypeparam == "unsignedLong":
            validate_value += "			if (bbfdm_validate_unsignedLong(ctx, value, %s))\n" % rangeargs
        elif datatypeparam == "long":
            validate_value += "			if (bbfdm_validate_long(ctx, value, %s))\n" % rangeargs
        elif datatypeparam == "dateTime":
            validate_value += "			if (bbfdm_validate_dateTime(ctx, value))\n"
        elif datatypeparam == "hexBinary":
            if rangeminparam == "NULL":
                rangeminparam = "-1"
            if rangemaxparam == "NULL":
                rangemaxparam = "-1"
            validate_value += "			if (bbfdm_validate_hexBinary(ctx, value, %s))\n" % rangeargs
        else:
            if rangeminparam == "NULL":
                rangeminparam = "-1"
            if rangemaxparam == "NULL":
                rangemaxparam = "-1"
            validate_value += "			if (bbfdm_validate_string(ctx, value, %s, %s, %s, %s))\n" % (
                rangeminparam, rangemaxparam, enumarationsparam, patternparam)
    validate_value += "				return FAULT_9007;"
    validate_value = validate_value.replace("\"NULL\"", "NULL")
    return validate_value


def printheaderObjCommon(objname):
    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
    print("/* *** %s *** */" % objname, file=fp)
    fp.close()


def cprintheaderOBJS(objname):
    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
    print("DMOBJ %s[] = {" % ("t" + getname(objname) + "Obj"), file=fp)
    print("/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */", file=fp)
    fp.close()


def hprintheaderOBJS(objname):
    fp = open('./.objparamarray.h', 'a', encoding='utf-8')
    print("extern DMOBJ %s[];" % ("t" + getname(objname) + "Obj"), file=fp)
    fp.close()


def cprinttopfile(fp, filename):
    print("/*", file=fp)
    print(" * Copyright (C) 2023 iopsys Software Solutions AB", file=fp)
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
    print(" * Copyright (C) 2023 iopsys Software Solutions AB", file=fp)
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
    print("#include <libbbfdm-api/legacy/dmcommon.h>", file=fp)
    print("", file=fp)


def hprintfootfile(fp, filename):
    print("", file=fp)
    print("#endif //__%s_H" % filename.upper(), file=fp)
    print("", file=fp)


def cprintAddDelObj(faddobj, fdelobj):
    fp = open('./.objadddel.c', 'a', encoding='utf-8')
    print("static int %s(char *refparam, struct dmctx *ctx, void *data, char **instance)" %
          faddobj, file=fp)
    print("{", file=fp)
    print("	//TODO", file=fp)
    print("	return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)
    print("static int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)" % fdelobj, file=fp)
    print("{", file=fp)
    print("	//TODO", file=fp)
    print("	return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)
    fp.close()


def cprintBrowseObj(fbrowse, mappingobj, dmobject):
    # Open file
    fp = open('./.objbrowse.c', 'a', encoding='utf-8')

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
    print("	//TODO", file=fp)
    print("	return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)

    # Close file
    fp.close()


def cprintGetSetValue(getvalue, setvalue, dmparam, value):
    # Open file
    fp = open('./.getstevalue.c', 'a', encoding='utf-8')

    # Generate Validate value
    validate_value = ""
    if setvalue != "NULL":
        validate_value = generate_validate_value(dmparam, value)

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
    fp = open('./.operatecommands.c', 'a', encoding='utf-8')
    
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
    print("    return 0;", file=fp)
    print("}", file=fp)
    print("", file=fp)

    # Close file
    fp.close()  


def cprintEvent(geteventargs, param_args, struct_name):
    # Open file
    fp = open('./.events.c', 'a', encoding='utf-8')
    
    if param_args != None:
        ############################## OPERATE ARGUMENTS ########################################
        print("static event_args %s = {" % struct_name, file=fp)
        if isinstance(param_args, dict):
            print("    .name = \"\"", file=fp)
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
    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
    print("DMLEAF %s[] = {" % ("t" + getname(objname) + "Params"), file=fp)
    print("/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */", file=fp)
    fp.close()


def hprintheaderPARAMS(objname):
    fp = open('./.objparamarray.h', 'a', encoding='utf-8')
    print("extern DMLEAF %s[];" % ("t" + getname(objname) + "Params"), file=fp)
    fp.close()


def printPARAMline(parentname, dmparam, value):
    commonname = getname(parentname) + "_" + dmparam
    ptype = bbf.get_param_type(value)
    getvalue = "get_" + commonname
    bbfdm = getprotocolsparam(value, "protocols")
    accessparam = bbf.get_option_value(value, "write")

    if accessparam:
        access = "&DMWRITE"
        setvalue = "set_" + commonname
    else:
        access = "&DMREAD"
        setvalue = "NULL"

    cprintGetSetValue(getvalue, setvalue, dmparam, value)

    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
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

    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
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

    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
    print("{\"%s\", &DMREAD, %s, %s, NULL, %s}," % (dmparam, ptype, geteventargs, bbfdm), file=fp)
    fp.close()


def printtailArray():
    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
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

    if accessobj:
        access = "&DMWRITE"
        faddobj = "addObj" + commonname
        fdelobj = "delObj" + commonname
        cprintAddDelObj(faddobj, fdelobj)
    else:
        access = "&DMREAD"
        faddobj = "NULL"
        fdelobj = "NULL"

    if dmobject.endswith(".{i}."):
        fbrowse = "browse" + commonname + "Inst"
        cprintBrowseObj(fbrowse, mappingobj, dmobject)
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

    fp = open('./.objparamarray.c', 'a', encoding='utf-8')
    print("{\"%s\", %s, %s, %s, NULL, %s, NULL, NULL, %s, %s, NULL, %s, NULL}," % (getlastname(
        dmobject), access, faddobj, fdelobj, fbrowse, objchildarray, paramarray, bbfdm), file=fp)
    fp.close()


def print_dmc_usage():
    print("Usage: " + sys.argv[0] + " [Object path]")
    print("Examples:")
    print("  - " + sys.argv[0])
    print("    ==> Generate the C code of full data model in datamodel/ folder")
    print("  - " + sys.argv[0] + " Device.DeviceInfo.")
    print("    ==> Generate the C code of Device.DeviceInfo object in datamodel/ folder")
    print("  - " + sys.argv[0] + " Device.Services.VoiceService.{i}.DECT.Base.{i}.")
    print("    ==> Generate the C code for a specific multi-instance object in datamodel/ folder")

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

    dmfpc = open(pdir + "/" + getname(pobj).lower() + ".c", "w", encoding='utf-8')
    dmfph = open(pdir + "/" + getname(pobj).lower() + ".h", "w", encoding='utf-8')
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
        tmpf = open("./.objbrowse.c", "r", encoding='utf-8')
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
        tmpf = open("./.objadddel.c", "r", encoding='utf-8')
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
        tmpf = open("./.getstevalue.c", "r", encoding='utf-8')
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
        tmpf = open("./.operatecommands.c", "r", encoding='utf-8')
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
        tmpf = open("./.events.c", "r", encoding='utf-8')
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        print("/**********************************************************************************************************************************", file=dmfpc)
        print("*                                            OBJ & PARAM DEFINITION", file=dmfpc)
        print("***********************************************************************************************************************************/", file=dmfpc)
        tmpf = open("./.objparamarray.c", "r", encoding='utf-8')
        tmpd = tmpf.read()
        tmpf.close()
        dmfpc.write(tmpd)
    except IOError:
        pass

    try:
        tmpf = open("./.objparamarray.h", "r", encoding='utf-8')
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


def generatecfromspecificobj(passed_data, obj_to_find):
    for _obj, _value in passed_data.items():
        if isinstance(_value, dict) and 'type' in _value and _value['type'] == "object":
            if _obj != obj_to_find:
                generatecfromspecificobj(_value, obj_to_find)
            else:
                return generatecfromobj(_obj, _value, DMC_DIR, 0)


### main ###
if len(sys.argv) > 1 and (sys.argv[1]).lower() in ["-h", "--help"]:
    print_dmc_usage()
    exit(1)

bbf.remove_folder(DMC_DIR)

json_file = open(bbf.DM_JSON_FILE, "r", encoding='utf-8')
data = json.loads(json_file.read(), object_pairs_hook=OrderedDict)

for dm_obj, dm_value in data.items():

    if dm_obj is None or not isinstance(dm_value, dict):
        print("Wrong JSON Data model format!")
        exit(0)

    # Generate the object file if it is defined by "sys.argv[1]" argument
    if len(sys.argv) > 1 and sys.argv[1] != dm_obj:
        generatecfromspecificobj(dm_value, sys.argv[1])
        break

    # Generate the root object tree file
    generatecfromobj(dm_obj, dm_value, DMC_DIR, 1)

    # Generate the sub object tree file
    for obj1, value1 in dm_value.items():
        if isinstance(value1, dict) and 'type' in value1 and value1['type'] == "object":
            generatecfromobj(obj1, value1, DMC_DIR, 0)


if os.path.isdir(DMC_DIR):
    print("Source code generated under \"%s\" folder" % DMC_DIR)
else:
    print("No source code generated!")
