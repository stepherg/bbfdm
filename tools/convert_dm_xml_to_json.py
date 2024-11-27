#!/usr/bin/python3

# Copyright (C) 2024 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

import os
import sys
import xml.etree.ElementTree as xml
import json
import re

LIST_DATA_MODEL = []
desc_dict = {}
XML_ROOT = None

listTypes = ["string",
             "unsignedInt",
             "unsignedLong",
             "int",
             "long",
             "boolean",
             "dateTime",
             "hexBinary",
             "base64"]

listdataTypes = ["string",
                 "unsignedInt",
                 "unsignedLong",
                 "int",
                 "long",
                 "boolean",
                 "dateTime",
                 "hexBinary",
                 "base64",
                 "IPAddress",
                 "IPv4Address",
                 "IPv6Address",
                 "IPPrefix",
                 "IPv4Prefix",
                 "IPv6Prefix",
                 "MACAddress",
                 "decimal",
                 "IoTDeviceType",
                 "IoTLevelType",
                 "IoTUnitType",
                 "IoTEnumSensorType",
                 "IoTEnumControlType"]


def getuniquekeys(dmobject):
    uniquekeys = None
    for c in dmobject:
        if c.tag == "uniqueKey":
            for s in c:
                if s.tag == "parameter":
                    if uniquekeys is None:
                        uniquekeys = "\"%s\"" % s.get('ref')
                    else:
                        uniquekeys = uniquekeys + "," + "\"%s\"" % s.get('ref')
    return uniquekeys
    
def getparamtype(dmparam):
    ptype = None
    for s in dmparam:
        if s.tag == "syntax":
            for c in s:
                if c.tag == "list":
                    ptype = "string"
                    break
                if c.tag == "dataType":
                    reftype = c.get("ref")
                    if reftype == "StatsCounter32" or reftype == "PSDBreakPointIndexAndLevel" or reftype == "PSMBreakPointIndexAndLevel" or reftype == "SELTPAttenuationCharacteristicsIndexAndTFlog" or reftype == "Order":
                        ptype = "unsignedInt"
                        break
                    elif reftype == "StatsCounter64":
                        ptype = "unsignedLong"
                        break
                    elif reftype == "Dbm1000" or reftype == "UERComplex":
                        ptype = "int"
                        break
                    else:
                        ptype = "string"
                        break
                ptype = c.tag
                break
            break
    if ptype is None:
        ptype = "__NA__"
    return ptype


def getParamDefault(dmparam):
    default = None
    for s in dmparam:
        if s.tag == "syntax":
            for c in s:
                if c.tag == "default":
                    default = c.get("value")
                    break
            break
    return default


def process_datatypes(datatype):
    key = None
    enum = None
    des = None
    if datatype.tag == "dataType":
        key = datatype.get("name")
        if not key:
            return

        if key in desc_dict:
            return

        for dt in datatype:
            if dt.tag == "description":
                des = dt.text
                break

        if des is None:
            desc_dict[key] = ""
            return
        elif '{{enum}}' in des:
            for c in datatype:
                if c.tag == "string":
                    for e in c:
                        if e.tag == "enumeration":
                            if enum is None:
                                enum = "Enumeration of: " + e.get("value")
                            else:
                                enum += ", " + e.get("value")

            if enum is not None:
                enum += "."
                des = re.sub('{{enum}}', enum, des)

        des = des.replace("{", "<").replace("}", ">").replace("'", "").replace("\"", "")
        desc_dict[key] = des


def get_param_desc(dmparam, key):
    text = None
    enum = None
    for s in dmparam:
        if s.tag == "description":
            text = s.text

    if not text:
        return ""

    if '{{enum}}' in text:
        for s in dmparam:
            if s.tag != "syntax":
                continue

            for c in s:
                if c.tag != "string":
                    continue

                for e in c:
                    if e.tag == "enumeration":
                        if enum is None:
                            enum = "Enumeration of: " + e.get("value")
                        else:
                            enum += ", " + e.get("value")

        if enum is not None:
            enum += "."
            text = re.sub('{{enum}}', enum, text)

    if '{{datatype|expand}}' in text and key is not None:
        detail = desc_dict.get(key)
        if detail is not None:
            text = re.sub('{{datatype|expand}}', detail, text)

    text = text.replace("{", "<").replace("}", ">").replace("'", "").replace("\"", "").replace("\n", "")
    return ' '.join(text.split())


def getMinMaxEnumerationUnitPatternparam(paramtype, c):
    paramvalrange = None
    paramenum = None
    paramunit = None
    parampattern = None
    if paramtype == "string" or paramtype == "hexBinary" or paramtype == "base64":
        for cc in c:
            if cc.tag == "size":
                if paramvalrange is None and (cc.get("minLength") is not None or cc.get("maxLength") is not None):
                    paramvalrange = "%s,%s" % (
                        cc.get("minLength"), cc.get("maxLength"))
                elif cc.get("minLength") is  not None or cc.get("maxLength") is not None:
                    paramvalrange = "%s;%s,%s" % (
                        paramvalrange, cc.get("minLength"), cc.get("maxLength"))
            if cc.tag == "enumeration":
                if paramenum is None:
                    paramenum = "\"%s\"" % cc.get('value')
                else:
                    paramenum = "%s, \"%s\"" % (paramenum, cc.get('value'))
            if cc.tag == "pattern":
                if parampattern is None:
                    parampattern = "\"%s\"" % cc.get('value')
                elif cc.get('value') != "":
                    parampattern = "%s,\"%s\"" % (
                        parampattern, cc.get('value'))

    elif paramtype == "unsignedInt" or paramtype == "int" or paramtype == "unsignedLong" or paramtype == "long":
        for cc in c:
            if cc.tag == "range":
                if paramvalrange is None:
                    paramvalrange = "%s,%s" % (
                        cc.get("minInclusive"), cc.get("maxInclusive"))
                else:
                    paramvalrange = "%s;%s,%s" % (paramvalrange, cc.get(
                        "minInclusive"), cc.get("maxInclusive"))
            if cc.tag == "units":
                paramunit = cc.get("value")

    return paramvalrange, paramenum, paramunit, parampattern


def getparamdatatyperef(datatyperef):
    paramvalrange = None
    paramenum = None
    paramunit = None
    parampattern = None
    for d in XML_ROOT:
        if d.tag == "dataType" and d.get("name") == datatyperef:
            if d.get("base") != "" and d.get("base") is not None and d.get("name") == "Alias":
                paramvalrange, paramenum, paramunit, parampattern = getparamdatatyperef(d.get("base"))
            else:
                for dd in d:
                    if dd.tag in listTypes:
                        paramvalrange, paramenum, paramunit, parampattern = getMinMaxEnumerationUnitPatternparam(
                            dd.tag, dd)
                        break
                    if dd.tag == "size":
                        if paramvalrange is None:
                            paramvalrange = "%s,%s" % (
                                dd.get("minLength"), dd.get("maxLength"))
                        else:
                            paramvalrange = "%s;%s,%s" % (
                                paramvalrange, dd.get("minLength"), dd.get("maxLength"))
                    if dd.tag == "enumeration":
                        if paramenum is None:
                            paramenum = "\"%s\"" % dd.get('value')
                        else:
                            paramenum = "%s, \"%s\"" % (
                                paramenum, dd.get('value'))
                    if dd.tag == "pattern":
                        if parampattern is None:
                            parampattern = "\"%s\"" % dd.get('value')
                        elif dd.get('value') != "":
                            parampattern = "%s,\"%s\"" % (
                                parampattern, dd.get('value'))
                break

    return paramvalrange, paramenum, paramunit, parampattern


def getparamlist(dmparam):
    minItem = None
    maxItem = None
    maxsize = None
    minItem = dmparam.get("minItems")
    maxItem = dmparam.get("maxItems")
    for cc in dmparam:
        if cc.tag == "size":
            maxsize = cc.get("maxLength")

    return minItem, maxItem, maxsize


def getparamoption(dmparam):
    datatype = None
    paramvalrange = None
    paramenum = None
    paramunit = None
    parampattern = None
    listminItem = None
    listmaxItem = None
    listmaxsize = None
    islist = False

    for s in dmparam:
        if s.tag == "syntax":
            for c in s:
                if c.tag == "list":
                    islist = True
                    listminItem, listmaxItem, listmaxsize = getparamlist(c)
                    for c1 in s:
                        datatype = c1.tag if c1.tag in listdataTypes else None
                        if datatype is not None:
                            paramvalrange, paramenum, paramunit, parampattern = getMinMaxEnumerationUnitPatternparam(datatype, c1)
                            break
                        if c1.tag == "dataType":
                            datatype = c1.get("ref")
                            paramvalrange, paramenum, paramunit, parampattern = getparamdatatyperef(c1.get("ref"))
                            break

                if islist is False:
                    datatype = c.tag if c.tag in listdataTypes else None
                    if datatype is not None:
                        paramvalrange, paramenum, paramunit, parampattern = getMinMaxEnumerationUnitPatternparam(datatype, c)
                        break
                    if c.tag == "dataType":
                        datatype = c.get("ref")
                        paramvalrange, paramenum, paramunit, parampattern = getparamdatatyperef(datatype)
                        break
            break

    return islist, datatype, paramvalrange, paramenum, paramunit, parampattern, listminItem, listmaxItem, listmaxsize


def get_range_array(val_range):
    range_array = []
    valranges = val_range.split(";")
    for eachvalrange in valranges:
        range_obj = {}

        valrange = eachvalrange.split(",")
        if valrange[0] != "None" and valrange[1] != "None":
            range_obj["min"] = int(valrange[0])
            range_obj["max"] = int(valrange[1])
        elif valrange[0] != "None" and valrange[1] == "None":
            range_obj["min"] = int(valrange[0])
        elif valrange[0] == "None" and valrange[1] != "None":
            range_obj["max"] = int(valrange[1])

        range_array.append(range_obj)

    return range_array

      
def add_entry_to_list(e):
    existing_entry_index = None

    # Check if the entry already exists in the list
    for i, existing_entry in enumerate(LIST_DATA_MODEL):
        if existing_entry['name'] == e['name']:
            existing_entry_index = i
            break
    
    if existing_entry_index is not None:
        # Entry already exists, update 'protocol' field
        existing_protocols = LIST_DATA_MODEL[existing_entry_index]['protocol']
        if isinstance(existing_protocols, list):
            if e['protocol'] not in existing_protocols:
                existing_protocols.append(e['protocol'])
        else:
            LIST_DATA_MODEL[existing_entry_index]['protocol'] = [existing_protocols, e['protocol']]
    else:
        proto_list = e['protocol']
        e['protocol'] = [proto_list]
        if e['name'].endswith('.'):
            # Insert the new entry at the end of the list
            LIST_DATA_MODEL.append(e)
        else:
            last_dot_index = e['name'].rfind('.')
            entry_obj = e['name'][:last_dot_index + 1]
            insert_index = 0
            entry_obj_found = False
            for i, existing_entry in enumerate(LIST_DATA_MODEL):
                if entry_obj == existing_entry['name']:
                    entry_obj_found = True
                    continue
                    
                if entry_obj_found is True and existing_entry['name'].endswith('.'):
                    insert_index = i
                    break
                    
            if insert_index != 0:
                # Insert the new entry at the appropriate index
                LIST_DATA_MODEL.insert(insert_index, e)
            else:
                # Insert the new entry at the end of the list
                LIST_DATA_MODEL.append(e)
    

def add_obj_to_list(main_obj, dmobject, proto):
    array = dmobject.get('name').endswith('.{i}.')
    access = dmobject.get('access') != "readOnly"
    description = get_param_desc(dmobject, None)
    obsolete = dmobject.get('status') in {"deprecated", "obsoleted", "deleted"}
    uniqueKeys = getuniquekeys(dmobject)

    entry_obj = {
        "name": main_obj + dmobject.get('name'),
        "type": "object",
        "array": array,
        "access": access,
        "protocol": proto,
        "description": description,
        "obsolete": obsolete,
    }
    
    if uniqueKeys is not None:
        entry_obj['uniqueKeys'] = re.findall(r'"(.*?)"', uniqueKeys)
        
    add_entry_to_list(entry_obj)


def add_param_to_list(main_obj, dmobject, dmparam, proto):
    islist, datatype, paramvalrange, paramenum, paramunit, parampattern, listminItem, listmaxItem, listmaxsize = getparamoption(dmparam)

    access = dmparam.get('access') != "readOnly"
    description = get_param_desc(dmparam, datatype)
    obsolete = dmobject.get('status') in {"deprecated", "obsoleted", "deleted"}
    if obsolete is False:
        obsolete = dmparam.get('status') in {"deprecated", "obsoleted", "deleted"}
    ptype = getparamtype(dmparam)
    default = getParamDefault(dmparam)

    entry_param = {
        "name": main_obj + dmparam.get('name'),
        "type": ptype,
        "read": True,
        "write": access,
        "protocol": proto,
        "description": description,
        "obsolete": obsolete,
        "list": islist
    }

    if default is not None:
        entry_param['default'] = default
    
    if datatype is not None:
        entry_param['datatype'] = datatype

    if paramvalrange is not None:
        entry_param['range'] = get_range_array(paramvalrange)

    if paramunit is not None:
        entry_param['unit'] = paramunit

    if paramenum is not None:
        entry_param['enumerations'] = re.findall(r'"(.*?)"', paramenum)

    if parampattern is not None:
        entry_param['pattern'] = re.findall(r'"(.*?)"', parampattern)
        
    if listminItem is not None:
        entry_param['min_item'] = int(listminItem)
        
    if listmaxItem is not None:
        entry_param['max_item'] = int(listmaxItem)
        
    if listmaxsize is not None:
        entry_param['max_size'] = int(listmaxsize)
        
    add_entry_to_list(entry_param)


def add_command_to_list(main_obj, dmparam, proto):
    is_async = False

    if dmparam.get('async') == "true":
        is_async = True

    entry_command = {
        "name": main_obj + dmparam.get('name'),
        "type": "command",
        "async": is_async,
        "protocol": proto
    }
    
    for c in dmparam:
        if c.tag == "input":
            entry_command['input'] = c
        elif c.tag == "output":
            entry_command['output'] = c
            
    add_entry_to_list(entry_command)


def add_event_to_list(main_obj, dmparam, proto):

    entry_event = {
        "name": main_obj + dmparam.get('name'),
        "type": "event",
        "protocol": proto
    }
    
    for c in dmparam:
        if c.tag == "parameter":
            entry_event['output'] = dmparam
            break
    
    add_entry_to_list(entry_event)

def get_argument(input_args, proto):
    input_dict = {}
    for param in input_args:
        if param.tag == "parameter":
            param_in_dict = {}
           
            islist, datatype, paramvalrange, paramenum, paramunit, parampattern, listminItem, listmaxItem, listmaxsize = getparamoption(param)
            description = get_param_desc(param, datatype)
            default = getParamDefault(param)
           
            param_in_dict['type'] = getparamtype(param)
            param_in_dict['read'] = True
            param_in_dict['write'] = param.get('access') != "readOnly"
            
            if param.get('status') in {"deprecated", "obsoleted", "deleted"}:
                param_in_dict['obsolete'] = True

            if param.get('mandatory') == "true":
                param_in_dict['mandatory'] = True

            param_in_dict['protocols'] = proto

            if description is not None:
                param_in_dict['description'] = description

            if default is not None and len(default):
                param_in_dict['default'] = default
               
            if islist is True:
                list_dict = {}
                item_dict = {}
    
                if datatype is not None:
                    list_dict['datatype'] = datatype
                    
                if listmaxsize is not None:
                    list_dict['maxsize'] = int(listmaxsize)
                    
                if listminItem is not None:
                    item_dict['min'] = int(listminItem)
                    
                if listmaxItem is not None:
                    item_dict['max'] = int(listmaxItem)
                
                if listminItem is not None or listmaxItem is not None:
                    list_dict['item'] = item_dict
                
                if paramvalrange is not None:
                    list_dict['range'] = get_range_array(paramvalrange)
                
                if paramunit is not None:
                    list_dict['unit'] = paramunit
                
                if paramenum is not None:
                    list_dict['enumerations'] = re.findall(r'"(.*?)"', paramenum)
                
                if parampattern is not None:
                    list_dict['pattern'] = re.findall(r'"(.*?)"', parampattern)
                
                param_in_dict['list'] = list_dict
            else:
                if datatype is not None:
                    param_in_dict['datatype'] = datatype
                
                if paramvalrange is not None:
                    param_in_dict['range'] = get_range_array(paramvalrange)
                
                if paramunit is not None:
                    param_in_dict['unit'] = paramunit
                
                if paramenum is not None:
                    param_in_dict['enumerations'] = re.findall(r'"(.*?)"', paramenum)
                
                if parampattern is not None:
                    param_in_dict['pattern'] = re.findall(r'"(.*?)"', parampattern)
                    
            input_dict[param.get('name')] = param_in_dict

    return input_dict


def add_to_dict(obj, e):
    name = e['name']
    components = name.split('.')
    current_dict = obj
    full_path = ""
    is_param = False

    for i, component in enumerate(components):

        if component == '' or component == '{i}':
            continue

        if i == len(components) - 1:
            full_path = component
            is_param = True
        else:
            if i + 1 < len(components) and components[i + 1] != '{i}':
                str_suffix = "."
            else:
                str_suffix = ".{i}."

            full_path += component + str_suffix
            is_param = False
            
        current_dict = current_dict.setdefault(full_path, {})

    if is_param is False:
        obj_dict = {}
        
        obj_dict['type'] = e['type']
        
        if 'obsolete' in e and e['obsolete'] is True:
            obj_dict['obsolete'] = e['obsolete']
        
        if 'protocol' in e:
            obj_dict['protocols'] = e['protocol']
        
        if 'description' in e:
            obj_dict['description'] = e['description']
        
        if 'uniqueKeys' in e:
            obj_dict['uniqueKeys'] = e['uniqueKeys']
          
        if 'access' in e:
            obj_dict['access'] = e['access']
        
        if 'array' in e:
            obj_dict['array'] = e['array']

        current_dict.update(obj_dict)
    else:
        param_dict = {}
        
        param_dict['type'] = e['type']

        if 'async' in e:
            param_dict['async'] = e['async']
        
        if 'read' in e:
            param_dict['read'] = e['read']
        
        if 'write' in e:
            param_dict['write'] = e['write']
        
        if 'obsolete' in e and e['obsolete'] is True:
            param_dict['obsolete'] = e['obsolete']
        
        if 'protocol' in e:
            param_dict['protocols'] = e['protocol']
            
        if 'input' in e:
            param_dict['input'] = get_argument(e['input'], e['protocol'])    
            
        if 'output' in e:
            param_dict['output'] = get_argument(e['output'], e['protocol'])
        
        if 'description' in e:
            param_dict['description'] = e['description']
        
        if 'default' in e and len(e['default']):
            param_dict['default'] = e['default']
        
        if 'list' in e and e['list'] is True:
            list_dict = {}
            item_dict = {}

            if 'datatype' in e:
                list_dict['datatype'] = e['datatype']
                
            if 'max_size' in e:
                list_dict['maxsize'] = e['max_size']
                
            if 'min_item' in e:
                item_dict['min'] = e['min_item']
                
            if 'max_item' in e:
                item_dict['max'] = e['max_item']
            
            if 'min_item' in e or 'max_item' in e:
                list_dict['item'] = item_dict
            
            if 'range' in e:
                list_dict['range'] = e['range']
            
            if 'unit' in e:
                list_dict['unit'] = e['unit']
            
            if 'enumerations' in e:
                list_dict['enumerations'] = e['enumerations']
            
            if 'pattern' in e:
                list_dict['pattern'] = e['pattern']
            
            param_dict['list'] = list_dict
        else:
            if 'datatype' in e:
                param_dict['datatype'] = e['datatype']
            
            if 'range' in e:
                param_dict['range'] = e['range']
            
            if 'unit' in e:
                param_dict['unit'] = e['unit']
            
            if 'enumerations' in e:
                param_dict['enumerations'] = e['enumerations']
            
            if 'pattern' in e:
                param_dict['pattern'] = e['pattern']

        current_dict.update(param_dict)


def object_parse_childs(main_obj, dmobject, proto):
    
    add_obj_to_list(main_obj, dmobject, proto)

    for c in dmobject:
        if c.tag == "parameter":
            add_param_to_list(main_obj + dmobject.get('name'), dmobject, c, proto)
        elif c.tag == "command":
            add_command_to_list(main_obj + dmobject.get('name'), c, proto)
        elif c.tag == "event":
            add_event_to_list(main_obj + dmobject.get('name'), c, proto)
        elif c.tag == "object":
            object_parse_childs(main_obj + dmobject.get('name'), c, proto)


def parse_xml_model(model, proto):
    is_service = model.get("isService")
    main_obj = "Device.Services." if is_service == "true" else ""

    for child in model:
        if child.tag == "object":
            object_parse_childs(main_obj, child, proto)


def print_usage():
    print("Usage: python convert_dm_xml_to_json -d <directory>")
    print("Options:")
    print("  -d, --directory <directory>: Directory containing XML files in pre-defined order to convert to JSON")
    print("Example:")
    print("  ./tools/convert_dm_xml_to_json.py -d test/tools/")


def convert_xml_to_json(file_path):
    #print("Converting XML to JSON:", file_path)
    global XML_ROOT

    try:
        tree = xml.parse(file_path)
        XML_ROOT = tree.getroot()
        spec = XML_ROOT.get("spec")
        if spec.endswith("cwmp"):
            proto = "cwmp"
        elif spec.endswith("usp"):
            proto = "usp"
        else:
            proto = "both"
            
        model = None

        for child in XML_ROOT:
            if child.tag == "dataType":
                process_datatypes(child)

            if child.tag == "model":
                model = child

        if model is None or model.tag != "model":
            print("Wrong {} XML Data model format!".format(file_path))
            return

        parse_xml_model(model, proto)
    except xml.ParseError as e:
        print("Error parsing XML file {}: {}".format(file_path, e))


if __name__ == "__main__":
    # Check if the script is run with proper arguments
    if len(sys.argv) != 3 or sys.argv[1] not in ("-d", "--directory"):
        print_usage()
        sys.exit(1)

    # Check if the directory exists
    directory = sys.argv[2]
    if not os.path.isdir(directory):
        print("Directory '{}' not found or not specified correctly.".format(directory))
        print_usage()
        sys.exit(1)

    # Get a list of all files ending with ".xml" in the directory
    xml_files = [file for file in os.listdir(directory) if file.endswith('.xml')]

    # Sort the list of filenames based on their prefixes
    sorted_files = sorted(xml_files, key=lambda x: int(x.split('-')[0]))

    # Process each XML file in the directory
    for filename in sorted_files:
        f_path = os.path.join(directory, filename)
        convert_xml_to_json(f_path)

    json_object = {}
    for entry_list in LIST_DATA_MODEL:
        add_to_dict(json_object, entry_list)

    # Convert JSON object to JSON string with indentation
    json_str = json.dumps(json_object, indent="\t")

    # Write JSON string to a file named datamodel.json
    with open("datamodel.json", "w", encoding="utf-8") as json_file:
        json_file.write(json_str)
        
    print("datamodel.json")
