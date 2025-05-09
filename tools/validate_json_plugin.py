#!/usr/bin/python3

# Copyright (C) 2024 iopsys Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>

import sys
import json
from jsonschema import validate

JSON_PLUGIN_VERSION = 0

obj_schema = {
	"definitions": {
		"type_t": {
			"type": "string",
			"enum": [
				"object"
			]
		},
		"map_type_t": {
			"type": "string",
			"enum": [
				"uci",
				"ubus"
			]
		},
		"protocols_t": {
			"type": "string",
			"enum": [
				"cwmp",
				"usp"
			]
		}
	},
	"type" : "object",
	"properties" : {
		"type" : {"$ref": "#/definitions/type_t"},
		"version" : {"type": "string"},
		"protocols" : {"type" : "array", "items" : {"$ref": "#/definitions/protocols_t"}},
		"uniqueKeys" : {"type" : "array"},
		"access" : {"type" : "boolean"},
		"array" : {"type" : "boolean"},
		"mapping" : {"type" : "object", "properties" : {
				"type" : {"$ref": "#/definitions/map_type_t"},
				"uci" : {"type" : "object", "properties" : {
						"file" : {"type": "string"},
						"section" : {"type": "object", "properties" : {
								"type" : {"type": "string"}
							}
						},
						"dmmapfile" : {"type": "string"}
					}
				},
				"ubus" : {"type" : "object", "properties" : {
						"object" : {"type": "string"},
						"method" : {"type": "string"},
						"args" : {"type": "object"},
						"key" : {"type": "string"}
					}
				}
			}
		}
	},
	"required": [
		"type",
		"protocols",
		"array",
		"access"
	]
}

obj_schema_v1 = {
	"definitions": {
		"type_t": {
			"type": "string",
			"enum": [
				"object"
			]
		},
		"map_type_t": {
			"type": "string",
			"enum": [
				"uci",
				"ubus"
			]
		},
		"protocols_t": {
			"type": "string",
			"enum": [
				"cwmp",
				"usp",
				"none"
			]
		}
	},
	"type" : "object",
	"properties" : {
		"type" : {"$ref": "#/definitions/type_t"},
		"version" : {"type": "string"},
		"protocols" : {"type" : "array", "items" : {"$ref": "#/definitions/protocols_t"}},
		"uniqueKeys" : {"type" : "array"},
		"access" : {"type" : "boolean"},
		"array" : {"type" : "boolean"},
		"mapping" : {"type" : "array", "items" : {
			"type" : "object", "properties" : {
				"type" : {"$ref": "#/definitions/map_type_t"},
					"uci" : {"type" : "object", "properties" : {
							"file" : {"type": "string"},
							"section" : {"type": "object", "properties" : {
									"type" : {"type": "string"}
								}
							},
							"dmmapfile" : {"type": "string"}
						}
					},
					"ubus" : {"type" : "object", "properties" : {
							"object" : {"type": "string"},
							"method" : {"type": "string"},
							"args" : {"type": "object"},
							"key" : {"type": "string"}
						}
					}
				}
			}
		}
	},
	"required": [
		"type",
		"protocols",
		"array",
		"access"
	]
}

param_schema = {
	"definitions": {
		"type_t": {
			"type": "string",
			"enum": [
				"string",
				"unsignedInt",
				"unsignedLong",
				"int",
				"long",
				"boolean",
				"dateTime",
				"hexBinary",
				"base64",
				"decimal"
			]
		},
		"map_type_t": {
			"type": "string",
			"enum": [
				"uci",
				"ubus",
				"procfs",
				"sysfs",
				"json",
				"uci_sec"
			]
		},
		"protocols_t": {
			"type": "string",
			"enum": [
				"cwmp",
				"usp",
				"none"
			]
		}
	},
	"type" : "object",
	"properties" : {
		"type" : {"$ref": "#/definitions/type_t"},
		"protocols" : {"type" : "array", "items" : {"$ref": "#/definitions/protocols_t"}},
		"read" : {"type" : "boolean"},
		"write" : {"type" : "boolean"},
		"mapping" : {"type" : "array", "items" : {"type": "object", "properties" : {
					"type" : {"$ref": "#/definitions/map_type_t"},
					"uci" : {"type" : "object", "properties" : {
							"file" : {"type": "string"},
							"section" : {"type": "object", "properties" : {
									"type" : {"type": "string"},
									"index" : {"type": "string"}
								}
							},
							"option" : {"type": "object", "properties" : {
									"name" : {"type": "string"}								}
							}
						}
					},
					"ubus" : {"type" : "object", "properties" : {
							"object" : {"type": "string"},
							"method" : {"type": "string"},
							"args" : {"type": "object"},
							"key" : {"type": "string"}
						}
					},
					"procfs" : {"type" : "object", "properties" : {
							"file" : {"type": "string"}
						}
					},
					"sysfs" : {"type" : "object", "properties" : {
							"file" : {"type": "string"}
						}
					}
				}
			}
		}
	},
	"required": [
		"type",
		"protocols",
		"read",
		"write"
	]
}

event_schema = {
	"definitions": {
		"type_t": {
			"type": "string",
			"enum": [
				"event"
			]
		},
		"protocols_t": {
			"type": "string",
			"enum": [
				"usp"
			]
		}
	},
	"type" : "object",
	"properties" : {
		"type" : {"$ref": "#/definitions/type_t"},
		"version" : {"type": "string"},
		"protocols" : {"type" : "array", "items" : {"$ref": "#/definitions/protocols_t"}}
	},
	"required": [
		"type",
		"protocols"
	]
}

command_schema = {
	"definitions": {
		"type_t": {
			"type": "string",
			"enum": [
				"command"
			]
		},
		"protocols_t": {
			"type": "string",
			"enum": [
				"usp"
			]
		}
	},
	"type" : "object",
	"properties" : {
		"type" : {"$ref": "#/definitions/type_t"},
		"async" : {"type" : "boolean"},
		"protocols" : {"type" : "array", "items" : {"$ref": "#/definitions/protocols_t"}},
		"input" : {"type" : "object"},
		"output" : {"type" : "object"}
	},
	"required": [
		"type",
		"async",
		"protocols"
	]
}

def print_validate_json_usage():
    print("Usage: " + sys.argv[0] + " <dm json file>")
    print("Examples:")
    print("  - " + sys.argv[0] + " datamodel.json")
    print("    ==> Validate the json file")
    print("")
    exit(1)

def parse_value( key , value ):

    if key.endswith('.') and not key.startswith('Device.'):
        print(key + " is not a valid path")
        exit(1)

    if key.endswith('.') and (JSON_PLUGIN_VERSION == 1 or JSON_PLUGIN_VERSION == 2):
        __schema = obj_schema_v1
    elif key.endswith('.'):
        __schema = obj_schema
    elif key.endswith('!'):
        __schema = event_schema
    elif key.endswith('()'):
        __schema = command_schema
    else:
        __schema = param_schema
    
    validate(instance = value, schema = __schema)
    
    for k, v in value.items():
        if k != "list" and k != "mapping" and k != "input" and k != "output" and isinstance(v, dict):
            parse_value(k, v)

### main ###
if len(sys.argv) < 2:
    print_validate_json_usage()
    
json_file = open(sys.argv[1], "r", encoding='utf-8')
try:
    json_data = json.loads(json_file.read())
except ValueError:
    print(sys.argv[1] + " file has a wrong JSON format!!!!!")
    exit(1)

for __key, __value in json_data.items():

    if __key == "json_plugin_version":

        if not isinstance(__value, int) or __value not in [0, 1, 2]:
            raise ValueError("Invalid value for json_plugin_version")

        JSON_PLUGIN_VERSION = __value
        continue

    parse_value(__key , __value)

print("JSON File is Valid")
