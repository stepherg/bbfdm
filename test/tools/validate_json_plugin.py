#!/usr/bin/python3

# Copyright (C) 2021 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import sys
import json
from jsonschema import validate

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
		"array"
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
				"sysfs"
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

def print_validate_json_usage():
    print("Usage: " + sys.argv[0] + " <dm json file>")
    print("Examples:")
    print("  - " + sys.argv[0] + " tr181.json")
    print("    ==> Validate the json file")
    print("")
    exit(1)

def parse_value( key , value ):

	if key.endswith('.') and not key.startswith('Device.'):
		print(key + " is not a valid path")
		exit(1)
	
	validate(instance = value, schema = obj_schema if key.endswith('.') else param_schema)

	for k, v in value.items():
		if not k.endswith('()') and not k.endswith('!') and k != "list" and k != "mapping" and isinstance(v, dict):
			parse_value(k, v)

### main ###
if len(sys.argv) < 2:
    print_validate_json_usage()
    
json_file = open(sys.argv[1], "r")
json_data = json.loads(json_file.read())

for key, value in json_data.items():	
	parse_value(key , value)

print("JSON File is Valid")
