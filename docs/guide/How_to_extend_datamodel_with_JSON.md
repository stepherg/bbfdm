# How to extend Datamodel parameters using Json

`bbfdm` provides tools to convert Broadband-forum's xml datamodel definition for cwmp and usp to a combined JSON file.

JSON definition of datamodel with latest release available in [datamodel.json](../../libbbfdm/dmtree/json/datamodel.json)

Now, a partial node from this file can be used to create a JSON datamodel definition, provided user adds a mapping to all LEAF parameters and multi-instance object.

```json
{
	"json_plugin_version": 2,
	"Device.": {
		"type": "object",
		"protocols": [
			"cwmp",
			"usp"
		],
		"access": false,
		"array": false,
		"RootDataModelVersion": {
			"type": "string",
			"read": true,
			"write": false,
			"protocols": [
				"cwmp",
				"usp"
			]
		},
		"Boot!": {
			"type": "event",
			"protocols": [
				"usp"
			],
			"Cause": {
				"type": "string",
				"read": true,
				"write": true,
				"protocols": [
					"usp"
				],
				"enumerations": [
					"LocalReboot",
					"RemoteReboot",
					"LocalFactoryReset",
					"RemoteFactoryReset"
				]
			}
		},
		"SelfTestDiagnostics()": {
			"type": "command",
			"async": true,
			"protocols": [
				"usp"
			],
			"output": {
				"Results": {
					"type": "string",
					"read": true,
					"write": true,
					"protocols": [
						"usp"
					]
				}
			}
		}
	}
}
```

> Note1: `json_plugin_version` is **mandatory** in json datamodel definition.

> Note2: It is advised to use `json_plugin_version` 2 for datamodel definition, usages version 0 and 1 are deprecated.

## JSON Plugin Version 2

Earlier versions of the json_plugins where treated as separate tree, so there where no sharing of data between main tree and JSON plugin, also it was not possible to overwrite/exclude a datamodel entry from core using JSON file.

JSON Plugin Version 2 introduces enhancements to the previous versions by providing increased flexibility in extending, overwriting, and excluding objects/parameters/commands/events from the core data model.

### How It Works

To illustrate how the new features work, let's consider the following example JSON Plugin:

```json
{
    "json_plugin_version": 2,
    "Device.WiFi.AccessPoint.{i}.Security.": {
        "type": "object",
        "protocols": [
            "cwmp",
            "usp"
        ],
        "access": false,
        "array": false,
        "{BBF_VENDOR_PREFIX}KeyPassphrase": {
            "type": "string",
            "read": true,
            "write": true,
            "protocols": [
                "cwmp",
                "usp"
            ],
            "datatype": "string",
            "mapping": [
                {
                    "data": "@Parent",
                    "type": "uci_sec",
                    "key": "key"
                }
            ]
        },
        "WEPKey": {
            "type": "string",
            "read": true,
            "write": true,
            "protocols": [
                "cwmp",
                "usp"
            ],
            "datatype": "string",
            "mapping": [
                {
                    "data": "@Parent",
                    "type": "uci_sec",
                    "key": "wek_key"
                }
            ]
        },
        "SAEPassphrase": {
            "type": "string",
            "read": true,
            "write": false,
            "protocols": [
                "none"
            ]
        }
    }
}
```

The JSON Plugin V2 operates by parsing the JSON file. Then it checks the parent top object, which in this example is `Device.WiFi.AccessPoint.{i}.Security`.

- If this object exists in the core data model, the plugin proceeds to examine the next each subsequent level to determine the necessary action for each JSON object.
  - If the object does not exist in the core data model, it is extended.
  - If the object exists, it is either overwritten or excluded, depending on the defined protocols. If the protocols array is defined as 'none', the object is excluded.
  - If the parent top object does not exist in the core data model, the plugin follows the old behavior defined in JSON Plugin V0 and V1, which is extending the core data model.

Examples

 - Device.WiFi.AccessPoint.{i}.Security.X_IOPSYS_EU_KeyPassphrase: This parameter will be extended to the core data model since it does not exist.
 - Device.WiFi.AccessPoint.{i}.Security.WEPKey: This parameter will be overwritten in the core data model since it already exists.
 - Device.WiFi.AccessPoint.{i}.Security.SAEPassphrase: This parameter will be excluded from the core data model since it exists, but the new protocol defined is `none`.

More example(s):
- [Extend](../../test/vendor_test/test_extend.json)
- [Overwrite](../../test/vendor_test/test_overwrite.json), and
- [Exclude](../../test/vendor_test/test_exclude.json)

### Important Notes

> Note: When extending a multiple-instance object, align the passed data from the browse function to children (LEAF) by keeping it `(struct uci_section *)data` pointer in case of the `type` is `uci_sec` or `(json_object *)data` pointer in case of the `type` is `json`.

> Note: The mapping format used by JSON Plugin V2 follows the format of version 1. Ensure that all mappings are aligned with JSON Plugin V1 specifications.

> Note4: Additional examples for each feature can be found in the following links:


### Features Supported with JSON Plugin V2

 - Allow extending the core tree with simple mappings based on the data passed from the parent object.
 - Allow overwriting an existing object, parameter, command, or event from the core tree.
 - Allow excluding an existing object, parameter, command, or event from the core tree.

#### Some examples on JSON Definition

**1. Object without instance:**

```bash
"Device.CWMP.": {
    "type": "object",
    "protocols": [
        "cwmp",
        "usp"
    ],
    "array": false,
    "access": false
}
```

**2. Object with instance:**

- **UCI command:** uci show wireless | grep wifi-device

```bash
"Device.X_IOPSYS_EU_Radio.{i}.": {
    "type": "object",
    "protocols": [
        "cwmp",
        "usp"
    ],
    "array": true,
    "access": true,
    "mapping": {
        "type": "uci",
        "uci": {
            "file": "wireless",
            "section": {
                "type": "wifi-device"
            },
            "dmmapfile": "dmmap_wireless"
        }
    }
}
```

- **UBUS command:** ubus call dsl status | jsonfilter -e @.line

```bash
"Device.DSL.Line.{i}.": {
	"type": "object",
	"protocols": [
		"cwmp",
		"usp"
	],
	"array": true,
	"access": false,
	"mapping": {
		"type": "ubus",
		"ubus": {
			"object": "dsl",
			"method": "status",
			"args": {},
			"key": "line"
		}
	}
}
```

**3. Parameter under object with instance:**

- **UCI option command:** uci get wireless.@wifi-device[0].country

- **@i:** is the number of instance object

```bash
"Country": {
	"type": "string",
	"protocols": [
		"cwmp",
		"usp"
	],
	"read": true,
	"write": true,
	"mapping": [
		{
			"type" : "uci",
			"uci" : {
				"file" : "wireless",
				"section" : {
					"type": "wifi-device",
					"index": "@i-1"
				},
				"option" : {
					"name" : "country"
				}
			}
		}
	]
}
```

- **UCI list command:** uci get urlfilter.@profile[0].whitelist_url

- **@i:** is the number of instance object

```bash
"WhitelistURL": {
	"type": "string",
	"read": true,
	"write": true,
	"protocols": [
		"cwmp",
		"usp"
	],
	"list": {
		"datatype": "string"
	},
	"mapping": [
		{
			"type": "uci",
			"uci": {
				"file": "urlfilter",
				"section": {
					"type": "profile",
					"index": "@i-1"
				},
				"list": {
					"name": "whitelist_url"
				}
			}
		}
	]
}
```


- **UBUS command:** ubus call wifi status | jsonfilter -e @.radios[0].noise

- **@i:** is the number of instance object

```bash
"Noise": {
	"type": "int",
	"protocols": [
		"cwmp",
		"usp"
	],
	"read": true,
	"write": false,
	"mapping": [
		{
			"type" : "ubus",
			"ubus" : {
				"object" : "wifi",
				"method" : "status",
				"args" : {},
				"key" : "radios[@i-1].noise"
			}
		}
	]
}
```

**4. Parameter without instance:**

- **UCI option command:** uci get cwmp.cpe.userid

```bash
"Username": {
	"type": "string",
	"protocols": [
		"cwmp",
		"usp"
	],
	"read": true,
	"write": true,
	"mapping": [
		{
			"type" : "uci",
			"uci" : {
				"file" : "cwmp",
				"section" : {
					"type": "cwmp",
	      				"name": "cpe"
	       			},
				"option" : {
					"name" : "userid"
				}
			}
		}
	]
}
```

- **UCI list command:** uci get urlfilter.globals.blacklist_url

- **@i:** is the number of instance object

```bash
"BlacklistURL": {
	"type": "string",
	"read": true,
	"write": true,
	"protocols": [
		"cwmp",
		"usp"
	],
	"list": {
		"datatype": "string"
	},
	"mapping": [
		{
			"type": "uci",
			"uci": {
				"file": "urlfilter",
				"section": {
					"name": "globals"
				},
				"list": {
					"name": "blacklist_url"
				}
			}
		}
	]
}
```

- **UBUS command:** ubus call system info | jsonfilter -e @.uptime

```bash
"Uptime": {
	"type": "unsignedInt",
	"protocols": [
		"cwmp",
		"usp"
	],
	"read": true,
	"write": false,
	"mapping": [
		{
			"type" : "ubus",
			"ubus" : {
				"object" : "system",
				"method" : "info",
				"args" : {},
				"key" : "uptime"
			}
		}
	]
}
```

- **UBUS command:** ubus call system info | jsonfilter -e @.memory.total

```bash
"Total": {
	"type": "unsignedInt",
	"protocols": [
		"cwmp",
		"usp"
	],
	"read": true,
	"write": false,
	"mapping": [
		{
			"type" : "ubus",
			"ubus" : {
				"object" : "system",
				"method" : "info",
				"args" : {},
				"key" : "memory.total"
			}
		}
	]
}
```

**5. Parameter to map another data model Object:**

- **UCI option command:** uci get urlfilter.@filter[0].profile

- **linker_obj** is the path name of an object that is stacked immediately below this object

```bash
"Profile": {
	"type": "string",
	"read": true,
	"write": true,
	"protocols": [
		"cwmp",
		"usp"
	],
	"mapping": [
		{
			"type": "uci",
			"uci": {
				"file": "urlfilter",
				"section": {
					"type": "filter",
					"index": "@i-1"
				},
				"option": {
					"name": "profile"
				}
			},
			"linker_obj": "Device.{BBF_VENDOR_PREFIX}URLFilter.Profile.*.Name"
		}
	]
}
```

**6. Object with Event and Operate command:**

```bash
{
	"Device.X_IOPSYS_Test.": {
		"type": "object",
		"protocols": [
			"cwmp",
			"usp"
		],
		"array": false,
		"access": false,
		"Push!": {
			"type": "event",
			"protocols": [
				"usp"
			],
			"data": {
				"type": "string",
				"read": true,
				"write": true,
				"protocols": [
					"usp"
				]
			}
		},
		"Status()": {
			"type": "command",
			"async": true,
			"protocols": [
				"usp"
			],
			"input": {
				"Option": {
					"type": "string",
					"read": "true",
					"write": "true",
					"protocols": [
						"usp"
					]
				}
			},
			"output": {
				"Result": {
					"type": "string",
					"read": "true",
					"write": "false",
					"protocols": [
						"usp"
					]
				}
			},
			"mapping": [
				{
					"type": "ubus",
					"ubus": {
						"object": "test",
						"method": "status"
					}
				}
			]
		}
	}
}
```

## How to add object dependency using Json plugin

In some cases we may need to set a dependency on datamodel object. In such cases the object will only populate if its dependencies are fulfilled.
The json object `dependency` is used to define the same. Below is an example of how to add object dependency:

```json
{
	"json_plugin_version": 1,
	"Device.CWMPManagementServer.": {
		"type": "object",
		"protocols": [
			"usp"
		],
		"access": false,
		"array": false,
		"dependency": "file:/etc/config/cwmp",
		"EnableCWMP": {
			"type": "boolean",
			"read": true,
			"write": true,
			"protocols": [
				"usp"
			],
			"mapping": [
				{
					"type": "uci",
					"uci": {
						"file": "cwmp",
						"section": {
							"name": "cpe"
						},
						"option": {
							"name": "enable"
						}
					}
				}
			]
		}
	}
}
```
In above example the object `CWMPManagementServer` has a dependency over the UCI file of cwmp (/etc/config/cwmp), that means if the cwmp UCI file is present in the device then only `Device.CWMPManagementServer.` object will populate.

### Possible values for dependency
one file => "file:/etc/config/network"
multiple files => "file:/etc/config/network,/lib/netifd/proto/dhcp.sh"
one ubus => "ubus:router.network" (with method : "ubus:router.network->hosts")
multiple ubus => "ubus:system->info,dsl->status,wifi"
one package => "opkg:icwmp"
multiple packages => "opkg:icwmp,obuspa"
common (files, ubus and package) => "file:/etc/config/network,/etc/config/dhcp;ubus:system,dsl->status;opkg:icwmp"

> Note: `dependency` can only be defined for datamodel objects and it can't be used for any leaf components (parameters/commands/events).

Now, If we consider the datamodel tree of usp, we have
- Non-leaf components(Objects/Multi-instance objects)
- Leaf components (Parameters/commands/events)

And on these tree components, we can do:
- Get
- Set
- Add
- Del
- Operate/commands

If we skip multi-instance objects for some time, everything else is stand-along entity, I mean, one parameter is having one specific information, so for those parameters information could be fetched from `uci/ubus` or some external `cli` command. The `datamodel.json` has all the required the information about the parameters except how to get it from the device. In json plugin, we solve that by introducing a new element in the tree called mapping, which describes how to process the operations on that specific datamodel parameter.

```json
mapping: [
{
	"type":"<uci/uci_sec/ubus/json/cli>",
}
]
```

If we consider multi-instance objects, they are kind of special because we have group of information, where one group can be visualize as one instance. Also, the parameters of multi-instance objects also shares data with there parents, apart from that, for others as well, we might require some runtime information to get some mappings, for those scenarios, mapping have some special symbol, all start with '@' symbol, some of them only applicable in case of multi-instance object. Overall all these are just for create the convention so that datamodel can easily be extended without getting into hustle of programming. Again, the plugin handler does not have any intelligence of it own and completely driven by the mapping provided by the enduser, so if mapping is in-correct it would give incorrect result or no result in the datamodel.


## How to have different mappings for get/set:
```json
{
  "Device.X_IOPSYS_EU-UserInterface.": {
    "type": "object",
    "protocols": [
      "cwmp",
      "usp"
    ],
    "access": false,
    "array": false,
    "Password": {
      "type": "string",
      "read": true,
      "write": true,
      "protocols": [
        "cwmp",
        "usp"
      ],
      "mapping": [
        {
          "rpc": "get"
        },
        {
          "rpc": "set",
          "type": "uci",
          "uci": {
            "file": "userinterface",
            "section": {
              "name": "global"
            },
            "option": {
              "name": "password_required"
            }
          }
        }
      ]
    },
    "CurrentLanguage": {
      "type": "string",
      "read": true,
      "write": true,
      "protocols": [
        "cwmp",
        "usp"
      ],
      "range": [
        {
          "max": 16
        }
      ],
      "mapping": [
        {
          "rpc": "get",
          "type": "ubus",
          "ubus": {
            "object": "userinterface",
            "method": "dump",
            "args": {},
            "key": "language"
          }
        },
        {
          "rpc": "set",
          "type": "ubus",
          "ubus": {
            "object": "userinterface",
            "method": "set",
            "args": {"language":"@Value"}
          }
        }
      ]
    }
  }
}
```

## How to map for NumberOfEntries parameter:
These are special parameters all with a suffix "NumberOfEntries", which has count of multi-instance object present. With our mapping, a multi-instance object can be added using ubus or uci mappings, so to get the count of the instances a new special symbol introduced `@Count`.

### mapping on ubus
For multi-instance on ubus mapping, it has to point to an array of objects, so for NumberOfEntries, we need to get the size of that array, which is refered here as `@Count`
```bash
{
  "Device.X_IOPSYS_EU_WiFi.RadioNumberOfEntries": {
	"type": "unsignedInt",
    "protocols": [
      "cwmp",
      "usp"
    ],
    "read": true,
    "write": false,
    "mapping": [
    	{
			"type": "ubus",
			"ubus": {
				"object": "wifi",
				"method": "status",
				"args": {},
				"key": "radios.@Count"
			}
		}
	]
  }
}
```

### mapping on uci
For multi-instance object mapped on uci, it has to point a uci section, so for NumberOfEntries it basically has the count of the sections.
```json
{
  "Device.X_IOPSYS_EU_DropbearNumberOfEntries": {
    "type": "unsignedInt",
    "protocols": [
      "cwmp",
      "usp"
    ],
    "read": true,
    "write": false,
    "mapping": [
    	{
			"type": "uci",
			"uci": {
				"file": "dropbear",
				"section": {
					"type": "dropbear"
				},
				"option": {
					"name": "@Count"
				}
			}
		}
    ]
  }
}
```

## How to pass data from parent node to child node
Multi-instance mapping either maps to array of json objects or uci section, so for the instance parameters, needs to extracts the information from the json data or from the uci section. This data sharing relationship can easily be mapped as below:

```json
{
  "Device.X_IOPSYS_EU_Dropbear.{i}.": {
    "type": "object",
    "protocols": [
      "cwmp",
      "usp"
    ],
    "access": true,
    "array": true,
    "mapping": [
    	{
			"type": "uci",
			"uci": {
				"file": "dropbear",
				"section": {
					"type": "dropbear"
				},
				"dmmapfile": "dmmap_dropbear"
			}
		}
	],
    "PasswordAuth": {
      "type": "boolean",
      "protocols": [
        "cwmp",
        "usp"
      ],
      "read": true,
      "write": true,
      "mapping": [
        {
			"data": "@Parent",
			"type": "uci_sec",
			"key": "PasswordAuth"
        }
      ]
    },
    "Name": {
      "type": "string",
      "protocols": [
        "cwmp",
        "usp"
      ],
      "read": true,
      "write": true,
      "mapping": [
        {
			"data": "@Parent",
			"type": "dmmap_sec",
			"key": "name"
        }
      ]
    },
    "Interface": {
      "type": "string",
      "protocols": [
        "cwmp",
        "usp"
      ],
      "read": true,
      "write": true,
      "flags": [
        "Reference"
      ],
      "mapping": [
        {
			"data": "@Parent",
			"type": "uci_sec",
			"key": "interface",
			"linker_obj": "Device.IP.Interface.*.Name"
        }
      ]
    }
  }
}
```

> Note1: If you want to get/set data from dmmap section instead of config section, ensure you specify the `type` as `dmmap_sec` instead of `uci_sec`, as demonstrated in the example above.
> Note2: To display a parameter value as a `reference`, you should add `flags` option as `Reference` and include `linker_obj` from which the reference will be obtained, as illustrated in the example above.

Ubus example for the same
```json
{
  "Device.X_IOPSYS_EU_WiFi.Radio.{i}.": {
    "type": "object",
    "protocols": [
      "cwmp",
      "usp"
    ],
    "access": false,
    "array": true,
    "mapping": [
    	{
			"type": "ubus",
			"ubus": {
				"object": "wifi",
				"method": "status",
				"args": {},
				"key": "radios"
			}
		}
	],
    "Noise": {
      "type": "int",
      "read": true,
      "write": true,
      "protocols": [
        "cwmp",
        "usp"
      ],
      "mapping": [
        {
			"data": "@Parent",
			"type": "json",
	  		"key": "noise"
        }
      ]
    },
    "Band": {
      "type": "string",
      "read": true,
      "write": true,
      "protocols": [
        "cwmp",
        "usp"
      ],
      "datatype": "string",
      "mapping": [
        {
          "type": "ubus",
          "ubus": {
            "object": "wifi",
            "method": "status",
            "args": {},
            "key": "radios[@index].band"
          }
        }
      ]
    }
  }
}
```

## How to map Multi Instance Object for Multiple Sections:

 - This is only applicable when mapping multi-instance Objects to **uci** config sections
 - Multi instance object must be mapped to uci 'config' sections
 - Uci options can only be mapped to leaf dm nodes
 - Uci list options can only be mapped to leaf dm nodes which show the values as csv list
 - It better to use a named config sections in place of unnamed config sections for multi-instance objects
 - Children on multi-instance objects needs to have reference to their parent using 'dm_parent' option in uci section like below:

  ```bash
config agent 'agent'
	option timezone 'GMT0BST,M3.5.0/1,M10.5.0'
	
config task 'http_get_mt'
	option dm_parent 'agent'
	option name 'http_get_mt'
	
config task_option 'http_get_mt_target'
	option dm_parent 'http_get_mt'
	option id 'target'
 ```

This object 'Device.LMAP.MeasurementAgent.{i}.Task.{i}.Option.{i}.' maps to the config above. It contains 3 Multi instance objects:

1. MeasurementAgent.{i}: parent object which maps to 'agent' section
2. Task.{i}: child object of MeasurementAgent object which maps to 'task' section, it must have a 'dm_parent' option with the value 'agent'
3. Option.{i}: child object of Task object which maps to 'task_option' section, it must have a 'dm_parent' option with the value 'http_get_mt'

## Special symbols

| Symbols | Meaning of the symbol  |
| ------- | ---------------------- |
| @Name   | Section name of parent |
| @Parent | data passed by parent  |
| @Count  | Returns the count of instances |
| @Value  | Replace with the value passed in set command, only used for ubus **set** |
| @Input.XXX | Replace with the value passed in Input 'XXX' option, only used for ubus **operate** |

