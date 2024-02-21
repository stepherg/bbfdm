# How to extend Datamodel parameters using Json plugins

It is often required to extend datamodel parameters of the device, extending the datamodel parameters using json plugin is the simplest way for the same.

To extend the datamodel using json plugin, its required to be defined it, as it is defined in `TR181.json` file and then place that json in '/etc/bbfdm/json/' directory of device.

It is often the case, that the supported mapping might not handle all the scenarios, and required some structural changes to fulfill the new requirements, to make these plugins backward compatible with the older mappings some kind of check was required, which is can be solved with having a "version" field in the plugin, which describes the list of supported mappings with that specific version. This can be added as below:
```json
{
	"json_plugin_version": 1,
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
> Note: If the `json_plugin_version` is omitted in the json then it means, it is having legacy mapping and considered as `json_plugin_version` 0.

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

If we skip multi-instance objects for some time, everything else is stand-along entity, I mean, one parameter is having one specific information, so for those parameters information could be fetched from `uci/ubus` or some external `cli` command. The `TR181.json` has all the required the information about the parameters except how to get it from the device. In json plugin, we solve that by introducing a new element in the tree called mapping, which describes how to process the operations on that specific datamodel parameter.

```json
mapping: [
{
	"type":"<uci/uci_sec/ubus/json/cli>",
}
]
```

If we consider multi-instance objects, they are kind of special because we have group of information, where one group can be visualize as one instance. Also, the parameters of multi-instance objects also shares data with there parents, apart from that, for others as well, we might require some runtime information to get some mappings, for those scenarios, mapping have some special symbol, all start with '@' symbol, some of them only applicable in case of multi-instance object. Overall all these are just for create the convention so that datamodel can easily be extended without getting into hustle of programming. Again, the plugin handler does not have any intelligence of it own and completely driven by the mapping provided by the enduser, so if mapping is in-correct it would give incorrect result or no result in the datamodel.

## Special symbols

@index     => Current instance number - 1

@index - 1 => Parent instance number - 1

@index - 2 => Grand parent instance number - 1, and likewise

@Name      => Section name of parent

@Parent    => data passed by parent

@Count     => Returns the count of instances

@Value     => Replace with the value passed in set command, only used for ubus **set**

@Input.XXX => Replace with the value passed in Input 'XXX' option, only used for ubus **operate**

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
  "Device.WiFi.X_IOPSYS_EU_RadioNumberOfEntries": {
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
    }
  }
}
```
Ubus example for the same
```json
{
  "Device.WiFi.X_IOPSYS_EU_Radio.{i}.": {
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

## Feature supported with this mapping
 - Use of `json_plugin_version` for mapping extensions
 - Use different mappings for get/set
 - Support for NumberOfEntries parameter
 - Data sharing between parent and child node in multi-instance object
 - Use of index number in mapping
 - Support for set in ubus command
