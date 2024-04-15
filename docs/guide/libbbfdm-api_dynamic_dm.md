# BBFDM Dynamic Object/Parameter/Operate/Event

`bbfdm` library allows all applications installed on the box to import its own Data Model parameters at run time in two formats:

- **Shared library**

- **JSON files**

## 1. Shared library via external package

The application should bring its shared library under **'/usr/share/bbfdm/plugins'** path that contains the sub tree of **Objects/Parameters** and the related functions **Get/Set/Add/Delete/Operate**. The new added objects, parameters and operates will be automatically shown by icwmpd and bbfdmd/obuspa.

Each library should contains the Root table: **“tDynamicObj”**


### DynamicObject definition

The “tDynamicObj” table contains entries of **DM_MAP_OBJ** structure.

The **DM_MAP_OBJ** structure contains three arguments:

|     Argument     |                                     Description                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `parentobj`      | A string of the parent object name. Example “Device.IP.Diagnostics.”, “Device.DeviceInfo”, “Device.WiFi.Radio.” |
| `nextobject`     | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `parameter`      | Pointer to a **DMLEAF** array which contains a list of the child parameters |


For the other tables, they are defined in the same way as the Object and Parameter definition described above.

> Note1: Shared library can only add vendor or standard objects that are not implemented by `libbbfdm`

> Note2: Shared library is not allowed to overwrite objects/parameters

- For more examples on the external packages, you can see these links: [BulkData](https://dev.iopsys.eu/bbf/bulkdata/-/blob/master/datamodel.c), [XMPP](https://dev.iopsys.eu/bbf/xmppc/-/blob/master/datamodel.c)

### 2. JSON File via external package

The application should bring its JSON file under **'/etc/bbfdm/json/'** path with **UCI** and **UBUS** mappings. The new added parameters will be automatically shown by icwmpd and bbfdmd/obuspa.

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

> Note1: JSON File can only add vendor or standard objects that are not implemented by `libbbfdm`

> Note2: JSON File is not allowed to overwrite objects/parameters

> Note3: Set, Add, Delete methods are only allowed for uci mapping. therefore for ubus mapping, only Get method is authorized

> Note4: Each object definition in JSON file must begin with "Device." and should have the full parent path if it is under another object

- For more examples on JSON files, you can see these links: [X_IOPSYS_EU_MCPD](https://dev.iopsys.eu/feed/broadcom/-/blob/devel/mcpd/files/etc/bbfdm/json/X_IOPSYS_EU_MCPD.json), [UserInterface](../../test/files/etc/bbfdm/json/UserInterface.json), [X_IOPSYS_EU_Dropbear](../../test/files/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json), [X_IOPSYS_EU_TEST](../../test/files/etc/bbfdm/json/X_IOPSYS_EU_TEST.json)


