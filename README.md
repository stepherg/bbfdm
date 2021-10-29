# BroadBand Forum Data Models (BBFDM)

`bbfdm` is a data model library implementation which includes a list of objects, parameters and operates used for CPE management through remote control protocols such as [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).

## Design of bbfdm

`bbfdm` library is structred as follow :


```bash
├── dm...(.c and .h)
├── dmtree
│   ├── json
│   ├── tr104
│   ├── tr143
│   ├── tr181
│   └── vendor
│       ├── iopsys
│       ├── openwrt
│       └── vendor.h
├── libbbf_api
├── scripts
└── tools
```

- `dmtree` folder which includes all supported Data Models. It contains 5 folders:

	- `tr181` folder : TR-181 Data Model files

	- `tr104` folder : Voice Services Data Model files

	- `tr143` folder : Diagnostics Data Model files

	- `vendor` folder : Vendor Data Model files

	- `json` folder : TR-181 and TR-104 JSON files

- `libbbf_api` folder which contains the source code of all API functions (UCI, Ubus, JSON, CLI and memory management)

- `scripts` folder which contains the Diagnostics scripts

- `tools` folder which contains some tools to generate Data Model in C, JSON, XML and Excel format

- `dm...(.c and .h)` files which contains the `bbfdm` engine (operate, diagnostics) functions

## How to add support for a new Object/Parameter

As mentioned above, all Data Models are stored in the **'dmtree'** folder. In order to implement a new object/parameter, you need to expand its get/set/add/delete functions and then save them in the rigth folder.

`bbfdm` library offers a tool to generate templates of the source code from json files placed under **'dmtree/json'**. So, any developer can fill these json files ([tr181](/dmtree/json/tr181.json) or [tr104](/dmtree/json/tr104.json)) with mapping field according to UCI, UBUS or CLI commands then generate the source code in C.

```bash
$ ./convert_dm_json_to_c.py
Usage: convert_dm_json_to_c.py <data model name> [Object path]
data model name:   The data model(s) to be used, for ex: tr181 or tr181,tr104
Examples:
  - convert_dm_json_to_c.py tr181
    ==> Generate the C code of tr181 data model in datamodel/ folder
  - convert_dm_json_to_c.py tr104
    ==> Generate the C code of tr104 data model in datamodel/ folder
  - convert_dm_json_to_c.py tr181,tr104
    ==> Generate the C code of tr181 and tr104 data model in datamodel/ folder
  - convert_dm_json_to_c.py tr181 Device.DeviceInfo.
    ==> Generate the C code of Device.DeviceInfo object in datamodel/ folder
  - convert_dm_json_to_c.py tr104 Device.Services.VoiceService.{i}.Capabilities.
    ==> Generate the C code of Device.Services.VoiceService.{i}.Capabilities. object in datamodel/ folder
```

Below some examples of **UCI**, **UBUS** or **CLI** mappings:

#### UCI command

- **@Name:** the section name of paraent object

- **@i:** is the number of instance object

```bash
	"mapping": [
		{
			"type": "uci",
			"uci": {
				"file": "wireless",
				"section": {
					"type": "wifi-device",
					"name": "@Name",
					"index": "@i-1"
				},
				"option": {
					"name": "disabled"
				}
			}
		}
	]
```

#### UBUS command

- **@Name:** the section name of paraent object

```bash
	"mapping": [
		{
			"type": "ubus",
			"ubus": {
				"object": "network.device",
				"method": "status",
				"args": {
					"name": "@Name"
				},
				"key": "statistics.rx_bytes"
			}
		}
	]
```

#### CLI command:

- **@Name:** the section name of paraent object

- **-i:** is the number of arguments command

```bash
	"mapping": [
		{
			"type" : "cli",
			"cli" : {
				"command" : "wlctl",
				"args" : [
					"-i",
					"@Name",
					"bands"
				]
			}
		}
	]
```

After building the templates of C source code, a **datamodel** folder will be generated under **'tools'** folder that contains all files related to each object under root "**Device.**"

> Note: You can generate the source code without filling out the mapping field in the JSON file

### Object definition

Each object in the **DMOBJ** table contains the following arguments:

|     Argument        |                            Description                                                               |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| `OBJ`               | A string of the object name. Example “Bridging”, “IP”, “DeviceInfo”, “WiFi” |
| `permission`        | The permission of the object. Could be **&DMREAD** or **&DMWRITE**. If it's `&DMWRITE` then we can add/delete instances of this object |
| `addobj`            | The function to add new instance under this object. This function will be triggered when the ACS/Controller call AddObject of this object |
| `delobj`            | The function to delete instance under this object. This function will be triggered when the ACS/Controller call DeleteObject of an instance of this object |
| `checkdep`          | A string of the object dependency, it can be a file("file:/etc/config/network") or an ubus object,method("ubus:network.interface->status"). If it's `NULL` then the object has always appeared in the tree |
| `browseinstobj`     | This function allow to browse all instances under this object |
| `nextdynamicobj`    | Pointer to the next of **DMOBJ** which contains a list of the child objects using json files, shared libraries and vendor extension |
| `dynamicleaf`       | Pointer to the next of **DMLEAF** which contains a list of the child parameters using json files, shared libraries and vendor extension |
| `nextobj`           | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `leaf`              | Pointer to a **DMLEAF** array which contains a list of the child parameters |
| `linker`            | This argument is used for LowerLayer parameters or to make reference to other instance object in the tree |
| `bbfdm_type`        | The bbfdm type of the object. Could be **BBFDM_CWMP**, **BBFDM_USP**, **BBFDM_BOTH** or **BBFDM_NONE**.If it's **BBFDM_BOTH** then we can see this object in all protocols (CWMP, USP,...) |
| `uniqueKeys`        | The unique key parameters defined for the object. |


### Leaf definition

Each leaf in the **DMLEAF** table can be a **Parameter**, **Command** or **Event**.


#### 1.Parameter definition

|     Argument        |                             Description                                                               |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the parameter name. Example “Enable”, “Status”, “Name” |
| `permission`        | The permission of the parameter. Could be **&DMREAD** or **&DMWRITE**.If it's `&DMWRITE` then we can set a value for this parameter |
| `type`              | Type of the parameter: **DM_STRING**, **DM_BOOL**, **DM_UNINT**,... |
| `getvalue`          | The function which return the value of this parameter |
| `setvalue`          | The function which set the value of this parameter |
| `bbfdm_type`        | The bbfdm type of the parameter. Could be **BBFDM_CWMP**, **BBFDM_USP**, **BBFDM_BOTH** or **BBFDM_NONE**.If it's **BBFDM_BOTH** then we can see this parameter in all protocols (CWMP, USP,...) |


#### 2.Command definition

|     Argument        |                             Description                                                               |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the command name. Example “IPPing()”, “DownloadDiagnostics()”, “Renew()” |
| `permission`        | The permission of the command. Could be **&DMASYNC** or **&DMSYNC**. |
| `type`              | Type of the command, It should be **DMT_COMMAND** |
| `getvalue`          | The function which return the input, output arguments of the command |
| `setvalue`          | The function which call the operation of the command |
| `bbfdm_type`        | The bbfdm type of the command. It should be **BBFDM_USP** as long as operate commands are only defined in USP protocol. |


#### 3.Event definition

|     Argument        |                             Description                                                               |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the event name. Example “Boot!”, “Push!”, “Periodic!” |
| `permission`        | The permission of the event. It should be **DMREAD** |
| `type`              | Type of the event, It should be **DMT_EVENT** |
| `getvalue`          | The function which return the parameter arguments of the event |
| `setvalue`          | The function which call the operation of the event, It should be **NULL** |
| `bbfdm_type`        | The bbfdm type of the event. It should be **BBFDM_USP** as long as events are only defined in USP protocol. |


### Browse definition

The browse function allow to go over all instances of the current object and link them to the data model tree.

In this function, there are two functions that need to be defined:

- function to retrieve the instances: it can be

	* `handle_instance` function: allow to retrieve/attribute the instances number/alias from uci config sections depending of the request and the instance mode.

	* `handle_instance_without_section` function: allow to attribute the instances number/alias with constant values.

- function to link the instances: we need to call `DM_LINK_INST_OBJ()` function for each instance in order to link the instance to the data model tree. we also need to specify the `data`of this instance level. This `data` could be use later in the sub object and parameters functions (Get/Set/Add/Delete/Operate/Event).

> Note1: the browse function is only developed for multi-instances objects.

> Note2: you can read the next section `BBF API` below to find the definition of the functions used in the browse.

> Note3: you can use [bbf_test plugin](./test/bbf_test/bbf_test.c) as a reference in order to develop any new object/leaf/browse.


## BBF API

`libbbf_api` is a library which contains the source code of all API functions (UCI, Ubus, JSON, CLI and memory management). these API are used for GET/SET/ADD/Delete/Operate calls which can be called in internal or external packages.

The most used one are as follow:

#### 1. dmuci_get_option_value_string: execute the uci get value

```bash
int dmuci_get_option_value_string(char *package, char *section, char *option, char **value)
```
**Argument:**
- **package:** package name
- **section:** section name
- **option:** option name
- **value:** the value of the returned option

#### 2. dmuci_get_value_by_section_string: execute the uci get value

```bash
int dmuci_get_value_by_section_string(struct uci_section *s, char *option, char **value)
```
**Argument:**
- **section:** section name
- **option:** option name
- **value:** the value of the returned option

#### 3. uci_foreach_sections: browse all sections by package and section type

```bash
#define uci_foreach_sections(package, stype, section)
```

**Argument:**
- **package:** package name
- **stype:** section type to browse
- **section:** return section pointer for each loop iteration

#### 4. dmubus_call: execute the ubus call

```bash
int dmubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
```

**Argument:**
- **obj:** ubus obj
- **method:** ubus method
- **u_args:** ubus arguments
- **u_args_size:** number of ubus arguments
- **req_res:** the json message of the ubus call

#### 5. dmubus_call_set: set the ubus call

```bash
int dmubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size);
```

**Argument:**
- **obj:** ubus obj
- **method:** ubus method
- **u_args: ubus** arguments
- **u_args_size:** number of ubus arguments

#### 6. handle_instance: allow to retrieve/attribute the instances from uci config sections

```bash
char *handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct uci_section *s, char *inst_opt, char *alias_opt);
```

**Argument:**
- **dmctx:** the current dmctx struct passed when calling this object
- **parent_node:** the current node struct passed when calling this object
- **s:** the uci section used to get the instance 
- **inst_opt:** the option name of the instance number used for this object
- **alias_opt:** the option name of the instance alias used for this object

#### 7. handle_instance_without_section: allow to attribute instances with constant values

```bash
char *handle_instance_without_section(struct dmctx *dmctx, DMNODE *parent_node, int inst_nbr);
```

**Argument:** the current dmctx struct passed when calling this object
- **dmctx:** the current dmctx struct passed when calling this object
- **parent_node:** the current node struct passed when calling this object
- **inst_nbr:** the instance to attribute for this object

#### 8. DM_LINK_INST_OBJ: link the instance to the data model tree

```bash
int DM_LINK_INST_OBJ(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance)
```

**Argument:**
- **dmctx:** the current dmctx struct passed when calling this object
- **parent_node:** the current node struct passed when calling this object
- **data:** the data transmitted for the next sub object and parameters that can be uci section, json object, or any type of data
- **instance:** the current instance used for this object


> Note1: For other funtions, please refer to dmuci, dmubus, dmjson, dmcommon and dmmem (.c and .h) files in the [link](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/libbbf_api)

> Note2: When developing a new parameters/features in the Data Model, it's highly recommended to use the memory management functions of `libbbf_api` allocate and free because it's freed at the end of each RPCs.

The list of memory management functions of `libbbf_api` are:

```bash
dmmalloc(x)
dmcalloc(n, x)
dmrealloc(x, n)
dmstrdup(x)
dmasprintf(s, format, ...)
dmastrcat(s, b, m)
dmfree(x)
```

> Note3: There are several APIs that have been deprecated and replaced with new ones. the table below summarizes them

|             Deprecated API             |                       New API                      |
| -------------------------------------- | -------------------------------------------------- |
| handle_update_instance                 | handle_instance or handle_instance_without_section |
| update_instance_alias                  | handle_instance                                    |
| update_instance_without_section        | handle_instance_without_section                    |
| update_instance                        |                      Not Used                      |
| get_last_instance_bbfdm                |                      Not Used                      |
| get_last_instance                      | find_max_instance                                  |
| get_last_instance_lev2_bbfdm_dmmap_opt |                      Not Used                      |
| get_last_instance_lev2_bbfdm           |                      Not Used                      |
| is_section_unnamed                     |                      Not Used                      |
| delete_sections_save_next_sections     |                      Not Used                      |
| update_dmmap_sections                  |                      Not Used                      |
| check_browse_section                   |                      Not Used                      |
| dmuci_delete_by_section_unnamed        | dmuci_delete_by_section                            |
| dmuci_delete_by_section_unnamed_bbfdm  | dmuci_delete_by_section                            |

## BBFDM Vendor

`bbfdm` library can be used to **Extend** the Data Model with new objects/parameters, to **Overwrite** existing objects/parameters with new ones and **Exclude** some objects/parameters from Data Model tree.

### How to add new vendor

#### 1. Create a vendor folder

Create a new folder under **'dmtree/vendor/'** which contains all files related to the vendor

#### 2. Fill Extend, Overwrite and Exclude tables with objects/parameters

Create the first vendor C file which contains new **Extend**, **Overwrite** and **Exclude** tables of objects/parameters.

##### Extend and Overwrite table

The Extend and Overwrite tables contain entries of **DM_MAP_OBJ** structure.

The **DM_MAP_OBJ** structure contains three arguments:

|     Argument     |                                     Description                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `parentobj`      | A string of the parent object name. Example “Device.IP.Diagnostics.”, “Device.DeviceInfo”, “Device.WiFi.Radio.” |
| `nextobject`     | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `parameter`      | Pointer to a **DMLEAF** array which contains a list of the child parameters |

##### Exclude table

Each entry in the exclude table is a string which could be a path of object or parameter that need to be excluded from the tree

The following [link](https://dev.iopsys.eu/iopsys/bbf/-/blob/devel/dmtree/vendor/test/tr181/vendor.c) contains example of Extend, Overwrite and Exclude table.

#### 3. Adding vendor and standard objects/Parameters

Implement the new vendor/standard objects and parameters as defined above in the first section.

Example: [Custom Vendor Object Dropbear](https://dev.iopsys.eu/iopsys/bbf/-/blob/devel/dmtree/vendor/test/tr181/x_test_com_dropbear.c)

#### 4. link vendor tables to the main tree

To register the new vendor tables, you need to link them in the main three tables:

- **tVendorExtension**

- **tVendorExtensionOverwrite**

- **tVendorExtensionExclude**

These tables are defined in the file **'dmtree/vendor/vendor.c'**.

Example: [Link vendor tables to the main tree](https://dev.iopsys.eu/iopsys/bbf/-/blob/devel/dmtree/vendor/vendor.c)

#### 5. Enable vendor

To enable the new vendor

- Define **BBF_VENDOR_EXTENSION** macro

- Add the new vendor in the list **BBF_VENDOR_LIST** macro

- Define the vendor prefix using **BBF_VENDOR_PREFIX** macro

Example of Config Options:

```bash
BBF_VENDOR_EXTENSION=y
BBF_VENDOR_LIST="iopsys,test"
BBF_VENDOR_PREFIX="X_TEST_COM_"
```

> Note1: The `libbbfdm` vendor list can support multi-vendor with comma seperated.

> Note2: If multi vendors are supported and there is a object/parameter that is implmented by multi customers in different way, the implemented object/parameter of the first vendor name in the **BBF_VENDOR_LIST** will be considered.

> Note3: Overwrite and Exclude are only considered in `dmtree/vendor/<vendor>/`

- The directory **'dmtree/vendor/test/'** contains an example of **test** vendor implementation


## BBFDM Dynamic Object/Parameter/Operate/Event

`bbfdm` library allows all applications installed on the box to import its own Data Model parameters at run time in two formats:

- **Shared library**

- **JSON files**

### 1. Shared library via external package

The application should bring its shared library under **'/usr/lib/bbfdm/'** path that contains the sub tree of **Objects/Parameters** and the related functions **Get/Set/Add/Delete/Operate**. The new added objects, parameters and operates will be automatically shown by icwmpd and uspd/obuspa.

Each library should contains the Root table: **“tDynamicObj”**


#### DynamicObject definition

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

- For more examples on the external packages, you can see these links: [BulkData](https://dev.iopsys.eu/iopsys/bulkdata/-/blob/master/datamodel.c), [XMPP](https://dev.iopsys.eu/iopsys/xmppc/-/blob/master/datamodel.c)

### 2. JSON File via external package

The application should bring its JSON file under **'/etc/bbfdm/json/'** path with **UCI** and **UBUS** mappings. The new added parameters will be automatically shown by icwmpd and uspd/obuspa.

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

- **UCI command:** uci get wireless.@wifi-device[0].country

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

- **UCI command:** uci get cwmp.cpe.userid

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

**5. Object with Event and Operate command:**

```bash
{
	"Device.X_IOPSYS_Test.": {
		"type": "object",
		"protocols": [
			"cwmp",
			"usp"
		],
		"array": false,
		"Push!": {
			"type": "event",
			"version": "2.13",
			"protocols": [
				"usp"
			],
			"data": {
				"type": "string",
				"read": true,
				"write": true,
				"version": "2.13",
				"protocols": [
					"usp"
				],
				"datatype": "string"
			}
		},
		"Status()": {
			"type": "command",
			"async": true,
			"version" : "2.12",
			"protocols": [
				"usp"
			],
			"input": {
				"Option" : {
					"type" : "string",
					"read" : "true",
					"write" : "true",
					"protocol" : [
						"usp"
					],
					"datatype" : "string"
				}
			},
			"output": {
				"Result" : {
					"type" : "string",
					"read" : "true",
					"write" : "false",
					"protocol" : [
						"usp"
					],
					"datatype" : "string"
				}
			},
			"mapping": [
				{
					"type" : "ubus",
					"ubus" : {
						"object" : "test",
						"method" : "status"
					}
				}
			]
		}
	}
}
```

- **UBUS command:** ubus call usp operate '{"path":"Device.X_IOPSYS_Test.", "action":"Status()", "input":{"Option":"Last"}}'

```bash
{
 	"Results": [
		{
			"path": "Device.X_IOPSYS_Test.Status()",
			"result": [
				{
					"Result": "Success"
				}
			]
		}
	]
}
```

- **UBUS command:** ubus call usp get_supported_dm

```bash
{
	"parameters": [
		{
			"parameter": "Device.X_IOPSYS_Test.Push!",
			"type": "xsd:event",
			"in": [
				"data"
			]
		},
		...
	]
}
```

- **UBUS command:** ubus call usp list_operate

```bash
{
	"parameters": [
		{
			"parameter": "Device.X_IOPSYS_Test.Status()",
			"type": "async",
			"in": [
				"Option"
			],
			"out": [
				"Result"
			]
		},
		...
	]
}
```

> Note1: JSON File can only add vendor or standard objects that are not implemented by `libbbfdm`

> Note2: JSON File is not allowed to overwrite objects/parameters

> Note3: Set, Add, Delete methods are only allowed for uci mapping. therefore for ubus mapping, only Get method is authorized

> Note4: Each object definition in JSON file must begin with "Device." and should have the full parent path if it is under another object

> Note5: You can validate any JSON file using [Validate_JSON_Plugin](/test/tools/validate_json_plugin.py) python script.

```bash
$ ./test/tools/validate_json_plugin.py test/files/etc/bbfdm/json/UserInterface.json
$ ./test/tools/validate_json_plugin.py test/files/etc/bbfdm/json/X_IOPSYS_EU_TEST.json
```

- For more examples on JSON files, you can see these links: [X_IOPSYS_EU_MCPD](https://dev.iopsys.eu/feed/broadcom/-/blob/devel/mcpd/files/etc/bbfdm/json/X_IOPSYS_EU_MCPD.json), [UserInterface](/test/files/etc/bbfdm/json/UserInterface.json), [X_IOPSYS_EU_Dropbear](/test/files/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json), [X_IOPSYS_EU_TEST](/test/files/etc/bbfdm/json/X_IOPSYS_EU_TEST.json)

## BBFDM Tools
BBF tools are written in python3 and has below dependencies.

System utilities: python3-pip, libxml2-utils
```bash
$ sudo apt install -y python3-pip
$ sudo apt install -y libxml2-utils
```
Python utilities: jsonschema, xlwt
```bash
$ pip3 install jsonschema xlwt
```

| Tools                   | Description                                                  |
| ----------------------- |:------------------------------------------------------------:|
|convert_dm_json_to_c.py  | Convert json mapping to C code for dynamic plugins library.  |
|convert_dm_xml_to_json.py| Convert standart xml to Json format.                         |
|generate_dm.py           | Generate list of supported/un-supported parameters based of json input|
|generate_dm_xml.py       | Generate list of supported/un-supported parameters in xml format |
|generate_dm_excel.py     | Generate list of supported/un-supported parameters in xls format |

> Note: Currently all the tools needs to be executed in tools directory.

### XML->JSON convertor
It is a [python script](./tools/convert_dm_xml_to_json.py) to convert Data Model from Broadband Forum XML format to JSON format.

```bash
$ ./convert_dm_xml_to_json.py
Usage: ./convert_dm_xml_to_json.py <tr-xxx cwmp xml data model> <tr-xxx usp xml data model> [Object path]
Examples:
  - ./convert_dm_xml_to_json.py tr-181-2-14-1-cwmp-full.xml tr-181-2-14-1-usp-full.xml Device.
    ==> Generate the json file of the sub tree Device. in tr181.json
  - ./convert_dm_xml_to_json.py tr-104-2-0-2-cwmp-full.xml tr-104-2-0-2-usp-full.xml Device.Services.VoiceService.
    ==> Generate the json file of the sub tree Device.Services.VoiceService. in tr104.json
  - ./convert_dm_xml_to_json.py tr-106-1-2-0-full.xml Device.
    ==> Generate the json file of the sub tree Device. in tr106.json

Example of xml data model file: https://www.broadband-forum.org/cwmp/tr-181-2-14-1-cwmp-full.xml
```

### XML generator

[Python script](./tools/generate_dm_xml.py) to generator list of supported and un-supported Data Model tree in XML for acs supported format: **Broadband Forum schema** and **HDM**.

```bash
$ ./generate_dm_xml.py -h
usage: generate_dm_xml.py [-h] [-r git^https://dev.iopsys.eu/iopsys/stunc.git^devel] [-v iopsys] [-p X_IOPSYS_EU_] [-d DEVICE_PROTOCOL_DSLFTR069v1] [-m iopsys] [-u 002207] [-c DG400PRIME] [-n DG400PRIME-A]
                          [-s 1.2.3.4] [-f BBF] [-o datamodel.xml]

Script to generate list of supported and non-supported parameter in xml format

optional arguments:
  -h, --help            show this help message and exit
  -r git^https://dev.iopsys.eu/iopsys/stunc.git^devel, --remote-dm git^https://dev.iopsys.eu/iopsys/stunc.git^devel
                        Includes OBJ/PARAM defined under remote repositories defined as bbf plugin
  -v iopsys, --vendor-list iopsys
                        Generate data model tree with vendor extension OBJ/PARAM.
  -p X_IOPSYS_EU_, --vendor-prefix X_IOPSYS_EU_
                        Generate data model tree using provided vendor prefix for vendor defined objects.
  -d DEVICE_PROTOCOL_DSLFTR069v1, --device-protocol DEVICE_PROTOCOL_DSLFTR069v1
                        Generate data model tree using this device protocol.
  -m iopsys, --manufacturer iopsys
                        Generate data model tree using this manufacturer.
  -u 002207, --manufacturer-oui 002207
                        Generate data model tree using this manufacturer oui.
  -c DG400PRIME, --product-class DG400PRIME
                        Generate data model tree using this product class.
  -n DG400PRIME-A, --model-name DG400PRIME-A
                        Generate data model tree using this model name.
  -s 1.2.3.4, --software-version 1.2.3.4
                        Generate data model tree using this software version.
  -f BBF, --format BBF  Generate data model tree with HDM format.
  -o datamodel.xml, --output datamodel.xml
                        Generate the output file with given name

Part of BBF-tools, refer Readme for more examples
```

More examples:
```bash
$ ./generate_dm_xml.py -v iopsys -v openwrt
$ ./generate_dm_xml.py -v iopsys -p X_IOPSYS_EU_ -r git^https://dev.iopsys.eu/iopsys/stunc.git^devel
$ ./generate_dm_xml.py -f HDM -v iopsys -p X_IOPSYS_EU_ -o iopsys.xml
```

> Note: For the remote data model, *git* is the only proto allowed to use in the *generate_dm_xml.py* script. Therefore, if you want to use vendor extensions from a local repository, you must use the *generate_dm.py* script.

### Excel generator
[Python script](./tools/generate_dm_excel.py) to generat list of supported and un-supported parameters in excel sheet.

```bash
$ ./generate_dm_excel.py -h
usage: generate_dm_excel.py [-h] -d tr181 [-r git^https://dev.iopsys.eu/iopsys/stunc.git^devel] [-v iopsys] [-p X_IOPSYS_EU_] [-o supported_datamodel.xls]

Script to generate list of supported and non-supported parameter in xls format

optional arguments:
  -h, --help            show this help message and exit
  -d tr181, --datamodel tr181
  -r git^https://dev.iopsys.eu/iopsys/stunc.git^devel, --remote-dm git^https://dev.iopsys.eu/iopsys/stunc.git^devel
                        Includes OBJ/PARAM defined under remote repositories defined as bbf plugin
  -v iopsys, --vendor-list iopsys
                        Generate data model tree with vendor extension OBJ/PARAM
  -p X_IOPSYS_EU_, --vendor-prefix X_IOPSYS_EU_
                        Generate data model tree using provided vendor prefix for vendor defined objects
  -o supported_datamodel.xls, --output supported_datamodel.xls
                        Generate the output file with given name

Part of BBF-tools, refer Readme for more examples
```

More examples:
```bash
$ ./generate_dm_excel.py -d tr181 -v iopsys -v openwrt -o datamodel.xls
$ ./generate_dm_excel.py -d tr181 -d tr104 -v iopsys -o datamodel.xls
$ ./generate_dm_excel.py -d tr181 -v iopsys -p X_IOPSYS_EU_ -r git^https://dev.iopsys.eu/iopsys/xmppc.git^devel -o datamodel_iopsys.xls
```
### Data Model generator

This is a pipeline friendly master script to generate the list of supported and un-supported datamodels in xml and xls formats based on provided input in a json file.
Example json file available [here](./tools/tools_input.json).

```bash
$ Usage: generate_dm.py <input json file>
Examples:
  - generate_dm.py tools_input.json
    ==> Generate all required files defined in tools_input.json file
```

The input json file should be defined as follow:

```bash
{
	"manufacturer": "iopsys",
	"protocol": "DEVICE_PROTOCOL_DSLFTR069v1",
	"manufacturer_oui": "002207",
	"product_class": "DG400PRIME",
	"model_name": "DG400PRIME-A",
	"software_version": "1.2.3.4",
	"vendor_list": [
		"iopsys",
		"openwrt",
		"test"
	],
	"vendor_prefix": "X_IOPSYS_EU_",
	"plugins": [
		{
			"repo": "https://dev.iopsys.eu/iopsys/mydatamodel.git",
			"proto": "git",
			"version": "tag/hash/branch",
			"dm_files": [
				"src/datamodel.c",
				"src/additional_datamodel.c"
			]
		},
		{
			"repo": "https://dev.iopsys.eu/iopsys/mybbfplugin.git",
			"proto": "git",
			"version": "tag/hash/branch",
			"dm_files": [
				"dm.c"
			]
		},
		{
			"repo": "https://dev.iopsys.eu/iopsys/mydatamodeljson.git",
			"proto": "git",
			"version": "tag/hash/branch",
			"dm_files": [
				"src/plugin/datamodel.json"
			]
		},
		{
			"repo": "/home/iopsys/sdk/mypackage/",
			"proto": "local",
			"dm_files": [
				"src/datamodel.c",
				"additional_datamodel.c"
			]
		},
		{
			"repo": "/src/feeds/mypackage/",
			"proto": "local",
			"dm_files": [
				"datamodel.c",
				"src/datamodel.json"
			]
		}
	],
	"output": {
		"acs": [
			"hdm",
			"default"
		],
		"file_format": [
			"xml",
			"xls"
		],
		"output_dir": "./out",
		"output_file_prefix": "datamodel"
	}
}
```

> Note1: For the local repository, you must use an absolute path as repo option.

> Note2: If proto is not defined in the json config file, then git is used by default as proto option.  

- For more examples of tools input json file, you can see this link: [tools_input.json](./devel/tools/tools_input.json)

## Dependencies

To successfully build libbbfdm, the following libraries are needed:

| Dependency  | Link                                        | License        |
| ----------- | ------------------------------------------- | -------------- |
| libuci      | https://git.openwrt.org/project/uci.git     | LGPL 2.1       |
| libubox     | https://git.openwrt.org/project/libubox.git | BSD            |
| libubus     | https://git.openwrt.org/project/ubus.git    | LGPL 2.1       |
| libjson-c   | https://s3.amazonaws.com/json-c_releases    | MIT            |
| libcurl     | https://dl.uxnr.de/mirror/curl              | MIT            |
| libtrace    | https://github.com/apietila/libtrace.git    | GPLv2          |
| libbbf_api  | https://dev.iopsys.eu/iopsys/bbf.git        | LGPL 2.1       |
