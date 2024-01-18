# How to add support for a new Object/Parameter

As mentioned in README, all Data Models are stored in the **'dmtree'** folder. In order to implement a new object/parameter, you need to expand its get/set/add/delete functions and then save them in the right folder.

`bbfdm` library offers a tool to generate templates of the source code from json files placed under **'dmtree/json'**. So, any developer can fill these json files ([tr181](../../libbbfdm/dmtree/json/tr181.json) or [tr104](../../libbbfdm/dmtree/json/tr104.json)) with mapping field according to UCI, UBUS or CLI commands then generate the source code in C.

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

- **@Name:** the section name of parent object

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

- **@Name:** the section name of parent object

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

- **@Name:** the section name of parent object

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

> Note3: you can use [bbf_test plugin](../../test/bbf_test/bbf_test.c) as a reference in order to develop any new object/leaf/browse.

