# How to Write a datamodel definition using C code

Datamodel definition can be added manually by defining the whole tree node-by-node or structure-by-structure, or can be semi-automated by using a `bbfdm` tool, which generates template C source code with all the structure definitions and dummy get/set/add/delete handlers.

## Generate datamodel source code with dummy definition using tool

```bash
./tools/convert_dm_json_to_c.py --help
Usage: ./tools/convert_dm_json_to_c.py [Object path]
Examples:
  - ./tools/convert_dm_json_to_c.py
    ==> Generate the C code of full data model in datamodel/ folder
  - ./tools/convert_dm_json_to_c.py Device.DeviceInfo.
    ==> Generate the C code of Device.DeviceInfo object in datamodel/ folder
  - ./tools/convert_dm_json_to_c.py Device.Services.VoiceService.{i}.DECT.Base.{i}.
    ==> Generate the C code for a specific multi-instance object in datamodel/ folder
```

After running the tool, datamodel shall be gets generated in datamodel directory with dummy handlers with '//TODO' marker, to complete the definition, developer need to update the logic in dummy function pointers.

To know more about different type of function pointers, check below section.

## Write datamodel source code manually

To write a datamodel definition manually, one has to add the Root definition along with object and leaves.

### Root definition

As per TR181, the root of the tree is 'Device.', which can be defined by using below named structure 'tDynamicObj'

```bash
DM_MAP_OBJ tDynamicObj[] = {
{"Device.", tDeviceObj, tDeviceParams},
{0}
};
```

The “tDynamicObj” table contains entries of **DM_MAP_OBJ** structure, which contains three arguments:

|     Argument     |                                     Description                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `parentobj`      | A string of the parent object name. Example “Device.IP.Diagnostics.”, “Device.DeviceInfo”, “Device.WiFi.Radio.” |
| `nextobject`     | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `parameter`      | Pointer to a **DMLEAF** array which contains a list of the child parameters |


> Note: This symbol needs to be defined once per module globally, and has the root definition for that module's datamodels

Datamodel can be divided in two parts,
1. Intermediate nodes or objects (defined with DMOBJ)
2. End nodes or leaf parameters (defined with DMLEAF)

### Object definition (DMOBJ)

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
| `linker`            | This argument is deprecated and should be `NULL` |
| `bbfdm_type`        | The bbfdm type of the object. Could be **BBFDM_CWMP**, **BBFDM_USP**, **BBFDM_BOTH** or **BBFDM_NONE**.If it's **BBFDM_BOTH** then we can see this object in all protocols (CWMP, USP,...) |
| `uniqueKeys`        | This argument is deprecated and should be `NULL` |


example:
```bash
/* *** Device. *** */
DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH, NULL},
{0}
};
```

Datamodel objects can be of two types

- Single instance object (Path which has a '.' prefix)
- Multi-instance objects (Path with has '.{i}' prefix)

Multi-instance objects means, there could be one or more such nodes available, it can be viewed as a group of things which also has a close resemblance with 'uci sections'. In datamodel definitions, this mostly depends on runtime data, and to define such object, one has to define a `browseinstobj` function pointer to dynamically gather data and create instances at the runtime.

#### Browse definition

The browse function allow to go over all instances of the current object and link them to the data model tree. So, it need to retrieve the instance number for the current instance and then create a link between current instance and existing defined tree.

To retrieve the instance, below APIs can be used

- `handle_instance`: allow to retrieve/attribute the instances number/alias from uci config sections depending of the request and the instance mode.
- `handle_instance_without_section`: allow to attribute the instances number/alias with constant values.

To link the current instance with the datamodel definition
- DM_LINK_INST_OBJ: This API needs to be called for each instance, this API also has a structure called `dm_data` which can be used to pass-on the data from current node to child objects.

> Note1: It is **mandatory** to use the generic structure `(struct dm_data *)` to pass the data to child objects/params.

> Note2: the browse function is only required for multi-instances objects.

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
| `dm_falgs`          | An enumeration value used to specify the displayed parameter value. Could be **DM_FLAG_REFERENCE**, **DM_FLAG_UNIQUE**, **DM_FLAG_LINKER** or **DM_FLAG_SECURE**. |

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
| `setvalue`          | The function which call the operation of the event |
| `bbfdm_type`        | The bbfdm type of the event. It should be **BBFDM_USP** as long as events are only defined in USP protocol. |

##### How events works

A datamodel event can be sent from external source (like: hotplug script) or it can be auto-generated based on system events. `bbfdmd` provides a methods to trigger datamodel event from ubus event.

Upon starting `bbfdmd`, it calls `bbf_entry_method` API with `BBF_SCHEMA` method to retrieve all events supported by Data Model. Subsequently, it attempts to register an event handler for each event by using the event name argument defined in each event leaf and then listens for that event name.

When the ubus event triggered in the system, `bbfdmd` calls `bbf_entry_method` API with `BBF_EVENT` method to perform the event operation. And finally, it sends `bbfdm.event` ubus event with the required input information obtained from the returned event operation.

Example:

Below is an example of `Device.WiFi.DataElements.AssociationEvent.Associated!` event implementation:
```bash
static event_args wifidataelementsassociationevent_associated_args = {
    .name = "wifi.dataelements.Associated",
    .param = (const char *[]) {
        "type",
        "version",
        "protocols",
        "BSSID",
        "MACAddress",
        "StatusCode",
        "HTCapabilities",
        "VHTCapabilities",
        "HECapabilities",
        "TimeStamp",
        NULL
    }
};

static int get_event_args_WiFiDataElementsAssociationEvent_Associated(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsassociationevent_associated_args;
    return 0;
}

static int event_WiFiDataElementsAssociationEvent_Associated(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case EVENT_CHECK:
		// Nothing to check
		break;
	case EVENT_RUN:
		char *event_time = dmjson_get_value((json_object *)value, 1, "eventTime");
		char *bssid = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent.AssocData", "DisassocData", "BSSID");
		char *mac_addr = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent.AssocData", "DisassocData", "MACAddress");
	
		add_list_parameter(ctx, dmstrdup("TimeStamp"), dmstrdup(event_time), DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, dmstrdup("BSSID"), dmstrdup(bssid), DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, dmstrdup("MACAddress"), dmstrdup(mac_addr), DMT_TYPE[DMT_STRING], NULL);
		break;
	}

	return 0;
}

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Associated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsAssociationEvent_Associated, event_WiFiDataElementsAssociationEvent_Associated, BBFDM_USP},
{0}
};
```

More leaf Example(s):

```bash
DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{"Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_Reboot, BBFDM_USP},
{"Boot!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP},
{0}
};
```

#### Alias handling
In general datamodel parameters with multi-instance objects has a parameter named as '.Alias' to uniquely identify the instance. Below APIs can be used to get/set Aliases, provided browseinstobj has dmmap definition in dm_data.

- Alias get handler (`bbf_get_alias`)
- Alias set handler (`bbf_set_alias`)

```bash
int bbf_get_alias(struct dmctx *ctx, struct uci_section *s, char *option_name, char *instance, char **value)
```

Input(s):

| Input  |  Description |
| ------ | ------------ |
| ctx    | bbf context  |
|  s     | Pointer to dmmap uci section from where will get Alias value |
| option_name| dmmap uci option name for alias value |
| instance | instance value |
| value   | pointer to where the value will be stored |

```bash
int bbf_set_alias(struct dmctx *ctx, struct uci_section *s, char *option_name, char *instance, char *value);
```

Input(s):

| Input  |  Description |
| ------ | ------------ |
| ctx    | bbf context  |
| s      | Pointer to dmmap uci section to where will save Alias value |
| option_name | dmmap uci option name to store the alias value |
| instance | instance value |
| value  | the value to be set |

Example:
```bash
static int get_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "endpointalias", instance, value);
}

static int set_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "endpointalias", instance, value);
}
```

#### NumberOfEntries parameter handling

Each multi-instance object has a related LEAF entry to denote the number of instances present for that object, Since multi-instance object already has a browse function which got the runtime logic to loop through the instances, `libbbfdm-api` provides another API `get_number_of_entries` to get the number of entries.

Example:

```bash
static int get_Device_InterfaceStackNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseInterfaceStackInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}
```
