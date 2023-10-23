# Datamodel Linker

Aim of this document is to explain how to migrate the linker functionality to the new linker design.

As per the definition in TR-181, each multi-instance object should have at least one unique key to identify each instance that's why in the current implementation we have defined two arguments in `DMOBJ` structure to support that:
 - `get_linker` function pointer to specify the linker value
 - `unique_keys` array to list the unique key parameters

```bash
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Interface", &DMWRITE, addObjIPInterface, delObjIPInterface, NULL, browseIPInterfaceInst, NULL, NULL, tIPInterfaceObj, tIPInterfaceParams, get_linker_ip_interface, BBFDM_BOTH, LIST_KEY{"Alias", "Name", NULL}},
```

However, this implementation caused us many issues, such as:

- The unique key list can include parameters that are not yet supported.
- A parameter can map to another multi-instance object that doesn't have a linker function.

To improve this requirement, we introduce a new argument `dm_flags` in `DMLEAF` structure which can play the role of defining all required information above.

The new `dm_flags` argument can only support for now 3 enumerations:

 * `DM_FLAG_REFERENCE`: parameter value should be an object reference available in the tree
 * `DM_FLAG_UNIQUE`: parameter value should be used to identify each instance
 * `DM_FLAG_LINKER`: parameter value can be used to identify each instance when calling a set method since each multi-instance object can have many unique keys

> Note:

- `DM_FLAG_LINKER` **must** be defined only once for each multi-instance object.
- Each object can have multiple unique keys.
- Regarding JSON plugin, we also introduce a new array option to support the same functionality. `"flags": [ "Reference", "Unique", "Linker" ]`.

Now with the new design datamodel gives more flexibility to define any parameter as a unique key, linker and reference at the same time, and all linker functions was removed and all related APIs are deprecated.

Below the list of APIs that have been deprecated:
- dm_entry_validate_allowed_objects
- adm_entry_get_linker_param
- adm_entry_get_linker_value

Below the list of new APIs that we introduced:
- dm_validate_allowed_objects
- adm_entry_get_reference_param
- bbf_get_reference_param
- bbf_get_reference_args


Actually bbfdm supports two methods to expose datamodel tree:

- datamodel exposed via bbfdm, which includes the main tree defined in bbfdm package and datamodel registred via JSON or DotSo plugins.
- datamodel exposed through micro-services.

In the next item, we will explain how to migrate to the new linker design based on the datamodel registration.

## Migrate to the new linker design

1. Update `dm_falgs` argument of `DMLEAF` structure

- Parameter exposed via main tree, DotSo plugin or micro-service: add `DM_FLAG_REFERENCE` to all parameters that have a path reference as a value.

```bash
DMLEAF tIPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
...
"LowerLayers", &DMWRITE, DMT_STRING, get_IPInterface_LowerLayers, set_IPInterface_LowerLayers, BBFDM_BOTH, DM_FLAG_REFERENCE},
...
}
```

- Parameter exposed via JSON plugin: add `Reference` value to the `flags` option for all parameters that have a path reference as a value

```bash
"Profile": {
	"type": "string",
	"read": true,
	...
	"flags": [
		"Reference"
	],
	...
}
```

2. Update Get method based on the new API

Before updating the get method, it is important to know which unique key parameter is used to identify the path reference then update the get method accordingly.

- Parameter exposed via main tree or DotSo plugin: use `adm_entry_get_reference_param` API to get the path reference

```bash
static int get_MQTTBroker_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *iface = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface", &iface);
	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", iface, value);
	return 0;
}
```

- Parameter exposed via micro-service: use `bbf_get_reference_param` API to get the path reference

```bash
static int get_client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *iface = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface", &iface);

	return bbf_get_reference_param("Device.IP.Interface.", "Name", iface, value);

}
```

- Parameter exposed via JSON plugin: update the `linker_obj` option with the full parameter path to obtain the path reference

```bash
"Profile": {
	"type": "string",
	"read": true,
	"write": true,
	"protocols": [
		"cwmp",
		"usp"
	],
	"flags": [
		"Reference"
	],
	"mapping": [
		{
			"type": "uci",
			"uci": {
				"file": "urlfilter",
				"section": {
					"type": "filter"
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

> Note:

- All instances should be replaced with the instance wildcard '*'.

3. Update Set method based on the new API

- Parameter exposed via main tree, DotSo plugin or micro-service: first, add `DM_FLAG_LINKER` to mark that the parameter is being used as a linker for that object.

```bash
DMLEAF tIPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
...
{"Name", &DMREAD, DMT_STRING, get_IPInterface_Name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
...
}
```

Then, use `bbf_get_reference_args` to get the reference path and value in the set method.

```bash
static int set_client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "interface", reference.value);
			break;
	}
	return 0;
}
```

- Parameter exposed via JSON plugin: add `Linker` value to the `flags` array to mark that the parameter is being used as a linker for that object.

```bash
"Name": {
	"type": "string",
	"read": true,
	"write": true,
	"protocols": [
		"cwmp",
		"usp"
	],
	"flags": [
		"Unique",
		"Linker"
	],
	...
}
```

The following links provide more examples of how the linker was implemented.

- https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/libbbfdm/dmtree/tr181/ip.c#L2242
- https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/libbbfdm/dmtree/tr181/ip.c#L1273
- https://dev.iopsys.eu/bbf/timemngr/-/blob/devel/src/times.c#L456
- https://dev.iopsys.eu/iopsys/hostmngr/-/blob/devel/src/bbf_plugin/hosts.c#L404
- https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/test/files/etc/bbfdm/plugins/urlfilter.json#L135
- https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/test/files/etc/bbfdm/plugins/urlfilter.json#L293
