# LIBBBFDM Ubus (libbbfdm-ubus)

`libbbfdm-ubus` is a library that provides APIs to expose datamodel over ubus. It is used to manage various data models in different micro-services and higher-level applications.

## Use Cases

`libbbfdm-ubus` library can be used by:

 - `bbfdmd`: to expose the core data model
 - `dm-service`: to expose a sub-data model as micro-service, example: [Netmngr](https://dev.iopsys.eu/network/netmngr/-/blob/devel/src/net_plugin.c)
 - Higher-level applications: to expose custom data models as microservices within their daemon, example: [Timemngr](https://dev.iopsys.eu/bbf/timemngr/-/blob/devel/src/main.c)

## libbbfdm-ubus APIs

The following APIs are provided by `libbbfdm-ubus` to expose data model over ubus:

### bbfdm_ubus_regiter_init

This method is used to initialize the bbfdm_context structure object and register ubus data model methods.

```
int bbfdm_ubus_regiter_init(struct bbfdm_context *bbfdm_ctx)

inputs
	struct bbfdm_context *bbfdm_ctx
		pointer to struct bbfdm_context structure to be initialized.

return
	int fault
		returns 0 on success, or an error code if the registration fails.	
```


### bbfdm_ubus_regiter_free

This method is used to free the bbfdm_context structure object

```
int bbfdm_ubus_regiter_free(struct bbfdm_context *bbfdm_ctx)

inputs
	struct bbfdm_context *bbfdm_ctx
		pointer to struct bbfdm_context structure to be freed.

return
	int fault
		returns 0 on success, or an error code if freeing fails.	
```


### bbfdm_ubus_set_service_name

This method is used the service name for the daemon running as a microservice

```
void bbfdm_ubus_set_service_name(struct bbfdm_context *bbfdm_ctx, const char *srv_name)

input
	struct bbfdm_context *bbfdm_ctx
		pointer to struct bbfdm_context structure

	const char *srv_name
		pointer to service name to set
	
return
	None
```


### bbfdm_ubus_set_log_level

This method is used to set the log level according to the standard syslog levels

```
void bbfdm_ubus_set_log_level(int log_level)

input
	int log_level
		desired log level to set
	
return
	None
```


### bbfdm_ubus_load_data_model

This method is used to load an internal data model, allowing you to use an internal model instead of external plugins (e.g., DotSo or JSON).

```
void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj)

input
	DM_MAP_OBJ *DynamicObj
		pointer to internal data model
	
return
	None
```

## libbbfdm-ubus methods

Following are the ubus methods exposed by `libbbfdm-ubus` when registering a new module:

```bash
# ubus -v list bbfdm
'bbfdm' @9e9928ef
        "get":{"path":"String","paths":"Array","maxdepth":"Integer","optional":"Table"}
        "schema":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "instances":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "set":{"path":"String","value":"String","obj_path":"Table","optional":"Table"}
        "operate":{"command":"String","command_key":"String","input":"Table","optional":"Table"}
        "add":{"path":"String","obj_path":"Table","optional":"Table"}
        "del":{"path":"String","paths":"Array","optional":"Table"}
        "service":{"cmd":"String","name":"String","parent_dm":"String","objects":"Array"}
        "notify_event":{"name":"String","input":"Array"}
```

## libbbfdm-ubus example(s)

1. The requested value is correct as per TR181 standard, but there is a limitation in the device.

```console
root@iopsys:~# ubus call bbfdm set '{"path":"Device.Firewall.Config", "value":"High"}'
{
    "results": [
        {
            "path": "Device.Firewall.Config",
            "fault": 9007,
            "fault_msg": "The current Firewall implementation supports only 'Advanced' config."
        }
    ]
}
```

2. The requested value is outside the allowed range.

```console
root@iopsys:~# ubus call bbfdm set '{"path":"Device.Firewall.Chain.1.Rule.9.DestPort", "value":"123456"}'
{
    "results": [
        {
            "path": "Device.Firewall.Chain.1.Rule.9.DestPort",
            "fault": 9007,
            "fault_msg": "'123456' value is not within range (min: '-1' max: '65535')"
        }
    ]
}
```

3. Some arguments should be defined to perform the requested operation.

```console
root@iopsys:~# ubus call bbfdm operate '{"command":"Device.IP.Diagnostics.IPPing()", "command_key":"ipping_test", "input":{}}'
{
    "results": [
        {
            "path": "Device.IP.Diagnostics.IPPing()",
            "data": "ipping_test",
            "fault": 7004,
            "fault_msg": "IPPing: 'Host' input should be defined"
        }
    ]
}
```

4. The path parameter value must start with 'Device.'. The command below doesn't have Device before path "Users.User."

```console
root@iopsys:~# ubus call bbfdm get '{"path":"Users.User.", "optional": {"format":"raw", "proto":"usp"}}'
{
    "results": [
        {
            "path": "Users.User.",
            "fault": 7026,
            "fault_msg": "Path is not present in the data model schema"
        }
    ]
}
```

These fault messages defined in datamodel handlers, users can add such fault message using `bbfdm_set_fault_message` libbbfdm-api's API, if no specific fault message defined for particular obj/param, datamodel returns standard error messages that are defined in CWMP and USP protocols as the fault message value.

### Fault handling

To indicate a fault and source of fault, `libbbfdm-ubus` provides `fault` along with `fault_msg` in the response in case of faults, which then handled by higher layer applications (i.e icwmp, obuspa).

This provides a clear inside on the root cause of the fault, and based on `fault_msg` it's easily to understand what the issue is and how to fix it and find out the limitations(if there are any on the device).

##### Errors Codes

| Error Code | Meaning                                                      |
|------------|--------------------------------------------------------------|
| 7003       | Message failed due to an internal error.                     |
| 7004       | Message failed due to invalid values in the request elements and/or failure to update one or more parameters during Add or Set requests. |
| 7005       | Message failed due to memory or processing limitations.      |
| 7008       | Requested path was invalid or a reference was invalid.       |
| 7010       | Requested Path Name associated with this ParamError did not match any instantiated parameters. |
| 7011       | Unable to convert string value to correct data type.         |
| 7012       | Out of range or invalid enumeration.                         |
| 7022       | Command failed to operate.                                   |
| 7026       | Path is not present in the data model schema.                |


## Parallel calls over Ubus

Some datamodel operations takes less time to execute compared to other, like
- Get on sub-set of datamodel or an individual datamodel parameter takes very less, where as
- Get on complete Device. and Async operate commands takes much longer

executing/serializing operations simplifies the code from developer perspective, but its not suitable for deployments. To make it suitable `bbfdmd` support parallel calls.

- All datamodel `operate` commands are running in parallel

example(s):

```console
root@iopsys:~# time ubus call bbfdm get '{"path":"Device."}' >/dev/null &
root@iopsys:~# time ubus call bbfdm get '{"path":"Device.Users."}' >/dev/null
real    0m 0.07s
user    0m 0.00s
sys     0m 0.00s
root@iopsys:~#
real     0m 1.86s
user    0m 0.05s
sys     0m 0.00s

[1]+  Done                       time ubus call bbfdm get "{\"path\":\"Device.\"}" >/dev/null
root@iopsys:~#
```
