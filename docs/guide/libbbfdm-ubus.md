# LIBBBFDM Ubus (libbbfdm-ubus)

`libbbfdm-ubus` is a library that provides APIs to expose the data model over ubus as microservices. It is used to manage various data models in different microservices and higher-level applications.

## Use Cases

The `libbbfdm-ubus` library can be used by:

- `dm-service`: To expose a sub-data model as a microservice, e.g., [Network Manager](https://dev.iopsys.eu/network/netmngr/-/blob/devel/src/net_plugin.c), [Bridge Manager](https://dev.iopsys.eu/network/bridgemngr/-/blob/devel/src/driver_vlan_backend/bridging.c)
- Higher-level applications (unified daemon): To expose custom data models as microservices within their daemon, e.g., [Time Manager](https://dev.iopsys.eu/bbf/timemngr/-/blob/devel/src/main.c), [System Manager](https://dev.iopsys.eu/system/sysmngr/-/blob/devel/src/sysmngr.c)

## libbbfdm-ubus APIs

The following APIs are provided by `libbbfdm-ubus` to expose the data model over ubus:

### bbfdm_ubus_register_init

This method initializes the `bbfdm_context` structure object and registers ubus data model methods.

```c
int bbfdm_ubus_register_init(struct bbfdm_context *bbfdm_ctx)

Inputs:
    struct bbfdm_context *bbfdm_ctx
        Pointer to the `bbfdm_context` structure to be initialized.

Returns:
    int fault
        Returns 0 on success, or an error code if the registration fails.
```

### bbfdm_ubus_register_free

This method frees the `bbfdm_context` structure object.

```c
int bbfdm_ubus_register_free(struct bbfdm_context *bbfdm_ctx)

Inputs:
    struct bbfdm_context *bbfdm_ctx
        Pointer to the `bbfdm_context` structure to be freed.

Returns:
    int fault
        Returns 0 on success, or an error code if freeing fails.
```

### bbfdm_ubus_set_service_name

This method sets the service name for the daemon running as a microservice.

```c
void bbfdm_ubus_set_service_name(struct bbfdm_context *bbfdm_ctx, const char *srv_name)

Inputs:
    struct bbfdm_context *bbfdm_ctx
        Pointer to the `bbfdm_context` structure.

    const char *srv_name
        Pointer to the service name to set.

Returns:
    None
```

### bbfdm_ubus_set_log_level

This method sets the log level according to the standard syslog levels.

```c
void bbfdm_ubus_set_log_level(int log_level)

Inputs:
    int log_level
        Desired log level to set.

Returns:
    None
```

### bbfdm_ubus_load_data_model

This method loads an internal data model, allowing you to use an internal model instead of external plugins (e.g., DotSo or JSON).

```c
void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj)

Inputs:
    DM_MAP_OBJ *DynamicObj
        Pointer to the internal data model.

Returns:
    None
```

## libbbfdm-ubus Methods

Following are the ubus methods exposed by `libbbfdm-ubus` when registering a new module:

```bash
# ubus -v list bbfdm.sysmngr
'bbfdm.sysmngr' @6931a0bb
    "get":{"path":"String","optional":"Table"}
    "schema":{"path":"String","first_level":"Boolean","optional":"Table"}
    "instances":{"path":"String","optional":"Table"}
    "set":{"path":"String","value":"String","datatype":"String","obj_path":"Table","optional":"Table"}
    "operate":{"path":"String","command_key":"String","input":"Table","optional":"Table"}
    "add":{"path":"String","obj_path":"Table","optional":"Table"}
    "del":{"path":"String","paths":"Array","optional":"Table"}
    "reference_path":{"path":"String","optional":"Table"}
    "reference_value":{"path":"String","optional":"Table"}
```

## libbbfdm-ubus Examples

### 1. The requested value is correct as per the TR181 standard, but there is a limitation in the device.

```bash
root@iowrt:~# ubus call bbfdm.firewallmngr set '{"path":"Device.Firewall.Config", "value":"High"}'
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

### 2. The requested value is outside the allowed range.

```bash
root@iowrt:~# ubus call bbfdm.firewallmngr set '{"path":"Device.Firewall.Chain.1.Rule.9.DestPort", "value":"123456"}'
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

### 3. Some arguments should be defined to perform the requested operation.

```bash
root@iowrt:~# ubus call bbfdm.netmngr operate '{"path":"Device.IP.Diagnostics.IPPing()", "command_key":"ipping_test", "input":{}}'
{
    "results": [
        {
            "path": "Device.IP.Diagnostics.IPPing()",
            "data": "ipping_test",
            "output": [
                {
                    "fault": 7004,
                    "IPPing: 'Host' input should be defined"                    
                }
            ]
        }
    ]
}
```

### 4. The path parameter value must start with 'Device.'. The command below doesn't have Device before path "Users.User."

```console
root@iowrt:~# ubus call bbfdm.usermngr get '{"path":"Users.User.", "optional": {"format":"raw", "proto":"usp"}}'
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

## Fault Handling

To indicate a fault and its source, `libbbfdm-ubus` provides `fault` along with `fault_msg` in the response in case of faults, which are then handled by higher-layer applications (e.g., icwmp, obuspa).

This provides a clear insight into the root cause of the fault. Based on `fault_msg`, it’s easy to understand the issue, how to fix it, and identify limitations (if any) in the device.

### Error Codes

| Error Code | Meaning |
|------------|---------|
| 7003 | Message failed due to an internal error. |
| 7004 | Message failed due to invalid values in the request elements and/or failure to update one or more parameters during Add or Set requests. |
| 7005 | Message failed due to memory or processing limitations. |
| 7008 | Requested path was invalid or a reference was invalid. |
| 7010 | Requested Path Name associated with this ParamError did not match any instantiated parameters. |
| 7011 | Unable to convert string value to correct data type. |
| 7012 | Out of range or invalid enumeration. |
| 7022 | Command failed to operate. |
| 7026 | Path is not present in the data model schema. |
