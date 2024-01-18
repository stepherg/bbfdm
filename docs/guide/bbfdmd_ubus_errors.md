# UBUS Errors

Today, in addional to the `CWMP` and `USP` standard error messages, bbfdm has introduced a new feature to provide customers more clarification about the root cause of the fault,
and based on that it's easily to understand what the issue is and how to fix it and find out the limitations we have on the device.

Whenever you encounter an error in a specific method(GET/SET/ADD/DELETE/OPERATE), you can use the `fault_msg` option to understand the reason for the error.

## Example of fault messages

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

root@iopsys:~# ubus call bbfdm set '{"path":"Device.Firewall.AdvancedLevel", "value":"Device.Firewall.Level.2"}'
{
	"results": [
		{
			"path": "Device.Firewall.AdvancedLevel",
			"fault": 9007,
			"fault_msg": "The current Firewall implementation supports only one Level. So the value should be 'Device.Firewall.Level.1'."
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

4. The requested method is not permitted since the instance was created by the system.

```console
root@iopsys:~# ubus call bbfdm add '{"path":"Device.Firewall.Chain.2.Rule."}'
{
	"results": [
		{
			"path": "Device.Firewall.Chain.2.Rule.",
			"fault": 9003,
			"fault_msg": "This is a dynamic 'Chain' instance which is created by 'Port Mapping', so it's not permitted to add a static 'Rule'."
		}
	]
}

root@iopsys:~# ubus call bbfdm del '{"path":"Device.Firewall.Chain.1.Rule.1."}'
{
	"results": [
		{
			"path": "Device.Firewall.Chain.1.Rule.1.",
			"fault": 9003,
			"fault_msg": "This is a dynamic 'Rule' instance, therefore it's not permitted to delete it."
		}
	]
}
```

> Note: If no specific fault message defined for particular obj/param, we return the standard error messages that are defined in CWMP and USP protocols as the fault message value.

## Path syntax and possible error cases

Please note some error scenerios with the bbfdm.

1. The path parameter value must start with 'Device.'. The command below doesn't have Device before path "Users.User."

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

2. The path parameter must end with a '.' if the path element is not a leaf element e.g.,
   Note that first two commands doesn't end with a '.' while the command with Alias is correct, due to Alias
   being the leaf element. To find correct schema path user can check with dump_schema option.

```console
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users.User.4", "optional": {"format":"raw", "proto":"usp"}}'
{
	"results": [
		{
			"path": "Device.Users.User.4",
			"fault": 7026,
			"fault_msg": "Path is not present in the data model schema"
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users.User.*", "optional": {"format":"raw", "proto":"usp"}}'
{
	"results": [
		{
			"path": "Device.Users.User.*",
			"fault": 7008,
			"fault_msg": "Requested path was invalid or a reference was invalid"
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users.User.4.Alias", "optional": {"format":"raw", "proto":"usp"}}'
{
        "results": [
                {
                        "path": "Device.Users.User.4.Alias",
                        "data": "cpe-4",
                        "type": "xsd:string"
                }
        ]
}
```

3. The path parameter value must use proper '.' separated path search expression. Note that a '.' is missing between User and *

```console
root@eagle-44d43771b550:~# ubus call bbfdm get '{"path":"Device.Users.User.*", "optional": {"format":"raw", "proto":"usp"}}'
{
	"results": [
		{
			"path": "Device.Users.User.*",
			"fault": 7008,
			"fault_msg": "Requested path was invalid or a reference was invalid"
		}
	]
}
```

4. The path parameter value must be a valid path schema, in example below SSID is used which is invalid schema element for Device.Users.User.{i}.

```console
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users.User.1.SSID", "optional": {"format":"raw", "proto":"usp"}}'
{
	"results": [
		{
			"path": "Device.Users.User.1.SSID",
			"fault": 7026,
			"fault_msg": "Path is not present in the data model schema"
		}
	]
}
```

#### Errors Codes

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
