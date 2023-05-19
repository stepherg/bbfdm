# UBUS Errors

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
                        "fault_msg": ""
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
                        "fault_msg": ""
                }
        ]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users.User.*", "optional": {"format":"raw", "proto":"usp"}}'
{
        "results": [
                {
                        "path": "Device.Users.User.*",
                        "fault": 7026,
                        "fault_msg": ""
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
                        "fault": 7026,
                        "fault_msg": ""
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
                        "fault_msg": ""
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


