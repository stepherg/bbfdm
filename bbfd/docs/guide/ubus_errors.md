# UBUS Errors

## Path syntax and possible error cases

Please note some error scenerios with the uspd.

1. The path parameter value must start with 'Device.'. The command below doesn't have Device before path "Users.User."

```console
root@iopsys:~# ubus call usp.raw get '{"path":"Users.User."}'
{
        "fault": 7026
}
```

2. The path parameter must end with a '.' if the path element is not a leaf element e.g.,
   Note that first two commands doesn't end with a '.' while the command with Alias is correct, due to Alias
   being the leaf element. To find correct schema path user can check with dump_schema option.

```console
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.4"}'
{
        "fault": 7026
}
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User"}'
{
        "fault": 9005
}
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.*"}'
{
        "fault": 7026
}
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.4.Alias"}'
{
        "Alias": "cpe-4"
}
```

3. In path parameter value below, note that, the first search expression 'Type==Normal' is string which should be used as : Type==\"Normal\"

```console
root@iopsys:~# ubus call usp get '{"path":"Device.IP.Interface.[Type==Normal].IPv4Address.[AddressingType==\"Static\"].IPAddress"}'
{
        "fault": 7008
}
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.IP.Interface.[Type==\"Normal\"].IPv4Address.[AddressingType==\"Static\"].IPAddress"}'
{
        "Interface": [
                {
                        "IPv4Address": [
                                {
                                        "IPAddress": "2.0.0.3"
                                }
                        ]
                }
        ]
}
```

4. The path parameter value must not have an empty search expression

```console
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.[]."}'
{
        "fault": 9005
}
```

5. The path parameter value must use proper '.' separated path search expression. Note that a '.' is missing between User and *

```console
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User*."}'
{
        "fault": 7026
}
```

6. The path parameter value must be a valid path schema, in example below SSID is used which is invalid schema element for Device.Users.User.{i}.

```console
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.1.SSID"}'
{
        "fault": 7026
}
```

7. Please note that in search expression, string comparison only work with "==" or "!=". Whereas in command below its =

```console
root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.[Username=\"user\"].Alias"}'
{
        "fault": 7008
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


