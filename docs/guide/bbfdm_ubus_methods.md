# UBUS Methods

`bbfdmd` needs to be started on startup after `ubusd`, as it exposes the data-model objects over `ubus`.

```console
root@iopsys:~# ubus list |grep bbfdm
bbfdm
```

`usp` namespace is to provide the output as required by `End User` or in pretty format, which can be used easliy by other front-end applications(like: `obuspa`, `icwmp`).


`bbfdmd` namespace provides many methods with functionalities:

```console
root@iopsys:~# ubus -v list bbfdm
'bbfdm' @17924c56
        "get":{"path":"String","paths":"Array","maxdepth":"Integer","optional":"Table"}
        "schema":{"path":"String","paths":"Array","first_level":"Boolean","commands":"Boolean","events":"Boolean","params":"Boolean","optional":"Table"}
        "instances":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "set":{"path":"String","value":"String","obj_path":"Table","optional":"Table"}
        "operate":{"command":"String","command_key":"String","input":"Table","optional":"Table"}
        "add":{"path":"String","obj_path":"Table","optional":"Table"}
        "del":{"path":"String","paths":"Array","optional":"Table"}
        "transaction":{"cmd":"String","timeout":"Integer","restart_services":"Boolean","optional":"Table"}
        "notify_event":{"name":"String","input":"Table"}
root@iopsys:~#
```

> Note1: `optional` table are present in all methods and it supports below options:

```console
"optional":{"proto":"String", "instance_mode":"Integer", "transaction_id":"Integer", "format":"String"}
```

 - `proto` in each method specify the data-model prototype('cwmp', 'usp') to use, if not provided default data-model will be used.

 - `instance_mode` could be 0 or 1, for instance number, instance alias respectively.

 - `transaction_id` to define the transaction id number.

 - `format` could be 'raw' or 'pretty', to specify the format to use as output, if not provided 'pretty' format will be used.

> Note2: `first_level` true means only get next level objects and false means get all objects recursively

> Note3: `maxdepth` is measured on max number of .(Dot) present in object name

The objects registered with the above namespace can be called with appropriate parameters to perform a `Get/Set/Operate/Add Object/Delete Object` operation as below.

## Overview

`bbfdmd` provides below functionality in pretty or raw formats using supported commands:

   - Get single value
   - Get multiple values
   - Set single value
   - Set multiple values
   - Operate
   - Add object
   - Add object and setting its parameters
   - Delete single object
   - Delete multiple objects
   - Instances
   - schema
   - Transaction start 
   - Transaction status
   - Transaction commit
   - Transaction abort
   - Send notification for an event


### Get single value
API to query the value of a specific object.

```console
root@iopsys:~# ubus call bbfdm get '{"path":"Device.IP.Diagnostics.", "optional": {"proto":"usp"}}'
{
        "Diagnostics": {
                "IPv4PingSupported": true,
                "IPv6PingSupported": true,
                "IPv4TraceRouteSupported": true,
                "IPv6TraceRouteSupported": true,
                "IPv4DownloadDiagnosticsSupported": true,
                "IPv6DownloadDiagnosticsSupported": true,
                "IPv4UploadDiagnosticsSupported": true,
                "IPv6UploadDiagnosticsSupported": true,
                "IPv4UDPEchoDiagnosticsSupported": true,
                "IPv6UDPEchoDiagnosticsSupported": true,
                "IPv4ServerSelectionDiagnosticsSupported": true,
                "IPv6ServerSelectionDiagnosticsSupported": true,
                "IPLayerCapacitySupported": true,
                "IPLayerMaxConnections": 1,
                "IPLayerMaxIncrementalResult": 3600,
                "IPLayerCapSupportedSoftwareVersion": "7.5.1",
                "IPLayerCapSupportedControlProtocolVersion": 9,
                "IPLayerCapSupportedMetrics": "IPLR,Sampled_RTT,IPDV,IPRR,RIPR",
                "UDPEchoConfig": {
                        "Enable": false,
                        "Interface": "",
                        "SourceIPAddress": "",
                        "UDPPort": 0,
                        "EchoPlusEnabled": false,
                        "EchoPlusSupported": true,
                        "PacketsReceived": 0,
                        "PacketsResponded": 0,
                        "BytesReceived": 0,
                        "BytesResponded": 0,
                        "TimeFirstPacketReceived": "0001-01-01T00:00:00.000000Z",
                        "TimeLastPacketReceived": "0001-01-01T00:00:00.000000Z"
                }
        }
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.IP.Diagnostics.", "optional": {"proto":"cwmp"}}'
{
        "Diagnostics": {
                "IPv4PingSupported": true,
                "IPv6PingSupported": true,
                "IPv4TraceRouteSupported": true,
                "IPv6TraceRouteSupported": true,
                "IPv4DownloadDiagnosticsSupported": true,
                "IPv6DownloadDiagnosticsSupported": true,
                "IPv4UploadDiagnosticsSupported": true,
                "IPv6UploadDiagnosticsSupported": true,
                "IPv4UDPEchoDiagnosticsSupported": true,
                "IPv6UDPEchoDiagnosticsSupported": true,
                "IPv4ServerSelectionDiagnosticsSupported": true,
                "IPv6ServerSelectionDiagnosticsSupported": true,
                "IPLayerCapacitySupported": true,
                "IPPing": {
                        "DiagnosticsState": "None",
                        "Interface": "",
                        "ProtocolVersion": "Any",
                        "Host": "",
                        "NumberOfRepetitions": 3,
                        "Timeout": 1000,
                        "DataBlockSize": 64,
                        "DSCP": 0,
                        "IPAddressUsed": "",
                        "SuccessCount": 0,
                        "FailureCount": 0,
                        "AverageResponseTime": 0,
                        "MinimumResponseTime": 0,
                        "MaximumResponseTime": 0,
                        "AverageResponseTimeDetailed": 0,
                        "MinimumResponseTimeDetailed": 0,
                        "MaximumResponseTimeDetailed": 0
                },
                "TraceRoute": {
                        "DiagnosticsState": "None",
                        "Interface": "",
                        "ProtocolVersion": "Any",
                        "Host": "",
                        "NumberOfTries": 3,
                        "Timeout": 5000,
                        "DataBlockSize": 72,
                        "DSCP": 0,
                        "MaxHopCount": 30,
                        "ResponseTime": 0,
                        "IPAddressUsed": "",
                        "RouteHopsNumberOfEntries": 0
                }
        }
}

root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users."}'
{
        "Users": {
                "UserNumberOfEntries": 3,
                "GroupNumberOfEntries": 2,
                "RoleNumberOfEntries": 0,
                "SupportedShellNumberOfEntries": 1,
                "User": [
                        {
                                "Alias": "cpe-1",
                                "Enable": true,
                                "UserID": 0,
                                "Username": "root",
                                "Password": "",
                                "RemoteAccessCapable": false,
                                "GroupParticipation": "Device.Users.Group.1",
                                "RoleParticipation": "",
                                "StaticUser": true,
                                "Language": "",
                                "Shell": "Device.Users.SupportedShell.1"
                        },
                        {
                                "Alias": "cpe-2",
                                "Enable": true,
                                "UserID": 1,
                                "Username": "daemon",
                                "Password": "",
                                "RemoteAccessCapable": false,
                                "GroupParticipation": "Device.Users.Group.2",
                                "RoleParticipation": "",
                                "StaticUser": true,
                                "Language": "",
                                "Shell": ""
                        },
                        {
                                "Alias": "cpe-3",
                                "Enable": true,
                                "UserID": 55,
                                "Username": "ftp",
                                "Password": "",
                                "RemoteAccessCapable": false,
                                "GroupParticipation": "Device.Users.Group.8",
                                "RoleParticipation": "",
                                "StaticUser": true,
                                "Language": "",
                                "Shell": ""
                        }
                ],
                "Group": [
                        {
                                "Alias": "cpe-1",
                                "Enable": true,
                                "GroupID": 0,
                                "Groupname": "root",
                                "RoleParticipation": "",
                                "StaticGroup": true
                        },
                        {
                                "Alias": "cpe-2",
                                "Enable": true,
                                "GroupID": 1,
                                "Groupname": "daemon",
                                "RoleParticipation": "",
                                "StaticGroup": true
                        }
                ],
                "SupportedShell": [
                        {
                                "Alias": "cpe-1",
                                "Enable": true,
                                "Name": "ash"
                        }
                ]
        }
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.Users.", "optional": {"format":"raw"}}'
{
        "results": [
                {
                        "path": "Device.Users.UserNumberOfEntries",
                        "data": "3",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.GroupNumberOfEntries",
                        "data": "2",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.RoleNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.SupportedShellNumberOfEntries",
                        "data": "1",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.User.1.Alias",
                        "data": "cpe-1",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.Enable",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.1.UserID",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.User.1.Username",
                        "data": "root",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.Password",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.RemoteAccessCapable",
                        "data": "0",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.1.GroupParticipation",
                        "data": "Device.Users.Group.1",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.RoleParticipation",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.StaticUser",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.1.Language",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.Shell",
                        "data": "Device.Users.SupportedShell.1",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.Alias",
                        "data": "cpe-2",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.Enable",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.2.UserID",
                        "data": "1",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.User.2.Username",
                        "data": "daemon",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.Password",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.RemoteAccessCapable",
                        "data": "0",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.2.GroupParticipation",
                        "data": "Device.Users.Group.2",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.RoleParticipation",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.StaticUser",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.2.Language",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.2.Shell",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.Alias",
                        "data": "cpe-3",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.Enable",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.3.UserID",
                        "data": "55",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.User.3.Username",
                        "data": "ftp",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.Password",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.RemoteAccessCapable",
                        "data": "0",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.3.GroupParticipation",
                        "data": "Device.Users.Group.8",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.RoleParticipation",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.StaticUser",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.User.3.Language",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.3.Shell",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.1.Alias",
                        "data": "cpe-1",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.1.Enable",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.Group.1.GroupID",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.Group.1.Groupname",
                        "data": "root",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.1.RoleParticipation",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.1.StaticGroup",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.Group.2.Alias",
                        "data": "cpe-2",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.2.Enable",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.Group.2.GroupID",
                        "data": "1",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.Group.2.Groupname",
                        "data": "daemon",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.2.RoleParticipation",
                        "data": "",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.Group.2.StaticGroup",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.Group.18.StaticGroup",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.SupportedShell.1.Alias",
                        "data": "cpe-1",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.SupportedShell.1.Enable",
                        "data": "1",
                        "type": "xsd:boolean"
                },
                {
                        "path": "Device.Users.SupportedShell.1.Name",
                        "data": "ash",
                        "type": "xsd:string"
                }
        ]
}

```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#get)

### Get multiple values
API to get values of multiple objects at once, object name must be provided in `paths` parameter array as below.

> Note: This method is only available in `usp.raw` namespace.

```console
root@iopsys:~# ubus call bbfdm get '{"paths":["Device.Users.User.1.Username","Device.DeviceInfo.SerialNumber"], "optional": {"format":"raw"}}'
{
        "results": [
                {
                        "path": "Device.Users.User.1.Username",
                        "data": "root",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.DeviceInfo.SerialNumber",
                        "data": "Y0721140086",
                        "type": "xsd:string"
                }
        ]
}
```

### Set
API to set value to specific object, object name must be provided in `path` parameter and value to be set in `value` option.

> Note: bbfdmd decides how to handle set method based on the `transaction_id` value. If the `transaction_id` value is different to `0`, it checks if the transaction is valid, then proceeds set operation. Otherwise, it creates a internal transaction before actually setting the value and after set operation it automatically commits the transaction. Please refer to `transaction` API for more details.

```console
root@iopsys:~# ubus call bbfdm set '{"path":"Device.WiFi.SSID.1.SSID", "value":"test-2g"}'
{
        "results": [
                {
                        "path": "Device.WiFi.SSID.1.SSID",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm set '{"path":"Device.WiFi.SSID.1.SSID", "value":"test-2g", "optional":{"transaction_id":12345}}'
{
        "results": [
                {
                        "path": "Device.WiFi.SSID.1.SSID",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm get '{"path":"Device.WiFi.SSID.1.SSID"}'
{
        "SSID": "test-2g"
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#set)

### Operate
API to run operate/diagnostics commands as defined in TR-369

```console
root@iopsys:~# ubus call bbfdm operate '{"command":"Device.IP.Diagnostics.IPPing()", "command_key":"ipping_test", "input":{"Host":"iopsys.eu"}}'
{
        "results": [
                {
                        "path": "Device.IP.Diagnostics.IPPing()",
                        "data": "ipping_test",
                        "output": [
                                {
                                        "Status": "Complete",
                                        "IPAddressUsed": "10.100.1.122",
                                        "SuccessCount": 3,
                                        "FailureCount": 0,
                                        "AverageResponseTime": 31,
                                        "MinimumResponseTime": 30,
                                        "MaximumResponseTime": 31,
                                        "AverageResponseTimeDetailed": 31007,
                                        "MinimumResponseTimeDetailed": 30957,
                                        "MaximumResponseTimeDetailed": 31059
                                }
                        ]
                }
        ]
}
root@iopsys:~# ubus call bbfdm operate '{"command":"Device.IP.Diagnostics.IPPing()", "command_key":"ipping_test", "input":{"Host":"iopsys.eu"}, "optional":{"format":"raw"}}'
{
        "results": [
                {
                        "path": "Device.IP.Diagnostics.IPPing()",
                        "data": "ipping_test",
                        "output": [
                                {
                                        "path": "Status",
                                        "data": "Complete",
                                        "type": "xsd:string"
                                },
                                {
                                        "path": "IPAddressUsed",
                                        "data": "10.100.1.122",
                                        "type": "xsd:string"
                                },
                                {
                                        "path": "SuccessCount",
                                        "data": "3",
                                        "type": "xsd:unsignedInt"
                                },
                                {
                                        "path": "FailureCount",
                                        "data": "0",
                                        "type": "xsd:unsignedInt"
                                }
                        ]
                }
        ]
}
root@iopsys:~# ubus call bbfdm operate '{"command":"Device.IP.Interface.2.Reset()"}'
{
        "results": [
                {
                        "path": "Device.IP.Interface.2.Reset()",
                        "data": "",
                        "output": [
                                {
                                        
                                }
                        ]
                }
        ]
}
root@iopsys:~# ubus call bbfdm operate '{"command":"Device.IP.Interface.2.Reset()", "optional":{"format":"raw"}}'
{
        "results": [
                {
                        "path": "Device.IP.Interface.2.Reset()",
                        "data": "",
                        "output": [
                                
                        ]
                }
        ]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#operate)


### Add object
API to add new objects in multi-instance object

> Note 1: In usp namespace, `add_object` method creates a internal transaction before actually setting the value. After set operation it automatically commits the transaction.
> Note 2: In usp.raw namespace, `add_object` method requires a transaction to be created before calling the set method. Please refer to transaction APIs for more details.

```console
root@iopsys:~# ubus call usp add_object '{"path":"Device.Users.User."}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.",
                        "status": true,
                        "instance": "4"
                }
        ]
}
root@iopsys:~# ubus call usp.raw add_object '{"path":"Device.Users.User.", "transaction_id":12345}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.",
                        "status": true,
                        "instance": "5"
                }
        ]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/usp.md#add)

### Delete object
API to delete an existing object from multi-instance object

> Note 1: In usp namespace, `del_object` method creates a internal transaction before actually setting the value. After set operation it automatically commits the transaction.
> Note 2: In usp.raw namespace, `del_object` method requires a transaction to be created before calling the set method. Please refer to transaction APIs for more details.

```console
root@iopsys:/tmp# ubus call usp del_object '{"path":"Device.Users.User.4"}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.4.",
                        "status": true
                }
        ]
}
root@iopsys:/tmp# ubus call usp.raw del_object '{"path":"Device.Users.User.3", "transaction_id": 12345}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.3.",
                        "status": true
                }
        ]
}
```

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md#del_object)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md#del_object)

### Object names
API to get the available list of object names.

```console
root@iopsys:~# ubus call usp object_names '{"path":"Device.DeviceInfo.SerialNumber"}'
{
        "parameters": [
                {
                        "parameter": "Device.DeviceInfo.SerialNumber",
                        "writable": "0",
                        "type": "xsd:string"
                }
        ]
}
root@iopsys:~#
root@iopsys:~# ubus call usp.raw object_names '{"path":"Device.Users.User.1."}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.1.",
                        "writable": "1",
                        "type": "xsd:object"
                },
                {
                        "parameter": "Device.Users.User.1.Alias",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.Enable",
                        "writable": "1",
                        "type": "xsd:boolean"
                },
                {
                        "parameter": "Device.Users.User.1.Language",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.Password",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.RemoteAccessCapable",
                        "writable": "1",
                        "type": "xsd:boolean"
                },
                {
                        "parameter": "Device.Users.User.1.Username",
                        "writable": "1",
                        "type": "xsd:string"
                }
        ]
}
root@iopsys:~#
```

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md)

### Instances
API to get the available instances of an multi-instance object. USP Instances method returns the registered instances.

```console
root@iopsys:~# ubus call usp instances '{"path":"Device.IP.Interface.", "proto":"usp"}'
{
        "parameters": [
                {
                        "parameter": "Device.IP.Interface.1."
                },
                {
                        "parameter": "Device.IP.Interface.1.IPv4Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.2."
                },
                {
                        "parameter": "Device.IP.Interface.3."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv4Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv6Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv6Prefix.1."
                }
        ]
}
```

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md#instances)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md#instances)

### Validate
API to validate a object in data-model. This api shall simply return the object name
if present in data-model objects or generates a fault if object not available in
data-model.

```console
root@iopsys:~# ubus call usp validate '{"path":"Device.DeviceInfo."}'
{
        "parameter": "Device.DeviceInfo"
}
root@iopsys:~# ubus call usp.raw validate '{"path":"invalid.object"}'
{
        "fault": 9005
}
```

### List Operate
API to list all available operate commands with supported input and output parameters


```console
root@iopsys:~# ubus call usp list_operate
{
        "parameters": [
                {
                        "parameter": "Device.DHCPv4.Client.{i}.Renew()",
                        "type": "sync"
                },
                {
                        "parameter": "Device.DNS.Diagnostics.NSLookupDiagnostics()",
                        "type": "async",
                        "in": [
                                "HostName",
                                "Interface",
                                "DNSServer",
                                "Timeout",
                                "NumberOfRepetitions"
                        ],
                        "out": [
                                "Status",
                                "AnswerType",
                                "HostNameReturned",
                                "IPAddresses",
                                "DNSServerIP",
                                "ResponseTime"
                        ]
                },
                {
                        "parameter": "Device.DeviceInfo.FirmwareImage.{i}.Activate()",
                        "type": "async"
                },
                {
                        "parameter": "Device.IP.Diagnostics.IPPing()",
                        "type": "async",
                        "in": [
                                "Interface",
                                "ProtocolVersion",
                                "Host",
                                "NumberOfRepetitions",
                                "Timeout",
                                "DataBlockSize",
                                "DSCP"
                        ],
                        "out": [
                                "Status",
                                "IPAddressUsed",
                                "SuccessCount",
                                "FailureCount",
                                "AverageResponseTime",
                                "MinimumResponseTime",
                                "MaximumResponseTime",
                                "AverageResponseTimeDetailed",
                                "MinimumResponseTimeDetailed",
                                "MaximumResponseTimeDetailed"
                        ]
                },
                {
```

### Dump schema
API to dump all registered schema paths,

```console
root@iopsys:~# ubus call usp dump_schema
{
        "parameters": [
                {
                        "parameter": "Device.ATM.Link.{i}.",
                        "writable": "1",
                        "type": "xsd:object"
                },
                {
                        "parameter": "Device.ATM.Link.{i}.Alias",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.ATM.Link.{i}.DestinationAddress",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.ATM.Link.{i}.Enable",
                        "writable": "1",
                        "type": "xsd:boolean"
                },
                {
```

### Set multiple values
API to set value of multiple parameters at once.

> Note: This method only available in usp.raw namespace

```console
root@iopsys:~# ubus call usp.raw setm_values '{"pv_tuple":[{"path":"Device.Users.User.2.Username", "value":"xzzz"}, {"path":"Device.Users.User.2.RemoteAccessCapable", "value":"true"}, {"path":"Device.Users.User.2.Password", "value":"zzzzzzz"}], "proto":"usp", "transaction_id":1249743667}'
{
        "status": true
}
root@iopsys:~#
root@iopsys:~#
root@iopsys:~# ubus call usp.raw setm_values '{"pv_tuple":[{"path":"Device.Users.User.2.Username", "value":"xzzz"}, {"path":"Device.Users.User.2.RemoteAccessCapable", "value":"dummy"}, {"path":"Device.Users.User.2.Password", "value":"zzzzzzz"}], "proto":"usp", "transaction_id":738335779}'
{
        "parameters": [
                {
                        "path": "Device.Users.User.2.RemoteAccessCapable",
                        "status": false,
                        "fault": 7012
                }
        ]
}
```

### Transaction start
To support the `allow_partial` and `required` parameters in Add/Del/Set operation as defined in TR-369, transaction_* APIs introduced.
It basically works around data-model objects which has dependent uci config files for each CUD operation.
API to start a transaction in usp.raw namespace for add/del/set operations in usp.raw namespace

> Note: This API only available in usp.raw namespace

```console
root@iopsys:~# ubus call usp.raw transaction_start '{"app":"test"}'
{
        "status": true,
        "transaction_id": 955001092
}
```

It's sometime required to have a per transaction timeout, which can be defined along with transaction_start
```bash
root@4949e4da3d27:~# ubus call usp.raw transaction_start '{"app":"test", "max_timeout":5000}'
{
        "status": true,
        "transaction_id": 491944812
}
```
> Note: max_timeout is time in milliseconds, its an optional input argument if not provided, uci default (uspd.usp.transaction_timeout) is used which is defined in seconds
> If uci option uspd.usp.transaction_timeout not set than a default 10 second timeout is used for the transactions.

### Get status of a transaction
API to get details and check status of a transaction id in usp.raw namespace

```console
root@iopsys:~# ubus call usp.raw transaction_status '{"transaction_id":955001092}'
{
        "app": "test",
        "status": "on-going",
        "remaining_time": 634
}
root@iopsys:~#
root@iopsys:~# ubus call usp.raw transaction_status '{"transaction_id":869066287}'
{
        "status": "not-exists"
}
root@iopsys:~#
```

### Transaction commit
API to commit an on-going transaction, on calling this api, uci changes shall
be committed and required services shall be restarted.

```console
root@iopsys:~# ubus call usp.raw transaction_commit '{"transaction_id":955001092}'
{
        "status": true
}
root@iopsys:~#
```

### Transaction abort
API to abort an on-going transaction, on calling this api, staged changes in
uci shall be reverted to earlier values.

```console
root@iopsys:~# ubus call usp.raw transaction_abort '{"transaction_id":955001092}'
{
        "status": true
}
root@iopsys:~#
```
