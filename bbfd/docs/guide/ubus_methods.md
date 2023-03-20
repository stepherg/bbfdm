# UBUS Methods

`uspd` needs to be started on startup after `ubusd`, as it exposes the data-model
objects over `ubus`. By default(when granularity is not set in `uci`), `uspd` registers
below two namespaces with `ubus`.

```console
root@iopsys:~# ubus list |grep usp
usp
usp.raw
```

`usp` namespace is to provide the output as required by `End User` or in pretty format,
whereas `usp.raw` namespace is to provide output in raw JSON format for easy API integration,
which can be used by other USP front-end applications(like: `obuspa`, `icwmp`).
`usp` namespace has fewer methods defined to provide a simple interface to `end users`,
whereas `usp.raw` has more features/methods to provide more customization options.

Default namespace with functionalities:

```console
root@iopsys:~# ubus -v list usp
'usp' @78f3eaca
        "list_operate":{}
        "get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer"}
        "operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
        "add_object":{"path":"String","proto":"String","instance_mode":"Integer"}
        "del_object":{"path":"String","proto":"String","instance_mode":"Integer"}
root@iopsys:~#
root@iopsys:~# ubus -v list usp.raw
'usp.raw' @08a13407
	"dump_schema":{}
	"list_operate":{}
	"list_events":{}
	"get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"getm_values":{"paths":"Array","proto":"String","next-level":"Boolean","instance_mode":"Integer"}
	"getm_names":{"paths":"Array","proto":"String","next-level":"Boolean","instance_mode":"Integer"}
	"object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"transaction_start":{"app":"String","max_timeout":"Integer"}
	"set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
	"add_object":{"path":"String","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"del_object":{"path":"String","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"setm_values":{"pv_tuple":"Array","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"transaction_commit":{"transaction_id":"Integer"}
	"transaction_abort":{"transaction_id":"Integer"}
	"transaction_status":{"transaction_id":"Integer"}
	"notify_event":{"name":"String","input":"Table"}
root@iopsys:~#
```

> Note1: `proto` in each method specify the data-model prototype('cwmp', 'usp') to use, if not provided default data-model will be used.

> Note2: `instance_mode` could be 0 or 1, for instance number, instance alias respectively.

> Note3: `next-level` true means only get next level objects and false means get all objects recursively

> Note4: `maxdepth` is measured on max number of .(Dot) present in object name

> Note5: `key` is used specifically for cwmp param_key

The objects registered with the above namespaces can be called with appropriate
parameters to perform a USP `Get/Set/Operate/Add Object/Delete Object` operation as below.

## Granularity

Granularity feature is basically exposes the same USP functionality by registering
additional ubus namespaces to reduce the `path` length in ubus parameter.
It is the number of levels(Dots) up to which we want to shorten the length.

Ex:
 - When Granularity is set to 1, exposed ubus namespaces are

```console
root@iopsys:~# ubus list|grep usp
usp
usp.Device.
usp.raw
```

 - When Granularity is set to 2, exposed ubus namespaces are

```console
root@iopsys:~# ubus list|grep usp
usp
usp.Device.
usp.Device.Bridging.
usp.Device.DHCPv4.
usp.Device.DHCPv6.
usp.Device.DNS.
usp.Device.DeviceInfo.
usp.Device.DynamicDNS.
usp.Device.Ethernet.
usp.Device.Firewall.
usp.Device.Hosts.
usp.Device.IP.
usp.raw
root@iopsys:~#
```

These granular ubus objects provides the same functionality as of `usp` ubus namespace

```console
root@iopsys:~# ubus -v list usp.Device.WiFi.
'usp.Device.WiFi.' @6fd43aca
        "list_operate":{}
        "get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
        "set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer"}
        "operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
        "add_object":{"path":"String","proto":"String","instance_mode":"Integer"}
        "del_object":{"path":"String","proto":"String","instance_mode":"Integer"}
root@iopsys:~#
```

Registered method can be called with appropriate parameters, like:

```console
root@iopsys:~# ubus call usp.Device. get '{"path":"Users."}'
{
        "Users": {
                "User": [
                        {
                                "Alias": "cpe-1",
                                "Enable": true,
                                "Language": "",
                                "Password": "",
                                "RemoteAccessCapable": true,
                                "Username": "user"
                        },
                        {
                                "Alias": "cpe-2",
                                "Enable": true,
                                "Language": "",
                                "Password": "",
                                "RemoteAccessCapable": true,
                                "Username": "support"
                        },
                        {
                                "Alias": "cpe-3",
                                "Enable": true,
                                "Language": "",
                                "Password": "",
                                "RemoteAccessCapable": true,
                                "Username": "admin"
                        }
                ],
                "UserNumberOfEntries": 3
        }
}
root@iopsys:~#
```

## Overview

`uspd` provides below commands in pretty(usp) or raw(usp.raw) formats, some methods only available for API integration in usp.raw namespace:

   - Get
   - Get multiple values
   - Get multiple names
   - Set
   - Operate
   - Add object
   - Delete object
   - Object names
   - Instances
   - Validate
   - List operate
   - Dump schema
   - Set multiple values
   - Transaction start
   - Transaction status
   - Transaction commit
   - Transaction abort
   - List supported usp events
   - Send notification for an event

It also provide a granularity layer which can be configured using uci parameter and provide additional ubus objects.

### Get
API to query the value of a specific object.

```console
root@iopsys:~# ubus call usp get '{"path":"Device.IP.Diagnostics.", "proto":"usp"}'
{
        "Diagnostics": {
                "IPv4DownloadDiagnosticsSupported": true,
                "IPv4PingSupported": true,
                "IPv4ServerSelectionDiagnosticsSupported": true,
                "IPv4TraceRouteSupported": true,
                "IPv4UDPEchoDiagnosticsSupported": true,
                "IPv4UploadDiagnosticsSupported": true,
                "IPv6DownloadDiagnosticsSupported": true,
                "IPv6PingSupported": true,
                "IPv6ServerSelectionDiagnosticsSupported": true,
                "IPv6TraceRouteSupported": true,
                "IPv6UDPEchoDiagnosticsSupported": true,
                "IPv6UploadDiagnosticsSupported": true
        }
}
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.IP.Diagnostics.", "proto":"cwmp"}'
{
        "Diagnostics": {
                "DownloadDiagnostics": {
                        "BOMTime": "0",
                        "DSCP": 0,
                        "DiagnosticsState": "None",
                        "DownloadDiagnosticMaxConnections": 1,
                        "TotalBytesSent": 0,
                        "TotalBytesSentUnderFullLoading": 0
                },
                "IPPing": {
                        "AverageResponseTime": 0,
                        "AverageResponseTimeDetailed": 0,
                        "DSCP": 0,
                        "DataBlockSize": 64,
                        "ProtocolVersion": "Any",
                        "SuccessCount": 0,
                        "Timeout": 1000
                },
                "IPv4DownloadDiagnosticsSupported": true,
                "IPv4PingSupported": true,
                "IPv4ServerSelectionDiagnosticsSupported": true,
                "IPv6UDPEchoDiagnosticsSupported": true,
                "IPv6UploadDiagnosticsSupported": true,
                }
        }
}
root@iopsys:~#
root@iopsys:~# ubus call usp get '{"path":"Device.Users."}'
{
        "Users": {
                "User": [
                        {
                                "Alias": "cpe-1",
                                "Enable": true,
                                "Language": "",
                                "Password": "",
                                "RemoteAccessCapable": true,
                                "Username": "user"
                        },
                        {
                                "Alias": "cpe-2",
                                "Enable": true,
                                "Language": "",
                                "Password": "",
                                "RemoteAccessCapable": true,
                                "Username": "support"
                        },
                        {
                                "Alias": "cpe-3",
                                "Enable": true,
                                "Language": "",
                                "Password": "",
                                "RemoteAccessCapable": true,
                                "Username": "admin"
                        }
                ],
                "UserNumberOfEntries": 3
        }
}
root@iopsys:~#
root@iopsys:~# ubus call usp.raw get '{"path":"Device.Users."}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.1.Alias",
                        "value": "cpe-1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.Enable",
                        "value": "1",
                        "type": "xsd:boolean"
                },
                {
                        "parameter": "Device.Users.User.1.Language",
                        "value": "",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.Password",
                        "value": "",
                        "type": "xsd:string"
                }
        ]
}

```

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md#get)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md#get)

### Get multiple values
API to get values of multiple objects at once, object name must be provided in `paths` parameter array as below.

> Note: This method is only available in `usp.raw` namespace.

```console
root@iopsys:~# ubus call usp.raw getm_values '{"paths":["Device.Users.User.1.Username","Device.DeviceInfo.SerialNumber"]}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.1.Username",
                        "value": "user",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.DeviceInfo.SerialNumber",
                        "value": "E40A24H185027824",
                        "type": "xsd:string"
                }
        ]
}
```

### Get multiple objects
API to get multiple objects from multiple paths at once.

> Note: This method only available in `usp.raw` namespace

```console
root@iopsys:~# ubus call usp.raw getm_names '{"paths":["Device.Users.User.1.","Device.DeviceInfo.SerialNumber"]}'
{
        "parameters": [
                {
                        "parameter": "Device.Users.User.1.",
                        "value": "1",
                        "type": "xsd:object"
                },
                {
                        "parameter": "Device.Users.User.1.Alias",
                        "value": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.Enable",
                        "value": "1",
                        "type": "xsd:boolean"
                },
                {
                        "parameter": "Device.Users.User.1.Language",
                        "value": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.Password",
                        "value": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.Users.User.1.RemoteAccessCapable",
                        "value": "1",
                        "type": "xsd:boolean"
                },
                {
                        "parameter": "Device.Users.User.1.Username",
                        "value": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.DeviceInfo.SerialNumber",
                        "value": "0",
                        "type": "xsd:string"
                }
        ]
}
root@iopsys:~#
```

### Set
API to set value to specific object, object name must be provided in `path` parameter and value to be set in `value` option.

> Note 1: In usp namespace, set method creates a internal transaction before actually setting the value. After set operation it automatically commits the transaction.

> Note 2: In usp.raw namespace, set method requires a transaction to be created before calling the set method. Please refer to transaction APIs for more details.

```console
root@iopsys:/tmp# ubus call usp set '{"path":"Device.WiFi.SSID.[BSSID==\"00:22:07:ae:ee:03\"].SSID", "value":"test-2g"}'
{
        "status": true
}
root@iopsys:/tmp# ubus call usp.raw set '{"path":"Device.WiFi.SSID.[BSSID==\"00:22:07:ae:ee:03\"].SSID", "value":"test-2g", "transaction_id":12345}'
{
        "status": true
}
root@iopsys:~# ubus call usp get '{"path":"Device.WiFi.SSID.[BSSID==\"00:22:07:ae:ee:03\"].SSID"}'
{
        "SSID": [
                {
                        "SSID": "test-2g"
                }
        ]
}
```

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md#set)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md#set)

### Operate
API to run operate/diagnostics commands as defined in TR-369

```console
root@iopsys:~# ubus call usp operate '{"path":"Device.IP.Diagnostics.", "action":"IPPing()","input":{"Host":"iopsys.eu"}}'
{
        "Results": [
                {
                        "path": "Device.IP.Diagnostics.IPPing",
                        "result": [
                                {
                                        "AverageResponseTime": 0,
                                        "AverageResponseTimeDetailed": 0,
                                        "FailureCount": 3,
                                        "MaximumResponseTime": 0,
                                        "MaximumResponseTimeDetailed": 0,
                                        "MinimumResponseTime": 9999,
                                        "MinimumResponseTimeDetailed": 999999999,
                                        "SuccessCount": 0
                                }
                        ]
                }
        ]
}

root@iopsys:~# ubus call usp.raw operate '{"path":"Device.IP.Diagnostics.", "action":"IPPing()","input":{"Host":"iopsys.eu"}}'
{
        "Results": [
                {
                        "path": "Device.IP.Diagnostics.IPPing",
                        "parameters": [
                                {
                                        "parameter": "AverageResponseTime",
                                        "value": "0",
                                        "type": "xsd:unsignedInt"
                                },
                                {
                                        "parameter": "AverageResponseTimeDetailed",
                                        "value": "0",
                                        "type": "xsd:unsignedInt"
                                },
                                {
                                        "parameter": "FailureCount",
                                        "value": "3",
                                        "type": "xsd:unsignedInt"
                                },
                                {
                }
        ]
}

root@iopsys:~# ubus call usp operate '{"path":"Device.IP.Interface.[Name==\"wan\"].", "action":"Reset()"}'
{
        "Results": [
                {
                        "path": "Device.IP.Interface.2.Reset",
                        "result": [
                                {

                                }
                        ]
                }
        ]
}

root@iopsys:~# ubus call usp.raw operate '{"path":"Device.IP.Interface.[Name==\"wan\"].", "action":"Reset()"}'
{
        "Results": [
                {
                        "path": "Device.IP.Interface.2.Reset",
                        "parameters": [

                        ]
                }
        ]
}
```

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md#operate)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md#operate)

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

- For more info on the `usp` ubus API see [link](../api/ubus/usp.md#add_object)
- For more info on the `usp.raw` ubus API see [link](../api/ubus/usp.raw.md#add_object)

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

### List supported usp events
API to list down the data-model events for usp notification supported by uspd.

```console
root@iopsys:~# ubus call usp.raw list_events
{
	"parameters": [
		{
			"parameter": "Device.LocalAgent.TransferComplete!",
			"in": [
				"Command",
				"CommandKey",
				"Requestor",
				"TransferType",
				"Affected",
				"TransferURL",
				"StartTime",
				"CompleteTime",
				"FaultCode",
				"FaultString"
			]
		}
	]
}
```

