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
   - Object names
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
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.WiFi.SSID.*.SSID"}'
{
	"SSID": [
		{
			"SSID": "iopsysWrt-44D43771B120"
		},
		{
			"SSID": "MAP-44D43771B120-BH-5GHz"
		},
		{
			"SSID": "iopsysWrt-44D43771B120"
		},
		{
			"SSID": "MAP-44D43771B120-BH-2.4GHz"
		}
	]
}
root@iopsys:~# 
root@iopsys:~# ubus call bbfdm get '{"path":"Device.WiFi.SSID.*.SSID", "optional":{"format":"raw"}}'
{
	"results": [
		{
			"path": "Device.WiFi.SSID.1.SSID",
			"data": "iopsysWrt-44D43771B120",
			"type": "xsd:string"
		},
		{
			"path": "Device.WiFi.SSID.2.SSID",
			"data": "MAP-44D43771B120-BH-5GHz",
			"type": "xsd:string"
		},
		{
			"path": "Device.WiFi.SSID.3.SSID",
			"data": "iopsysWrt-44D43771B120",
			"type": "xsd:string"
		},
		{
			"path": "Device.WiFi.SSID.4.SSID",
			"data": "MAP-44D43771B120-BH-2.4GHz",
			"type": "xsd:string"
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.WiFi.SSID.[BSSID==\"be:d4:37:71:b1:28\"].SSID"}'
{
	"SSID": [
		{
			"SSID": "MAP-44D43771B120-BH-5GHz"
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.IP.Interface.[Status==\"Up\"].IPv4Address.[AddressingType==\"DHCP\"].IPAddress"}'
{
	"Interface": [
		{
			"IPv4Address": [
				{
					"IPAddress": "10.100.1.201"
				}
			]
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.IP.Interface.[Status==\"Up\"].IPv4Address.[AddressingType==\"DHCP\"&&Status==\"Up\"]."}'
{
	"Interface": [
		{
			"IPv4Address": [
				{
					"Enable": true,
					"Status": "Enabled",
					"Alias": "cpe-1",
					"IPAddress": "10.100.1.201",
					"SubnetMask": "255.255.255.0",
					"AddressingType": "DHCP"
				}
			]
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path":"Device.IP.Interface.[Type==\"Normal\"&&Stats.PacketsSent<=500].IPv4Address.[AddressingType==\"DHCP\"].IPAddress"}'
{
	"Interface": [
		{
			"IPv4Address": [
				{
					"IPAddress": "10.100.1.201"
				}
			]
		}
	]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm get '{"path": "Device.Firewall.Chain.1.Rule.[Description==\"Allow-Ping\"]."}'
{
	"Rule": [
		{
			"Enable": true,
			"Status": "Enabled",
			"Order": 3,
			"Alias": "cpe-3",
			"Description": "Allow-Ping",
			"Target": "Accept",
			"Log": false,
			"CreationDate": "0001-01-01T00:00:00Z",
			"ExpiryDate": "9999-12-31T23:59:59Z",
			"SourceInterface": "Device.IP.Interface.2",
			"SourceAllInterfaces": false,
			"DestInterface": "",
			"DestAllInterfaces": false,
			"IPVersion": 4,
			"DestIP": "",
			"DestMask": "",
			"SourceIP": "",
			"SourceMask": "",
			"Protocol": 1,
			"DestPort": -1,
			"DestPortRangeMax": -1,
			"SourcePort": -1,
			"SourcePortRangeMax": -1
		}
	]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#get)

### Get multiple values
API to get values of multiple objects at once, object name must be provided in `paths` parameter array as below.

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

### Set single value
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

### Set multiple values
API to set value to specific object, object name must be provided in `path` object and parameter and its value to be set in `obj_path` table.

> Note: bbfdmd decides how to handle set method based on the `transaction_id` value. If the `transaction_id` value is different to `0`, it checks if the transaction is valid, then proceeds set operation. Otherwise, it creates a internal transaction before actually setting the value and after set operation it automatically commits the transaction. Please refer to `transaction` API for more details.

```console
root@iopsys:~# ubus call bbfdm set '{"path":"Device.WiFi.SSID.1.", "obj_path":{"Enable":"0", "SSID":"test-2g"}}'
{
        "results": [
                {
                        "path": "Device.WiFi.SSID.1.Enable",
                        "data": "1"
                },
                {
                        "path": "Device.WiFi.SSID.1.SSID",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm set '{"path":"Device.WiFi.SSID.1.", "obj_path":{"Enable":"0", "SSID":"test-2g"}, "optional":{"transaction_id":12345}}'
{
        "results": [
                {
                        "path": "Device.WiFi.SSID.1.Enable",
                        "data": "1"
                },
                {
                        "path": "Device.WiFi.SSID.1.SSID",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm get '{"paths":["Device.WiFi.SSID.1.Enable", "Device.WiFi.SSID.1.SSID"]}'
{
        "Enable": false,
        "SSID": "test-2g"
}
root@iopsys:~# ubus call bbfdm set '{"path": "Device.Firewall.Chain.1.Rule.[Description==\"Allow-Ping\"].", "obj_path": {"Target": "Accept"}}'
{
	"results": [
		{
			"path": "Device.Firewall.Chain.1.Rule.3.Target",
			"data": "1"
		}
	]
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

> Note: bbfdmd decides how to handle `add_object` method based on the `transaction_id` value. If the `transaction_id` value is different to `0`, it checks if the transaction is valid, then proceeds set operation. Otherwise, it creates a internal transaction before actually adding the object and after set operation it automatically commits the transaction. Please refer to `transaction` API for more details.

```console
root@iopsys:~# ubus call bbfdm add '{"path":"Device.Users.User."}'
{
        "results": [
                {
                        "path": "Device.Users.User.",
                        "data": "14"
                }
        ]
}
root@iopsys:~# ubus call bbfdm add '{"path":"Device.Users.User.", "optional":{"transaction_id":12345}}'
{
        "results": [
                {
                        "path": "Device.Users.User.",
                        "data": "14"
                }
        ]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#add)

### Add object and setting its parameters
API to add new objects in multi-instance object

> Note: bbfdmd decides how to handle `add_object` method based on the `transaction_id` value. If the `transaction_id` value is different to `0`, it checks if the transaction is valid, then proceeds set operation. Otherwise, it creates a internal transaction before actually adding the object and after add operation it automatically commits the transaction. Please refer to `transaction` API for more details.

```console
root@iopsys:~# ubus call bbfdm add '{"path":"Device.Firewall.Chain.1.Rule.", "obj_path":{"Enable":"1", "Description":"rule for test"}}'
{
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.",
                        "data": "12"
                }
        ],
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.Enable",
                        "data": "1"
                },
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.Description",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm add '{"path":"Device.Firewall.Chain.1.Rule.", "obj_path":{"Enable":"1", "Description":"rule for test"}, "optional":{"transaction_id":12345}}'
{
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.",
                        "data": "12"
                }
        ],
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.Enable",
                        "data": "1"
                },
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.Description",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm get '{"paths":["Device.Firewall.Chain.1.Rule.12.Enable", "Device.Firewall.Chain.1.Rule.12.Description"]}'
{
        "Enable": true,
        "Description": "rule for test"
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#add)

### Delete single object
API to delete an existing object from multi-instance object

> Note: bbfdmd decides how to handle `add_object` method based on the `transaction_id` value. If the `transaction_id` value is different to `0`, it checks if the transaction is valid, then proceeds set operation. Otherwise, it creates a internal transaction before actually deleting the object and after del operation it automatically commits the transaction. Please refer to `transaction` API for more details.

```console
root@iopsys:~# ubus call bbfdm del '{"path":"Device.Firewall.Chain.1.Rule.12."}'
{
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm del '{"path":"Device.Firewall.Chain.1.Rule.12.", "optional":{"transaction_id":12345}}'
{
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.",
                        "data": "1"
                }
        ]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#del)

### Delete multiple objects
API to delete an existing object from multi-instance object

> Note: bbfdmd decides how to handle `add_object` method based on the `transaction_id` value. If the `transaction_id` value is different to `0`, it checks if the transaction is valid, then proceeds set operation. Otherwise, it creates a internal transaction before actually deleting the object and after del operation it automatically commits the transaction. Please refer to `transaction` API for more details.

```console
root@iopsys:~# ubus call bbfdm del '{"paths":["Device.Firewall.Chain.1.Rule.10.","Device.Firewall.Chain.1.Rule.11."]}'
{
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.10.",
                        "data": "1"
                },
                {
                        "path": "Device.Firewall.Chain.1.Rule.11.",
                        "data": "1"
                }
        ]
}
root@iopsys:~# ubus call bbfdm del '{"paths":["Device.Firewall.Chain.1.Rule.10.","Device.Firewall.Chain.1.Rule.11."], "optional":{"transaction_id":12345}}'
{
        "results": [
                {
                        "path": "Device.Firewall.Chain.1.Rule.12.",
                        "data": "1"
                }
        ]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#del)


### Object names
API to get the available list of object names which is available only with `cwmp` proto.

```console
root@iopsys:~# ubus call bbfdm schema '{"path":"Device.DeviceInfo.SerialNumber", "optional":{"proto":"cwmp"}}'
{
        "results": [
                {
                        "path": "Device.DeviceInfo.SerialNumber",
                        "data": "0",
                        "type": "xsd:string"
                }
        ]
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm schema '{"path":"Device.Users.", "optional":{"proto":"cwmp"}}'
{
        "results": [
                {
                        "path": "Device.Users.",
                        "data": "0",
                        "type": "xsd:object"
                },
                {
                        "path": "Device.Users.UserNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.GroupNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.RoleNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.SupportedShellNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.Users.User.",
                        "data": "1",
                        "type": "xsd:object"
                },
                {
                        "path": "Device.Users.User.1.",
                        "data": "1",
                        "type": "xsd:object"
                },
                {
                        "path": "Device.Users.User.1.Alias",
                        "data": "1",
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
                        "data": "1",
                        "type": "xsd:string"
                },
                {
                        "path": "Device.Users.User.1.Password",
                        "data": "1",
                        "type": "xsd:string"
                }
        ]
}
root@iopsys:~#
```

### Instances
API to get the available instances of an multi-instance object. USP Instances method returns the registered instances.

```console
root@iopsys:~# ubus call bbfdm instances '{"path":"Device.IP.Interface."}'
{
        "results": [
                {
                        "path": "Device.IP.Interface.1"
                },
                {
                        "path": "Device.IP.Interface.1.IPv4Address.1"
                },
                {
                        "path": "Device.IP.Interface.1.IPv6Address.1"
                },
                {
                        "path": "Device.IP.Interface.1.IPv6Address.2"
                },
                {
                        "path": "Device.IP.Interface.1.IPv6Prefix.1"
                },
                {
                        "path": "Device.IP.Interface.2"
                }
        ]
}
```

- For more info on the `bbfdm` ubus API see [link](../api/ubus/bbfdm.md#instances)

### schema
API to dump all registered schema paths

```console
root@iopsys:~# ubus call bbfdm schema '{"path":"Device.WiFi.", "optional":{"proto":"usp"}}'
{
        "results": [
                {
                        "path": "Device.WiFi.RadioNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.WiFi.SSIDNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.WiFi.AccessPointNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.WiFi.EndPointNumberOfEntries",
                        "data": "0",
                        "type": "xsd:unsignedInt"
                },
                {
                        "path": "Device.WiFi.Reset()",
                        "type": "xsd:command",
                        "data": "sync"
                },
                {
                        "path": "Device.WiFi.NeighboringWiFiDiagnostic()",
                        "type": "xsd:command",
                        "data": "async",
                        "output": [
                                {
                                        "path": "Status"
                                },
                                {
                                        "path": "Result.{i}.Radio"
                                },
                                {
                                        "path": "Result.{i}.SSID"
                                },
                                {
                                        "path": "Result.{i}.BSSID"
                                },
                                {
                                        "path": "Result.{i}.Mode"
                                },
                                {
                                        "path": "Result.{i}.Channel"
                                },
                                {
                                        "path": "Result.{i}.SignalStrength"
                                },
                                {
                                        "path": "Result.{i}.SecurityModeEnabled"
                                },
                                {
                                        "path": "Result.{i}.EncryptionMode"
                                },
                                {
                                        "path": "Result.{i}.OperatingFrequencyBand"
                                },
                                {
                                        "path": "Result.{i}.SupportedStandards"
                                },
                                {
                                        "path": "Result.{i}.OperatingStandards"
                                },
                                {
                                        "path": "Result.{i}.OperatingChannelBandwidth"
                                },
                                {
                                        "path": "Result.{i}.BeaconPeriod"
                                },
                                {
                                        "path": "Result.{i}.Noise"
                                },
                                {
                                        "path": "Result.{i}.BasicDataTransferRates"
                                },
                                {
                                        "path": "Result.{i}.SupportedDataTransferRates"
                                },
                                {
                                        "path": "Result.{i}.DTIMPeriod"
                                }
                        ]
                }
        ]
}
```

### Transaction start
To support the `allow_partial` and `required` parameters in Add/Del/Set operation as defined in TR-369, transaction_* APIs introduced.
It basically works around data-model objects which has dependent uci config files for each CUD operation.
API to start a transaction for add/del/set operations


```console
root@iopsys:~# ubus call bbfdm transaction '{"cmd":"start"}'
{
        "status": true,
        "transaction_id": 1727398631
}
```

It's sometime required to have a per transaction timeout, which can be defined along with transaction_start
```bash
root@4949e4da3d27:~# ubus call bbfdm transaction '{"cmd":"start", "timeout":30}'
{
        "status": true,
        "transaction_id": 2124763996
}

```
> Note: max_timeout is time in second, its an optional input argument if not provided, uci default (bbfdm.bbfdmd.transaction_timeout) is used which is defined in seconds
> If uci option bbfdm.bbfdmd.transaction_timeout not set than a default 10 second timeout is used for the transactions.

### Get status of a transaction
API to get details and check status of a transaction id

```console
root@iopsys:~# ubus call bbfdm transaction '{"cmd":"status", "optional":{"transaction_id":439041413}}'
{
        "status": "on-going",
        "remaining_time": 17
}
root@iopsys:~#
root@iopsys:~# ubus call bbfdm transaction '{"cmd":"status", "optional":{"transaction_id":439041413}}'
{
        "status": "not-exists"
}
root@iopsys:~#
```

### Transaction commit
API to commit an on-going transaction, on calling this api, uci changes shall be committed and required services shall be restarted.

```console
root@iopsys:~# ubus call bbfdm transaction '{"cmd":"commit", "optional":{"transaction_id":439041413}}'
{
        "updated_services": [
                "mapcontroller",
                "wireless"
        ],
        "status": true
}
```

### Transaction abort
API to abort an on-going transaction, on calling this api, staged changes in uci shall be reverted to earlier values.

```console
root@iopsys:~# ubus call bbfdm transaction '{"cmd":"abort", "optional":{"transaction_id":1695754826}}'
{
        "reverted_configs": [
                "mapcontroller",
                "wireless"
        ],
        "status": true
}
```
