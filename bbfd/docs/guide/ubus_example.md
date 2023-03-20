# UBUS examples

```console

root@iopsys:~# ubus call usp get '{"path":"Device.WiFi.SSID.*.SSID"}'
{
        "SSID": [
                {
                        "SSID": "NORRLAND-34E380760120"
                },
                {
                        "SSID": "NORRLAND-34E380760120"
                }
        ]
}

root@iopsys:~# ubus call usp get '{"path":"Device.WiFi.SSID.*.BSSID"}'
{
        "SSID": [
                {
                        "BSSID": "34:E3:80:76:01:22"
                },
                {
                        "BSSID": "34:E3:80:76:01:23"
                }
        ]
}

root@iopsys:~# ubus call usp get '{"path":"Device.WiFi.SSID.[BSSID==\"34:E3:80:76:01:22\"].SSID"}'
{
        "SSID": [
                {
                        "SSID": "NORRLAND-34E380760120"
                }
        ]
}

root@iopsys:~# ubus call usp get '{"path":"Device.IP.Interface.[Status==\"Up\"].IPv4Address.[AddressingType==\"DHCP\"].IPAddress"}'
{
        "Interface": [
                {
                        "IPv4Address": [
                                {
                                        "IPAddress": "192.168.0.96"
                                }
                        ]
                }
        ]
}

root@iopsys:~# ubus call usp get '{"path":"Device.IP.Interface.[Status==\"Up\"].IPv4Address.[AddressingType==\"DHCP\"&&Status==\"Up\"]."}'
{
        "Interface": [
                {
                        "IPv4Address": [
                                {
                                        "AddressingType": "DHCP",
                                        "Alias": "cpe-2",
                                        "Enable": true,
                                        "IPAddress": "192.168.0.96",
                                        "Status": "Up",
                                        "SubnetMask": "255.255.255.0",
                                        "X_IOPSYS_EU_FirewallEnabled": true
                                }
                        ]
                }
        ]
}

root@iopsys:~# ubus call usp get '{"path":"Device.IP.Interface.[Type==\"Normal\"&&Stats.PacketsSent<=500].IPv4Address.[AddressingType==\"Static\"].IPAddress"}'
{
        "Interface": [
                {
                        "IPv4Address": [
                                {
                                        "IPAddress": "192.168.1.1"
                                }
                        ]
                }
        ]
}

root@iopsys:~# ubus call usp get '{"path":"Device.WiFi.AccessPoint.[SSIDReference+.SSID==\"NORRLAND-34E380760120\"].AssociatedDevice.[Noise>15].SignalStrength"}
'
{
        "AccessPoint": [
                {
                        "AssociatedDevice": [
                                {
                                        "SignalStrength": -31
                                }
                        ]
                }
        ]
}


root@iopsys:~# ubus call usp get '{"path":"Device.WiFi.SSID.*.LowerLayers#1+.Name"}'
{
        {
                "Name": "wlan0",
                "Name": "wlan2"
        }
}



root@iopsys:~# ubus call usp get '{"path":"Device.Users.User.*.Username"}'
{
        "User": [
                {
                        "Username": "user"
                },
                {
                        "Username": "support"
                },
                {
                        "Username": "admin"
                }
        ]
}

root@iopsys:~# ubus call usp.raw set '{"path":"Device.IP.Diagnostics.IPPing.DiagnosticsState", "value":"Requested", "proto":"cwmp"}'
{
        "parameters": [
                {
                        "path": "Device.IP.Diagnostics.IPPing.DiagnosticsState",
                        "status": true,
                }
        ]
}

root@iopsys:~# ubus call usp.raw set '{"path":"Device.Users.User.2.Username", "value":"abc", "proto":"cwmp"}'
{
        "parameters": [
                {
                        "path": "Device.Users.User.2.Username",
                        "status": true,
                }
        ]
}

root@iopsys:~# ubus call usp.raw set '{"path":"Device.Users.User.2.Username", "value":"abc", "proto":"usp"}'
{
        "parameters": [
                {
                        "path": "Device.Users.User.2.Username",
                        "status": true
                }
        ]
}

root@iopsys:~# ubus call usp.raw set '{"path":"Device.Users.User.2.Username", "value":"abc"}'
{
        "parameters": [
                {
                        "path": "Device.Users.User.2.Username",
                        "status": true
                }
        ]
}

root@iopsys:~#
root@iopsys:~# ubus call usp set '{"path":"Device.Users.User.[Username==\"xyz1\"].", "values":{"Username":"xyz1", "Enable":"dummy", "Password":"yzssssx"}, "proto":"usp"}'
{
        "parameters": [
                {
                        "path": "Device.Users.User.2.Username",
                        "status": true
                },
                {
                        "path": "Device.Users.User.2.Enable",
                        "status": false,
                        "fault": 7012
                },
                {
                        "path": "Device.Users.User.2.Password",
                        "status": true
                }
        ]
}
root@iopsys:~#
root@iopsys:~# ubus call usp.raw setm_values '{"pv_tuple":[{"path":"Device.Users.User.2.Username", "value":"xzzz"}, {"path":"Device.Users.User.2.RemoteAccessCapable", "value":"1"}, {"path":"Device.Users.User.2.Password", "value":"zzzzzzz"}], "proto":"usp"}'
{
        "parameters": [
                {
                        "path": "Device.Users.User.2.Username",
                        "status": true
                },
                {
                        "path": "Device.Users.User.2.RemoteAccessCapable",
                        "status": false,
                        "fault": 7012
                },
                {
                        "path": "Device.Users.User.2.Password",
                        "status": true
                }
        ]
}
```

- For more info on the usp ubus API see [link](../api/ubus/usp.md)
- For more info on the usp.raw ubus API see [link](../api/ubus/usp.raw.md)

