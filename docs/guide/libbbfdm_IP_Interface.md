# TR181 IP.Interface. Object

The purpose of this document is to describe what are the problems and limitation we have in managing IP.Interface. with their sub-objects and what is the best way for the customer to avoid these problems/limitations and can easily configure IP.Interface. with different IPv4/v6 addresses using static or dhcp server.

In fact, many TR181 objects are not mapped 1-to-1 with uci config which makes managing these objects so difficult and one of the important objects is IP.Interface.

# Problematics:

Actually, we find a lot of problems with the current implementation of IP.Interface object such as:

 - If IP.Interface instance and IP.Interface.X.IPv4Address instance map to the same interface section, so there is no way to disable IPv4Address instance without affecting IP.Interface since both maps to the same interface section.

```
config interface 'wan'   ---> used by Device.IP.Interface.X. and Device.IP.Interface.X.IPv4Address.X. instances
	option disabled '0'  ---> Disabling this IPv4Address.X. instance using Enable parameter(Device.IP.Interface.X.IPv4Address.X.Enable) will impact on IP.Interface.X. instance
	option device 'ethx'
	option proto 'static'
	option ipaddr '10.100.17.39'
	option netmask '255.255.255.0'

```

 - If someone try to create a static route and bind it to an IP.Interface. instance which has an IPv4Address instance defined there so disabling IPv4Addres will cause IP.Interface instance to be disabled and therefore the static route will be automatically disabled from the system.

```
config interface 'wan'   ---> used by Device.IP.Interface.1. and Device.IP.Interface.1.IPv4Address.1. instances
	option disabled '1'  ---> Disabling this IPv4Address.1. instance using Enable parameter(Device.IP.Interface.1.IPv4Address.1.Enable) will disable IP.Interface.1. and route section even if there are others section use the same device(wan_2)
	option device 'ethx'
	option proto 'dhcp'

config interface 'wan_2' ---> used by Device.IP.Interface.1.IPv4Address.2. instance
	option disabled '0'
	option device 'ethx'
	option proto 'static'
	option ipaddr '10.100.17.39'
	option netmask '255.255.255.0'

config route
    option interface 'wan'
    option target '0.0.0.0/0'
    option gateway '10.72.197.110'
 
```

# Solution:

To fix the above issues, we have updated our IP.Interface.X.IPv4Address implementation to store everything in dmmap, then based on each uci section, we decide how to manage their IP.Interface.X.IPv4Address parameters. but unfortunately, with this approach, the customer has to be aware of some limitations such as:

 - If Data Model shows IP.Interface.{i}.IPv4Address.{i}. instance with DHCP type, then it's not allowed to disable this IP.Interface.{i}.IPv4Address.{i}. instance and the only way to disable it is to set their DHCPv4.Client.X.Interface parameter to empty.

 - If Data Model shows IP.Interface.{i}.IPv6Address.{i}. instance with DHCP type, then it's not allowed to disable this IP.Interface.{i}.IPv6Address.{i}. instance and the only way to disable it is to set their DHCPv6.Client.X.Interface parameter to empty

 - If the network uci defines an interface section which used by both IP.Interface.{i}. instance and DHCPv4.Client.{i}. instance, then it's not allowed to disable this DHCPv4.Client.{i}. instance using Enable parameter and the only way to disable it is to set their IP.Interface.X.Enable parameter to 0. 

>Note: In future we might optimise it further to simplify the mapping between data model objects and uci, that might forgo some limitations.
