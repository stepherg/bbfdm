# TR181 IP.Interface. Object

The purpose of this document is to describe what are the problems and limitation we have in managing IP.Interface. with their sub-objects and what is the best way for the customer to avoid these problems/limitations and can easily configure IP.Interface. with different IPv4/v6 addresses using static or dhcp server.

In fact, many TR181 objects are not mapped 1-to-1 with uci config  which makes managing these objects so difficult and one of the important objects is IP.Interface.

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

 - Currently, each IP.Interface instance can be configured with either dhcpv4 or dhcpv6. So there is no way to configure it with both DHCPv4 and DHCPv6 server at the same time as shown below.

 ```
config interface 'wan'
	option device 'ethx'
	option proto 'dhcp'

config interface 'wan6'
	option device 'ethx'
	option proto 'dhcpv6'

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

 - There is no way to handle config interface section which is created by luci or cli commands as below:

```
config interface 'wan'
	option disabled '0'
	option device 'ethx'
	option proto 'static'
	list ipaddr '10.100.17.39'
	list ipaddr '10.100.18.39'
	list ipaddr '10.100.19.39'
	option netmask '255.255.255.0'

```

# Limitations:

1. If the network uci defines IPv4 address with the primary config interface secion, then its only allowed to have one IPv4 address with the mapped IP.Interface. instance, any addition of IPv4Address in the same section will result into a fault <9001>. 

2. If the network uci defines IPv6 address with the primary config interface secion, then its only allowed to have one IPv6 address with the mapped IP.Interface. instance, any addition of IPv6Address in the same section will result into a fault <9001>

3. If Data Model shows IP.Interface.{i}.IPv4Address.{i}. instance with DHCP type, then its not allowed to disable this IP.Interface.{i}.IPv4Address.{i}. instance.

4. If Data Model shows IP.Interface.{i}.IPv6Address.{i}. instance with DHCP type, then its not allowed to disable this IP.Interface.{i}.IPv6Address.{i}. instance.


# Solutions:

1. If someone wants to configure IP.Interface. instance with different IPv4/6 addresses, it should **remove** the default IP.Interface. instance and trying to define their IP.Interface. instance with needed IPv4Address or IPv6Address instances.

> Note1: Before setting LowerLayers of new IP.Interface. instance, please make sure there is no other IP.Interface instance links to the same object that you want to set. Otherwise, the new IP.Interface. instance will be disappered. 

> Note2: We have supported now both alias and device name.

2. Each data model object which maps to uci network interface section should create its network section.

3. We need to have an internal migration mechanism in bbfdm to migrate everything added by other apps to be alligned with new design.

```
config interface 'wan									config interface 'wan'
	option proto 'dhcp'										option proto 'dhcp'
	option device 'ethx'									option device 'ethx'
									==========> 
config interface 'wan6'									config interface 'wan6'
	option proto 'dhcpv6'									option proto 'dhcpv6'
	option device 'ethx'									option device 'ethx'

														config interface 'ip_iface_x'
															option proto 'none'
															option device 'ethx'

```

# Explaination with uci network config:

### Adding an IP.Interface. instance

```
config interface 'iface_x'         ---> Device.IP.Interface.X.Name
	option proto 'none'
	option disabled '1'            ---> Device.IP.Interface.X.Enable
	option device 'iface_x'        ---> Device.IP.Interface.X.LowerLayers
	option ula ''                  ---> Device.IP.Interface.X.ULAEnable
	option mtu ''                  ---> Device.IP.Interface.X.MaxMTUSize

```

### Adding a static IP.Interface.X.IPv4Address. instance

```
config interface 'iface_x_ipv4_x'
	option proto 'static'          ---> Device.IP.Interface.X.IPv4Address.X.AddressingType
	option disabled '1'            ---> Device.IP.Interface.X.IPv4Address.X.Enable
	option device '@iface_x'
	option ipaddr ''               ---> Device.IP.Interface.X.IPv4Address.X.IPAddress
	option netmask ''              ---> Device.IP.Interface.X.IPv4Address.X.SubnetMask

```

### Adding a static IP.Interface.X.IPv6Address. instance

```
config interface 'iface_x_ipv6_x'
	option proto 'static'          ---> Device.IP.Interface.X.IPv6Address.X.Origin
	option disabled '1'            ---> Device.IP.Interface.X.IPv6Address.X.Enable
	option device '@iface_x'
	option ipaddr ''               ---> Device.IP.Interface.X.IPv6Address.X.IPAddress

```

### Adding a DHCPv4.Client. instance

```
config interface 'dhcpv4_x'
	option proto 'dhcp'
	option disabled '1'            ---> Device.DHCPv4.Client.X.Enable
	option device ''               ---> Device.DHCPv4.Client.X.Interface

```

### Adding a DHCPv6.Client. instance

```
config interface 'dhcpv6_x'
	option proto 'dhcpv6'
	option disabled '1'            ---> Device.DHCPv6.Client.X.Enable
	option device ''               ---> Device.DHCPv6.Client.X.Interface

```

### Adding a PPP.Interface. instance

```
config interface 'ppp_x'           ---> Device.PPP.Interface.X.Name
	option proto 'ppp'
	option disabled '1'            ---> Device.PPP.Interface.X.Enable
	option device ''               ---> Device.PPP.Interface.X.LowerLayers

```
