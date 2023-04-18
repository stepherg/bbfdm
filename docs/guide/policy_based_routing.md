# PBR (Policy based routing)

Aim of this document to explain policy based routing management using TR181 Routing/QoS datamodel parameter mappings with network and qos uci.

In order to enable source based routing, you must first add a new 'Device.Routing.Router.{i}.' object to redirect routes for specific interface to a separate routing table, then configure the policy by adding new instances for 'Device.QoS.Classification.{i}.' object.

## How to handle 'Device.Routing.Router.{i}.' object:

By default, all interfaces with all routes being available in the main routing table which is 'Device.Routing.Router.1.'.

```bash
config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option ip6assign '60'
    option is_lan '1'

config interface 'wan'
    option proto 'dhcp'
    option device 'eth0'

config interface 'wan6'
    option proto 'dhcpv6'
    option device 'eth0'
```

Its table id should be 254 according to rt_tables as defined below:

```bash
$ cat /etc/iproute2/rt_tables 
#
# reserved values
#
128 prelocal
255 local
254 main
253 default
0   unspec
#
# local
#
#1  inr.ruhep
````

To redirect routes for specific interface to a separate routing table, you need to add a new 'Device.Routing.Router.{i}.' object.

1. Adding a new 'Device.Routing.Router.{i}.' object:

Each new routing object must have a unique route table which is calculated as follows:

route table = local route which is the highest known reserved table id + current instance number - 1 which is the instance number for the main table

For example: 
In our case, the local route is 255 as defined in '/etc/iproute2/rt_tables' file and the current instance number is 2 so the new route table will be 255+2-1 = 256

```bash
$ cat /etc/bbfdm/dmmap/dmmap
config route
    option router_instance '1'
    option rt_table '254'

config route
    option router_instance '2'
    option rt_table '256'
```

2. Setting new routing object to needed interface:

```bash
obuspa -c set Device.IP.Interface.{i}.Router=Device.Routing.Router.{i}.
```

At this stage, the network uci should add the options 'ip4table' and 'ip6table' to needed main interface and its alias sections with the new route table id which is 256.

For example:
In our case, we used wan interface to redirect routes to a separate routing table which is 'Device.Routing.Router.2.'

```bash
config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option ip6assign '60'
    option is_lan '1'

config interface 'wan'
    option proto 'dhcp'
    option device 'eth0'
    option ip4table '256'
    option ip6table '256'

config interface 'wan6'
    option proto 'dhcpv6'
    option device 'eth0'
    option ip4table '256'
    option ip6table '256'
```

> Note1: All the routes for wan interface should be visible in the 'Device.Routing.Router.2.' instead of 'Device.Routing.Router.1.'
> Note2: The 'Device.Routing.Router.1.' should contain the contents of main table as before except all routes related to wan interface

## How to handle 'Device.Routing.Router.{i}.[IPv4Forwarding.{i},IPv6Forwarding.{i}].' object:

Each routing object can have ipv{4,6} static routes defined in uci network and ipv{4,6} dynamic routes defined in '/proc/net/route' and '/proc/net/ipv6_route' files.

1. Dynamic routes:

For each route defined in '/proc/net/route' and '/proc/net/ipv6_route' files, a new instance will be created for IPv4Forwarding.{i} and IPv6Forwarding.{i} objects under the main routing object which is Device.Routing.Router.1. or any specific routing object (Device.Routing.Router.{2,3,..}.)


2. Static routes:

When adding a new static route there are two options that need to be populated from routing object which are interface and table id.

For example:
In our case, we used wan interface to redirect routes to a separate routing table which is 'Device.Routing.Router.2.' and we created an ipv4 static route for table 256.

 ```bash
config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option ip6assign '60'
    option is_lan '1'

config interface 'wan'
    option proto 'dhcp'
    option device 'eth0'
    option ip4table '256'
    option ip6table '256'

config interface 'wan6'
    option proto 'dhcpv6'
    option device 'eth0'
    option ip4table '256'
    option ip6table '256'

config route 'wan_rt'
    option interface 'wan'
    option target '0.0.0.0/0'
    option table '256'

config route6 'wan_rt6'
    option interface 'wan'
    option target '::/0'
    option table '256'
```

> Note: The same can be done for ipv6 static route.

## How to handle 'Device.QoS.Classification.{i}.' object:

To configure the policy based routing we need to add new instances for 'Device.QoS.Classification.{i}.' object. Each instance should maps to qos->classify section and network->rule section, so each qos->classify section must have its network->rule section and vice versa and the syncronisation between them will be handled in dmmap_qos file.

```bash
$ cat /etc/config/qos

config classify 'classify_1'
    option enable '1'
    option dest_ip '1.1.1.0/24'
    option src_ip '172.16.11.1/32'

$ cat /etc/config/network

config rule 'rule_1'
    option enable '1'
    option dest '1.1.1.0/24'
    option src '172.16.11.1/32'
    option lookup '256'
    option priority '100'

$ cat /etc/bbfdm/dmmap/dmmap_qos

config class
    option class_instance '1'
    option classify 'classify_1'
    option rule 'rule_1'
````

> Note1: The same can be done for ipv6 routing as well using rule6 uci.

> Note2: The priority is significant since the default rule to lookup main table is at '32766' and we need to insert the source based routing rules before this.

```bash
$ ip rule show
0:  from all lookup local
100:    from all lookup 256
32766:  from all lookup main
32767:  from all lookup default
```

### QoS Data Model parameters mapping:

- Device.QoS.Classification.{i}.Enable // maps to qos->classify->enable
- Device.QoS.Classification.{i}.Order // maps to network->rule->priority
- Device.QoS.Classification.{i}.Interface // maps to qos->classify->ifname
- Device.QoS.Classification.{i}.DestIP // maps to qos->classify->dest_ip and network->rule->dest
- Device.QoS.Classification.{i}.DestMask // maps to qos->classify->dest_ip and network->rule->dest
- Device.QoS.Classification.{i}.SourceIP // maps to qos->classify->src_ip and network->rule->src
- Device.QoS.Classification.{i}.SourceMask // maps to qos->classify->src_ip and network->rule->src
- Device.QoS.Classification.{i}.ForwardingPolicy // maps to network->rule->lookup

# Limitations

- The value of 'ForwardingPolicy' should same as the routing table that we want to lookup for the packet meeting the classification criteria.

- For 'Device.QoS.Classification.{i}.ForwardingPolicy' and 'Device.Routing.Router.{i}.IPv4Forwarding.{i}.ForwardingPolicy' parameters, only values defined in the 'rt_tables' file are allowed like 254 for main table.

# References
1. [Network route uci](https://openwrt.org/docs/guide-user/network/routing/routes_configuration)
2. [Network rule uci](https://openwrt.org/docs/guide-user/network/routing/ip_rules)
3. [PBR with netifd](https://openwrt.org/docs/guide-user/network/routing/pbr_netifd)
4. [Examples of PBR with netifd](https://openwrt.org/docs/guide-user/network/routing/examples/pbr_netifd)
