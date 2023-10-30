# Network Deployment Scenarios using TR-181 Data Model

The purpose of this document is to explain the different deployment scenarios supported by our devices and how to configure each scenario using TR-181 data model.

## Deployment scenarios

### 1. Transparent Bridge

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.1

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1

obuspa -c set Device.Bridging.Bridge.1.Port.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.4.Enable 1

obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.4.ManagementPort 0

obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.1.Port.4.LowerLayers Device.Ethernet.Interface.3
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fdec:6076:a3d3::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface1'
        option proto 'dhcp'
        option disabled '0'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_br1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1'
        list ports 'eth3'
        list ports 'eth4'
        option macaddr '44:D4:37:71:B5:53'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.1
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2,Device.Bridging.Bridge.1.Port.3,Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.1.Port.3.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.1.Port.4.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
```

### 2. One VLAN per Service (Bridge mode)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c add Device.Bridging.Bridge.2.VLAN.
obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c add Device.Bridging.Bridge.2.VLANPort.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.3.Enable 1

obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2
obuspa -c set Device.IP.Interface.3.LowerLayers Device.Ethernet.Link.3

obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.3

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Bridging.Bridge.2.Port.1
obuspa -c set Device.Ethernet.Link.3.LowerLayers Device.Ethernet.Interface.3

obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Enable 1

obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.VLAN Device.Bridging.Bridge.1.VLAN.1

obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Port Device.Bridging.Bridge.1.Port.2
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Port Device.Bridging.Bridge.1.Port.3

obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.3

obuspa -c set Device.Bridging.Bridge.1.VLAN.1.VLANID 100

obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0

obuspa -c set Device.Bridging.Bridge.1.Port.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1

obuspa -c set Device.Bridging.Bridge.2.Port.1.ManagementPort 1
obuspa -c set Device.Bridging.Bridge.2.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.3.ManagementPort 0

obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.VLAN Device.Bridging.Bridge.2.VLAN.1

obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Port Device.Bridging.Bridge.2.Port.2
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.Port Device.Bridging.Bridge.2.Port.3

obuspa -c set Device.Bridging.Bridge.2.VLAN.1.VLANID 200

obuspa -c set Device.Bridging.Bridge.2.Port.1.Enable 1
obuspa -c set Device.Bridging.Bridge.2.Port.2.Enable 1
obuspa -c set Device.Bridging.Bridge.2.Port.3.Enable 1

obuspa -c set Device.Bridging.Bridge.2.Port.2.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.2.Port.3.LowerLayers Device.Ethernet.Interface.3

obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.Enable 1
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fddd:90b7:d9ec::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:55'

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'none'
        option disabled '0'
        option device 'br-dev2'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface3'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4'
        option macaddr '44:D4:37:71:B5:55'

config device 'dev_br1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        option macaddr '44:D4:37:71:B5:53'
        list ports 'eth1.100'
        list ports 'eth4.100'

config device 'dev_br2'
        option name 'br-dev2'
        option type 'bridge'
        option bridge_empty '1'
        option macaddr '44:D4:37:71:B5:54'
        list ports 'eth3.200'
        list ports 'eth4.200'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth1'
        option name 'eth1.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_2_port_1'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option ifname 'eth3'
        option name 'eth3.200'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_2'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option ifname 'eth4'
        option name 'eth4.200'
        option macaddr '44:D4:37:71:B5:54'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
Device.IP.Interface.3.LowerLayers => Device.Ethernet.Link.3
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Bridging.Bridge.2.Port.1
Device.Ethernet.Link.3.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2,Device.Bridging.Bridge.1.Port.3
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.1.Port.3.LowerLayers => Device.Ethernet.Interface.3
Device.Bridging.Bridge.2.Port.1.LowerLayers => Device.Bridging.Bridge.2.Port.2,Device.Bridging.Bridge.2.Port.3
Device.Bridging.Bridge.2.Port.2.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.2.Port.3.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
Device.Bridging.Bridge.1.VLANPort.1.Enable => 1
Device.Bridging.Bridge.1.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLANPort.1.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.1.Port => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.2.Enable => 1
Device.Bridging.Bridge.1.VLANPort.2.Alias => cpe-2
Device.Bridging.Bridge.1.VLANPort.2.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.2.Port => Device.Bridging.Bridge.1.Port.3
Device.Bridging.Bridge.1.VLANPort.2.Untagged => 0
Device.Bridging.Bridge.2.VLANPort.1.Enable => 1
Device.Bridging.Bridge.2.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.2.VLANPort.1.VLAN => Device.Bridging.Bridge.2.VLAN.1
Device.Bridging.Bridge.2.VLANPort.1.Port => Device.Bridging.Bridge.2.Port.2
Device.Bridging.Bridge.2.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.2.VLANPort.2.Enable => 1
Device.Bridging.Bridge.2.VLANPort.2.Alias => cpe-2
Device.Bridging.Bridge.2.VLANPort.2.VLAN => Device.Bridging.Bridge.2.VLAN.1
Device.Bridging.Bridge.2.VLANPort.2.Port => Device.Bridging.Bridge.2.Port.3
Device.Bridging.Bridge.2.VLANPort.2.Untagged => 0
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
Device.Bridging.Bridge.1.VLAN.1.Enable => 1
Device.Bridging.Bridge.1.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLAN.1.Name => br_1_vlan_1
Device.Bridging.Bridge.1.VLAN.1.VLANID => 100
Device.Bridging.Bridge.2.VLAN.1.Enable => 1
Device.Bridging.Bridge.2.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.2.VLAN.1.Name => br_2_vlan_1
Device.Bridging.Bridge.2.VLAN.1.VLANID => 200
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.3
```

### 3. One VLAN per Service (Route mode)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.3.Enable 1
obuspa -c set Device.IP.Interface.4.Enable 1

obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.VLANTermination.1
obuspa -c set Device.IP.Interface.3.LowerLayers Device.Ethernet.VLANTermination.2
obuspa -c set Device.IP.Interface.4.LowerLayers Device.Ethernet.Link.2

obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.4

obuspa -c set Device.Ethernet.VLANTermination.1.LowerLayers Device.Ethernet.Link.2
obuspa -c set Device.Ethernet.VLANTermination.2.LowerLayers Device.Ethernet.Link.2

obuspa -c set Device.Ethernet.VLANTermination.1.VLANID 100
obuspa -c set Device.Ethernet.VLANTermination.2.VLANID 200

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Ethernet.Interface.3

obuspa -c set Device.Bridging.Bridge.1.Port.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1

obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0

obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.2
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd9b:03aa:df0a::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:56'

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'none'
        option disabled '0'
        option device 'eth4.100'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface3'
        option proto 'none'
        option disabled '0'
        option device 'eth4.200'
        option macaddr '44:D4:37:71:B5:55'

config interface 'iface4'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4'
        option macaddr '44:D4:37:71:B5:56'

config device 'vlan_ter_1'
        option type '8021q'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'
        option macaddr '44:D4:37:71:B5:54'

config device 'vlan_ter_2'
        option type '8021q'
        option vid '200'
        option ifname 'eth4'
        option name 'eth4.200'
        option macaddr '44:D4:37:71:B5:55'

config device 'dev_br1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        option macaddr '44:D4:37:71:B5:53'
        list ports 'eth1'
        list ports 'eth3'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.VLANTermination.1
Device.IP.Interface.3.LowerLayers => Device.Ethernet.VLANTermination.2
Device.IP.Interface.4.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
Device.Ethernet.VLANTermination.1.LowerLayers => Device.Ethernet.Link.2
Device.Ethernet.VLANTermination.2.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2,Device.Bridging.Bridge.1.Port.3
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.1.Port.3.LowerLayers => Device.Ethernet.Interface.2
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.4
```

### 4. VLAN Trunking

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.Bridging.Bridge.

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.4.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.4.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.1.Port.4.Enable 1

obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c set Device.Bridging.Bridge.1.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Port Device.Bridging.Bridge.1.Port.2

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Port Device.Bridging.Bridge.1.Port.3

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Port Device.Bridging.Bridge.1.Port.4

obuspa -c add Device.Bridging.Bridge.

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.1.ManagementPort 1

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.2.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.3.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.2.Port.3.Enable 1

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.4.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.4.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.2.Port.4.Enable 1

obuspa -c add Device.Bridging.Bridge.2.VLAN.
obuspa -c set Device.Bridging.Bridge.2.VLAN.1.VLANID 200

obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Port Device.Bridging.Bridge.2.Port.2

obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.Enable 1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.Port Device.Bridging.Bridge.2.Port.3

obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c set Device.Bridging.Bridge.2.VLANPort.3.Enable 1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.3.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.3.Port Device.Bridging.Bridge.2.Port.4

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Bridging.Bridge.2.Port.1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.3.LowerLayers Device.Ethernet.Interface.3

obuspa -c add Device.Ethernet.VLANTermination
obuspa -c set Device.Ethernet.VLANTermination.1.VLANID 300
obuspa -c set Device.Ethernet.VLANTermination.1.LowerLayers Device.Ethernet.Link.3

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.3.Enable 1
obuspa -c set Device.IP.Interface.3.LowerLayers Device.Ethernet.VLANTermination.1

obuspa -c add Device.DHCPv4.Client.
obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.3
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fdd6:db34:8106::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config device 'dev_br1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth1'
        option name 'eth1.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth3'
        option name 'eth3.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_3'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_br2'
        option name 'br-dev2'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.200'
        list ports 'eth3.200'
        list ports 'eth4.200'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_1'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option ifname 'eth1'
        option name 'eth1.200'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_2'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option ifname 'eth3'
        option name 'eth3.200'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_3'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option ifname 'eth4'
        option name 'eth4.200'
        option macaddr '44:D4:37:71:B5:54'

config device 'vlan_ter_1'
        option type '8021q'
        option vid '300'
        option ifname 'eth4'
        option name 'eth4.300'
        option macaddr '44:D4:37:71:B5:55'

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'none'
        option disabled '0'
        option device 'br-dev2'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface3'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4.300'
        option macaddr '44:D4:37:71:B5:55'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
Device.IP.Interface.3.LowerLayers => Device.Ethernet.VLANTermination.1
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
Device.Ethernet.VLANTermination.1.LowerLayers => Device.Ethernet.Link.3
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Bridging.Bridge.2.Port.1
Device.Ethernet.Link.3.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2,Device.Bridging.Bridge.1.Port.3,Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.1.Port.3.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.1.Port.4.LowerLayers => Device.Ethernet.Interface.3
Device.Bridging.Bridge.2.Port.1.LowerLayers => Device.Bridging.Bridge.2.Port.2,Device.Bridging.Bridge.2.Port.3,Device.Bridging.Bridge.2.Port.4
Device.Bridging.Bridge.2.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.2.Port.3.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.2.Port.4.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
Device.Bridging.Bridge.1.VLANPort.1.Enable => 1
Device.Bridging.Bridge.1.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLANPort.1.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.1.Port => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.2.Enable => 1
Device.Bridging.Bridge.1.VLANPort.2.Alias => cpe-2
Device.Bridging.Bridge.1.VLANPort.2.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.2.Port => Device.Bridging.Bridge.1.Port.3
Device.Bridging.Bridge.1.VLANPort.2.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.3.Enable => 1
Device.Bridging.Bridge.1.VLANPort.3.Alias => cpe-3
Device.Bridging.Bridge.1.VLANPort.3.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.3.Port => Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.VLANPort.3.Untagged => 0
Device.Bridging.Bridge.2.VLANPort.1.Enable => 1
Device.Bridging.Bridge.2.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.2.VLANPort.1.VLAN => Device.Bridging.Bridge.2.VLAN.1
Device.Bridging.Bridge.2.VLANPort.1.Port => Device.Bridging.Bridge.2.Port.2
Device.Bridging.Bridge.2.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.2.VLANPort.2.Enable => 1
Device.Bridging.Bridge.2.VLANPort.2.Alias => cpe-2
Device.Bridging.Bridge.2.VLANPort.2.VLAN => Device.Bridging.Bridge.2.VLAN.1
Device.Bridging.Bridge.2.VLANPort.2.Port => Device.Bridging.Bridge.2.Port.3
Device.Bridging.Bridge.2.VLANPort.2.Untagged => 0
Device.Bridging.Bridge.2.VLANPort.3.Enable => 1
Device.Bridging.Bridge.2.VLANPort.3.Alias => cpe-3
Device.Bridging.Bridge.2.VLANPort.3.VLAN => Device.Bridging.Bridge.2.VLAN.1
Device.Bridging.Bridge.2.VLANPort.3.Port => Device.Bridging.Bridge.2.Port.4
Device.Bridging.Bridge.2.VLANPort.3.Untagged => 0
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
Device.Bridging.Bridge.1.VLAN.1.Enable => 1
Device.Bridging.Bridge.1.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLAN.1.Name => br_1_vlan_1
Device.Bridging.Bridge.1.VLAN.1.VLANID => 100
Device.Bridging.Bridge.2.VLAN.1.Enable => 1
Device.Bridging.Bridge.2.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.2.VLAN.1.Name => br_2_vlan_1
Device.Bridging.Bridge.2.VLAN.1.VLANID => 200
```

### 5. One VLAN per Customer(MACVLAN over tagged interface)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.Ethernet.X_IOPSYS_EU_MACVLAN.
obuspa -c add Device.Ethernet.X_IOPSYS_EU_MACVLAN.
obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c add Device.Ethernet.Link.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.2.Enable 1

obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.X_IOPSYS_EU_MACVLAN.1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.X_IOPSYS_EU_MACVLAN.2

obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.2.Enable 1

obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.1
obuspa -c set Device.DHCPv4.Client.2.Interface Device.IP.Interface.2

obuspa -c set Device.Ethernet.X_IOPSYS_EU_MACVLAN.1.LowerLayers Device.Ethernet.VLANTermination.1
obuspa -c set Device.Ethernet.X_IOPSYS_EU_MACVLAN.2.LowerLayers Device.Ethernet.VLANTermination.1

obuspa -c set Device.Ethernet.VLANTermination.1.VLANID 100
obuspa -c set Device.Ethernet.VLANTermination.1.LowerLayers Device.Ethernet.Link.1

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Ethernet.Interface.3
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fde7:715b:fb50::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface1'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4_1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4_2'
        option macaddr '44:D4:37:71:B5:54'

config device 'mac_vlan_1'
        option type 'macvlan'
        option ifname 'eth4.100'
        option name 'eth4_1'
        option macaddr '44:D4:37:71:B5:53'

config device 'mac_vlan_2'
        option type 'macvlan'
        option ifname 'eth4.100'
        option name 'eth4_2'
        option macaddr '44:D4:37:71:B5:54'

config device 'vlan_ter_1'
        option type '8021q'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.X_IOPSYS_EU_MACVLAN.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.X_IOPSYS_EU_MACVLAN.2
$ obuspa -c get Device.Ethernet.X_IOPSYS_EU_MACVLAN.*.LowerLayers
Device.Ethernet.X_IOPSYS_EU_MACVLAN.1.LowerLayers => Device.Ethernet.VLANTermination.1
Device.Ethernet.X_IOPSYS_EU_MACVLAN.2.LowerLayers => Device.Ethernet.VLANTermination.1
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
Device.Ethernet.VLANTermination.1.LowerLayers => Device.Ethernet.Link.1
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.1
Device.DHCPv4.Client.2.Interface => Device.IP.Interface.2
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
```

### 6. One VLAN per Customer(MACVLAN over untagged interface)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.Ethernet.X_IOPSYS_EU_MACVLAN.
obuspa -c add Device.Ethernet.X_IOPSYS_EU_MACVLAN.
obuspa -c add Device.Ethernet.Link.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.2.Enable 1

obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.X_IOPSYS_EU_MACVLAN.1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.X_IOPSYS_EU_MACVLAN.2

obuspa -c set Device.Ethernet.X_IOPSYS_EU_MACVLAN.1.LowerLayers Device.Ethernet.Link.1
obuspa -c set Device.Ethernet.X_IOPSYS_EU_MACVLAN.2.LowerLayers Device.Ethernet.Link.1

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Ethernet.Interface.3

obuspa -c add Device.DHCPv4.Client.
obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.1

obuspa -c add Device.DHCPv4.Client.
obuspa -c set Device.DHCPv4.Client.2.Enable 1
obuspa -c set Device.DHCPv4.Client.2.Interface Device.IP.Interface.2
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd75:d87a:791b::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface1'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4_1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4_2'
        option macaddr '44:D4:37:71:B5:54'

config device 'mac_vlan_1'
        option type 'macvlan'
        option ifname 'eth4'
        option name 'eth4_1'
        option macaddr '44:D4:37:71:B5:53'

config device 'mac_vlan_2'
        option type 'macvlan'
        option ifname 'eth4'
        option name 'eth4_2'
        option macaddr '44:D4:37:71:B5:54'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.X_IOPSYS_EU_MACVLAN.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.X_IOPSYS_EU_MACVLAN.2
$ obuspa -c get Device.Ethernet.X_IOPSYS_EU_MACVLAN.*.LowerLayers
Device.Ethernet.X_IOPSYS_EU_MACVLAN.1.LowerLayers => Device.Ethernet.Link.1
Device.Ethernet.X_IOPSYS_EU_MACVLAN.2.LowerLayers => Device.Ethernet.Link.1
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.1
Device.DHCPv4.Client.2.Interface => Device.IP.Interface.2
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
```

### 7. VLAN Translation

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Ethernet.Link.
obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c add Device.Bridging.Bridge.1.VLANPort.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2

obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.2

obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.4.Enable 1

obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.4.ManagementPort 0

obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Enable 1

obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Port Device.Bridging.Bridge.1.Port.2


obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Port Device.Bridging.Bridge.1.Port.3

obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.VLAN Device.Bridging.Bridge.1.VLAN.2
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Port Device.Bridging.Bridge.1.Port.4

obuspa -c set Device.Bridging.Bridge.1.VLAN.1.VLANID 100
obuspa -c set Device.Bridging.Bridge.1.VLAN.2.VLANID 200

obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.1.Port.4.LowerLayers Device.Ethernet.Interface.3

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Ethernet.Interface.3
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd07:a062:db26::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4'
        option macaddr '44:D4:37:71:B5:54'

config device 'dev_br1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        option macaddr '44:D4:37:71:B5:53'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.200'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth1'
        option name 'eth1.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth3'
        option name 'eth3.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_3'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option ifname 'eth4'
        option name 'eth4.200'
        option macaddr '44:D4:37:71:B5:53'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2,Device.Bridging.Bridge.1.Port.3,Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.1.Port.3.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.1.Port.4.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
Device.Bridging.Bridge.1.VLAN.1.Enable => 1
Device.Bridging.Bridge.1.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLAN.1.Name => br_1_vlan_1
Device.Bridging.Bridge.1.VLAN.1.VLANID => 100
Device.Bridging.Bridge.1.VLAN.2.Enable => 1
Device.Bridging.Bridge.1.VLAN.2.Alias => cpe-2
Device.Bridging.Bridge.1.VLAN.2.Name => br_1_vlan_2
Device.Bridging.Bridge.1.VLAN.2.VLANID => 200
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
Device.Bridging.Bridge.1.VLANPort.1.Enable => 1
Device.Bridging.Bridge.1.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLANPort.1.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.1.Port => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.2.Enable => 1
Device.Bridging.Bridge.1.VLANPort.2.Alias => cpe-2
Device.Bridging.Bridge.1.VLANPort.2.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.2.Port => Device.Bridging.Bridge.1.Port.3
Device.Bridging.Bridge.1.VLANPort.2.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.3.Enable => 1
Device.Bridging.Bridge.1.VLANPort.3.Alias => cpe-3
Device.Bridging.Bridge.1.VLANPort.3.VLAN => Device.Bridging.Bridge.1.VLAN.2
Device.Bridging.Bridge.1.VLANPort.3.Port => Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.VLANPort.3.Untagged => 0
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.2
```

### 8. Managed Bridge

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.Bridging.Bridge.

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.4.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.4.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.1.Port.4.Enable 1

obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c set Device.Bridging.Bridge.1.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Port Device.Bridging.Bridge.1.Port.2
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.VLAN Device.Bridging.Bridge.1.VLAN.1

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Port Device.Bridging.Bridge.1.Port.3
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.VLAN Device.Bridging.Bridge.1.VLAN.1

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Port Device.Bridging.Bridge.1.Port.4

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c add Device.DHCPv4.Client.
obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.1
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fde2:72a7:da9d::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config device 'dev_br1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1.100'
        option vid '100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3.100'
        option vid '100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_3'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface1'
        option proto 'dhcp'
        option disabled '0'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2,Device.Bridging.Bridge.1.Port.3,Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.1.Port.3.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.1.Port.4.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
Device.Bridging.Bridge.1.VLANPort.1.Enable => 1
Device.Bridging.Bridge.1.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLANPort.1.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.1.Port => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.2.Enable => 1
Device.Bridging.Bridge.1.VLANPort.2.Alias => cpe-2
Device.Bridging.Bridge.1.VLANPort.2.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.2.Port => Device.Bridging.Bridge.1.Port.3
Device.Bridging.Bridge.1.VLANPort.2.Untagged => 0
Device.Bridging.Bridge.1.VLANPort.3.Enable => 1
Device.Bridging.Bridge.1.VLANPort.3.Alias => cpe-3
Device.Bridging.Bridge.1.VLANPort.3.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.3.Port => Device.Bridging.Bridge.1.Port.4
Device.Bridging.Bridge.1.VLANPort.3.Untagged => 0
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
Device.Bridging.Bridge.1.VLAN.1.Enable => 1
Device.Bridging.Bridge.1.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLAN.1.Name => br_1_vlan_1
Device.Bridging.Bridge.1.VLAN.1.VLANID => 100
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.1
```

### 9. QinQ lan untagged to wan double tagged (Bridge mode)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.2.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.2.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.3.Port.
obuspa -c set Device.Bridging.Bridge.3.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.3.Port.
obuspa -c set Device.Bridging.Bridge.3.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.3.Port.2.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.3.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.3.VLAN.
obuspa -c set Device.Bridging.Bridge.3.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.3.VLANPort.
obuspa -c set Device.Bridging.Bridge.3.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.3.VLANPort.1.VLAN Device.Bridging.Bridge.3.VLAN.1
obuspa -c set Device.Bridging.Bridge.3.VLANPort.1.Port Device.Bridging.Bridge.3.Port.2

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.4.Port.
obuspa -c set Device.Bridging.Bridge.4.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.4.Port.
obuspa -c set Device.Bridging.Bridge.4.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.4.Port.2.TPID 34984
obuspa -c set Device.Bridging.Bridge.4.Port.2.LowerLayers Device.Bridging.Bridge.3.Port.2
obuspa -c set Device.Bridging.Bridge.4.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.4.VLAN.
obuspa -c set Device.Bridging.Bridge.4.VLAN.1.VLANID 300

obuspa -c add Device.Bridging.Bridge.4.VLANPort.
obuspa -c set Device.Bridging.Bridge.4.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.4.VLANPort.1.VLAN Device.Bridging.Bridge.4.VLAN.1
obuspa -c set Device.Bridging.Bridge.4.VLANPort.1.Port Device.Bridging.Bridge.4.Port.2

obuspa -c add  Device.Bridging.ProviderBridge.

obuspa -c set Device.Bridging.ProviderBridge.1.CVLANcomponents Device.Bridging.Bridge.1,Device.Bridging.Bridge.2
obuspa -c set Device.Bridging.ProviderBridge.1.SVLANcomponent Device.Bridging.Bridge.4
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fdf8:6c90:1a98::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface_br1'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config device 'pr_br_1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1'
        list ports 'eth3'
        list ports 'eth4.100.300'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_3_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_4_port_1'
        option type '8021ad'
        option enabled '1'
        option vid '300'
        option ifname 'eth4.100'
        option name 'eth4.100.300'
        option macaddr '44:D4:37:71:B5:55'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.2.Port.1.LowerLayers => Device.Bridging.Bridge.2.Port.2
Device.Bridging.Bridge.2.Port.2.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.3.Port.1.LowerLayers => Device.Bridging.Bridge.3.Port.2
Device.Bridging.Bridge.3.Port.2.LowerLayers => Device.Ethernet.Interface.3
Device.Bridging.Bridge.4.Port.1.LowerLayers => Device.Bridging.Bridge.4.Port.2
Device.Bridging.Bridge.4.Port.2.LowerLayers => Device.Bridging.Bridge.3.Port.2
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
Device.Bridging.Bridge.3.VLANPort.1.Enable => 1
Device.Bridging.Bridge.3.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.3.VLANPort.1.VLAN => Device.Bridging.Bridge.3.VLAN.1
Device.Bridging.Bridge.3.VLANPort.1.Port => Device.Bridging.Bridge.3.Port.2
Device.Bridging.Bridge.3.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.4.VLANPort.1.Enable => 1
Device.Bridging.Bridge.4.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.4.VLANPort.1.VLAN => Device.Bridging.Bridge.4.VLAN.1
Device.Bridging.Bridge.4.VLANPort.1.Port => Device.Bridging.Bridge.4.Port.2
Device.Bridging.Bridge.4.VLANPort.1.Untagged => 0
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
Device.Bridging.Bridge.3.VLAN.1.Enable => 1
Device.Bridging.Bridge.3.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.3.VLAN.1.Name => br_3_vlan_1
Device.Bridging.Bridge.3.VLAN.1.VLANID => 100
Device.Bridging.Bridge.4.VLAN.1.Enable => 1
Device.Bridging.Bridge.4.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.4.VLAN.1.Name => br_4_vlan_1
Device.Bridging.Bridge.4.VLAN.1.VLANID => 300
$ obuspa -c get Device.Bridging.ProviderBridge.
Device.Bridging.ProviderBridge.1.Enable => 1
Device.Bridging.ProviderBridge.1.Status => Enabled
Device.Bridging.ProviderBridge.1.Alias => cpe-1
Device.Bridging.ProviderBridge.1.SVLANcomponent => Device.Bridging.Bridge.4
Device.Bridging.ProviderBridge.1.CVLANcomponents => Device.Bridging.Bridge.1,Device.Bridging.Bridge.2
```

### 10. QinQ lan single tagged to wan double tagged (Bridge mode)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c set Device.Bridging.Bridge.1.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Port Device.Bridging.Bridge.1.Port.2

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.2.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.2.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.2.VLAN.
obuspa -c set Device.Bridging.Bridge.2.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Port Device.Bridging.Bridge.2.Port.2

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.3.Port.
obuspa -c set Device.Bridging.Bridge.3.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.3.Port.
obuspa -c set Device.Bridging.Bridge.3.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.3.Port.2.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.3.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.3.VLAN.
obuspa -c set Device.Bridging.Bridge.3.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.3.VLANPort.
obuspa -c set Device.Bridging.Bridge.3.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.3.VLANPort.1.VLAN Device.Bridging.Bridge.3.VLAN.1
obuspa -c set Device.Bridging.Bridge.3.VLANPort.1.Port Device.Bridging.Bridge.3.Port.2

obuspa -c add Device.Bridging.Bridge.
obuspa -c add Device.Bridging.Bridge.4.Port.
obuspa -c set Device.Bridging.Bridge.4.Port.1.ManagementPort 1
obuspa -c add Device.Bridging.Bridge.4.Port.
obuspa -c set Device.Bridging.Bridge.4.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.4.Port.2.TPID 34984
obuspa -c set Device.Bridging.Bridge.4.Port.2.LowerLayers Device.Bridging.Bridge.3.Port.2
obuspa -c set Device.Bridging.Bridge.4.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.4.VLAN.
obuspa -c set Device.Bridging.Bridge.4.VLAN.1.VLANID 300

obuspa -c add Device.Bridging.Bridge.4.VLANPort.
obuspa -c set Device.Bridging.Bridge.4.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.4.VLANPort.1.VLAN Device.Bridging.Bridge.4.VLAN.1
obuspa -c set Device.Bridging.Bridge.4.VLANPort.1.Port Device.Bridging.Bridge.4.Port.2

obuspa -c add  Device.Bridging.ProviderBridge.

obuspa -c set Device.Bridging.ProviderBridge.1.CVLANcomponents Device.Bridging.Bridge.1,Device.Bridging.Bridge.2
obuspa -c set Device.Bridging.ProviderBridge.1.SVLANcomponent Device.Bridging.Bridge.4
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fde7:6307:3a39::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface_br1'
        option device 'br-dev1'
        option macaddr '44:D4:37:71:B5:53'

config device 'pr_br_1'
        option name 'br-dev1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.100.300'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth1'
        option name 'eth1.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_2_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth3'
        option name 'eth3.100'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_3_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'
        option macaddr '44:D4:37:71:B5:55'

config device 'br_4_port_1'
        option type '8021ad'
        option enabled '1'
        option vid '300'
        option ifname 'eth4.100'
        option name 'eth4.100.300'
        option macaddr '44:D4:37:71:B5:53'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
Device.Bridging.Bridge.1.Port.1.LowerLayers => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.Port.2.LowerLayers => Device.Ethernet.Interface.1
Device.Bridging.Bridge.2.Port.1.LowerLayers => Device.Bridging.Bridge.2.Port.2
Device.Bridging.Bridge.2.Port.2.LowerLayers => Device.Ethernet.Interface.2
Device.Bridging.Bridge.3.Port.1.LowerLayers => Device.Bridging.Bridge.3.Port.2
Device.Bridging.Bridge.3.Port.2.LowerLayers => Device.Ethernet.Interface.3
Device.Bridging.Bridge.4.Port.1.LowerLayers => Device.Bridging.Bridge.4.Port.2
Device.Bridging.Bridge.4.Port.2.LowerLayers => Device.Bridging.Bridge.3.Port.2
$ obuspa -c get Device.Bridging.Bridge.*.VLANPort.
Device.Bridging.Bridge.1.VLANPort.1.Enable => 1
Device.Bridging.Bridge.1.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLANPort.1.VLAN => Device.Bridging.Bridge.1.VLAN.1
Device.Bridging.Bridge.1.VLANPort.1.Port => Device.Bridging.Bridge.1.Port.2
Device.Bridging.Bridge.1.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.2.VLANPort.1.Enable => 1
Device.Bridging.Bridge.2.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.2.VLANPort.1.VLAN => Device.Bridging.Bridge.2.VLAN.1
Device.Bridging.Bridge.2.VLANPort.1.Port => Device.Bridging.Bridge.2.Port.2
Device.Bridging.Bridge.2.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.3.VLANPort.1.Enable => 1
Device.Bridging.Bridge.3.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.3.VLANPort.1.VLAN => Device.Bridging.Bridge.3.VLAN.1
Device.Bridging.Bridge.3.VLANPort.1.Port => Device.Bridging.Bridge.3.Port.2
Device.Bridging.Bridge.3.VLANPort.1.Untagged => 0
Device.Bridging.Bridge.4.VLANPort.1.Enable => 1
Device.Bridging.Bridge.4.VLANPort.1.Alias => cpe-1
Device.Bridging.Bridge.4.VLANPort.1.VLAN => Device.Bridging.Bridge.4.VLAN.1
Device.Bridging.Bridge.4.VLANPort.1.Port => Device.Bridging.Bridge.4.Port.2
Device.Bridging.Bridge.4.VLANPort.1.Untagged => 0
$ obuspa -c get Device.Bridging.Bridge.*.VLAN.
Device.Bridging.Bridge.1.VLAN.1.Enable => 1
Device.Bridging.Bridge.1.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.1.VLAN.1.Name => br_1_vlan_1
Device.Bridging.Bridge.1.VLAN.1.VLANID => 100
Device.Bridging.Bridge.2.VLAN.1.Enable => 1
Device.Bridging.Bridge.2.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.2.VLAN.1.Name => br_2_vlan_1
Device.Bridging.Bridge.2.VLAN.1.VLANID => 100
Device.Bridging.Bridge.3.VLAN.1.Enable => 1
Device.Bridging.Bridge.3.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.3.VLAN.1.Name => br_3_vlan_1
Device.Bridging.Bridge.3.VLAN.1.VLANID => 100
Device.Bridging.Bridge.4.VLAN.1.Enable => 1
Device.Bridging.Bridge.4.VLAN.1.Alias => cpe-1
Device.Bridging.Bridge.4.VLAN.1.Name => br_4_vlan_1
Device.Bridging.Bridge.4.VLAN.1.VLANID => 300
$ obuspa -c get Device.Bridging.ProviderBridge.
Device.Bridging.ProviderBridge.1.Enable => 1
Device.Bridging.ProviderBridge.1.Status => Enabled
Device.Bridging.ProviderBridge.1.Alias => cpe-1
Device.Bridging.ProviderBridge.1.SVLANcomponent => Device.Bridging.Bridge.4
Device.Bridging.ProviderBridge.1.CVLANcomponents => Device.Bridging.Bridge.1,Device.Bridging.Bridge.2
```

### 11. QinQ (Route mode)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.DHCPv4.Client.
obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c add Device.Ethernet.Link.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.VLANTermination.2

obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.1

obuspa -c set Device.Ethernet.VLANTermination.1.VLANID 100
obuspa -c set Device.Ethernet.VLANTermination.1.LowerLayers Device.Ethernet.Link.1

obuspa -c set Device.Ethernet.VLANTermination.2.TPID 34984
obuspa -c set Device.Ethernet.VLANTermination.2.VLANID 200
obuspa -c set Device.Ethernet.VLANTermination.2.LowerLayers Device.Ethernet.VLANTermination.1

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Ethernet.Interface.3
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fde6:fba3:37bb::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface1'
        option proto 'dhcp'
        option disabled '0'
        option device 'eth4.100.200'
        option macaddr '44:D4:37:71:B5:53'

config device 'vlan_ter_1'
        option type '8021q'
        option vid '100'
        option ifname 'eth4'
        option name 'eth4.100'

config device 'vlan_ter_2'
        option type '8021ad'
        option vid '200'
        option ifname 'eth4.100'
        option name 'eth4.100.200'
        option macaddr '44:D4:37:71:B5:53'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.VLANTermination.2
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
Device.Ethernet.VLANTermination.1.LowerLayers => Device.Ethernet.Link.1
Device.Ethernet.VLANTermination.2.LowerLayers => Device.Ethernet.VLANTermination.1
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.1
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
```

### 12. PPPoE WAN connection

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.IP.Interface.
obuspa -c add Device.PPP.Interface.
obuspa -c add Device.Ethernet.Link.

obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.PPP.Interface.1

obuspa -c set Device.PPP.Interface.1.LowerLayers Device.Ethernet.Link.1
obuspa -c set Device.PPP.Interface.1.Username test
obuspa -c set Device.PPP.Interface.1.Password test
obuspa -c set Device.PPP.Interface.1.Enable 1

obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Ethernet.Interface.3
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd8d:6e8e:444f::/48'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'iface1'
        option proto 'pppoe'
        option disabled '0'
        option device 'eth4'
        option macaddr '44:D4:37:71:B5:53'
        option username 'test'
        option password 'test'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.PPP.Interface.1
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
Device.PPP.Interface.1.LowerLayers => Device.Ethernet.Link.1
$ obuspa -c get Device.Ethernet.VLANTermination.*.LowerLayers
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.DHCPv4.Client.*.Interface
$ obuspa -c get Device.Bridging.Bridge.*.Port.*.LowerLayers
```

### 13. Switch WAN connection from DHCP to PPP

- **TR-181 Commands**

```bash
obuspa -c set Device.DHCPv4.Client.1.Interface ""
obuspa -c set Device.DHCPv6.Client.1.Interface ""
obuspa -c set Device.IP.Interface.2.LowerLayers ""

obuspa -c add Device.PPP.Interface.
obuspa -c set Device.PPP.Interface.1.LowerLayers Device.Ethernet.Link.2
obuspa -c set Device.PPP.Interface.1.Username test
obuspa -c set Device.PPP.Interface.1.Password test
obuspa -c set Device.PPP.Interface.1.Enable 1

obuspa -c set Device.IP.Interface.2.LowerLayers Device.PPP.Interface.1
```

- **Network UCI Config**

```bash
$ cat /etc/config/network

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd7c:b8d8:8e46::/48'

config device 'br_lan'
        option name 'br-lan'
        option type 'bridge'
        list ports 'eth1'
        list ports 'eth3'
        option multicast_to_unicast '0'
        option macaddr '44:D4:37:71:B5:51'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option is_lan '1'
        option macaddr '44:D4:37:71:B5:51'

config interface 'wan'
        option device 'eth4'
        option proto 'pppoe'
        option macaddr '44:D4:37:71:B5:52'
        option username 'test'
        option password 'test'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.PPP.Interface.1
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
Device.PPP.Interface.1.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => 
$ obuspa -c get Device.DHCPv6.Client.*.Interface
Device.DHCPv6.Client.1.Interface => 
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
```

### 14. Switch WAN connection from PPP to Static

- **TR-181 Commands**

```bash
obuspa -c set Device.IP.Interface.2.LowerLayers ""

obuspa -c del Device.PPP.Interface.1

obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2
obuspa -c set Device.IP.Interface.2.Enable 1

obuspa -c add Device.IP.Interface.2.IPv4Address.
obuspa -c set Device.IP.Interface.2.IPv4Address.1.Enable 1
obuspa -c set Device.IP.Interface.2.IPv4Address.1.IPAddress 10.100.1.222
obuspa -c set Device.IP.Interface.2.IPv4Address.1.SubnetMask 255.255.255.0

obuspa -c add Device.IP.Interface.2.IPv4Address.
obuspa -c set Device.IP.Interface.2.IPv4Address.2.Enable 1
obuspa -c set Device.IP.Interface.2.IPv4Address.2.IPAddress 10.100.10.222
obuspa -c set Device.IP.Interface.2.IPv4Address.2.SubnetMask 255.255.255.0
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd7c:b8d8:8e46::/48'

config device 'br_lan'
        option name 'br-lan'
        option type 'bridge'
        list ports 'eth1'
        list ports 'eth3'
        option multicast_to_unicast '0'
        option macaddr '44:D4:37:71:B5:51'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option is_lan '1'
        option macaddr '44:D4:37:71:B5:51'

config interface 'wan'
        option device 'eth4'
        option proto 'none'
        option macaddr '44:D4:37:71:B5:52'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface2_ipv4_1'
        option device 'eth4'
        option proto 'static'
        option disabled '0'
        option ipaddr '10.100.1.222'
        option netmask '255.255.255.0'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2_ipv4_2'
        option device 'eth4'
        option proto 'static'
        option disabled '0'
        option ipaddr '10.100.10.222'
        option netmask '255.255.255.0'
        option macaddr '44:D4:37:71:B5:54'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => 
$ obuspa -c get Device.DHCPv6.Client.*.Interface
Device.DHCPv6.Client.1.Interface => 
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.IP.Interface.2.IPv4Address.
Device.IP.Interface.2.IPv4Address.1.Enable => 1
Device.IP.Interface.2.IPv4Address.1.Status => Enabled
Device.IP.Interface.2.IPv4Address.1.Alias => cpe-1
Device.IP.Interface.2.IPv4Address.1.IPAddress => 10.100.1.222
Device.IP.Interface.2.IPv4Address.1.SubnetMask => 255.255.255.0
Device.IP.Interface.2.IPv4Address.1.AddressingType => Static
Device.IP.Interface.2.IPv4Address.2.Enable => 1
Device.IP.Interface.2.IPv4Address.2.Status => Enabled
Device.IP.Interface.2.IPv4Address.2.Alias => cpe-2
Device.IP.Interface.2.IPv4Address.2.IPAddress => 10.100.10.222
Device.IP.Interface.2.IPv4Address.2.SubnetMask => 255.255.255.0
Device.IP.Interface.2.IPv4Address.2.AddressingType => Static
```

### 15. Switch WAN connection from Static to DHCP

- **TR-181 Commands**

```bash
obuspa -c del Device.IP.Interface.2.IPv4Address.1
obuspa -c del Device.IP.Interface.2.IPv4Address.2

obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.2
obuspa -c set Device.DHCPv6.Client.1.Interface Device.IP.Interface.2
```

- **Network UCI Config**

```bash
$ cat /etc/config/network

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd7c:b8d8:8e46::/48'

config device 'br_lan'
        option name 'br-lan'
        option type 'bridge'
        list ports 'eth1'
        list ports 'eth3'
        option multicast_to_unicast '0'
        option macaddr '44:D4:37:71:B5:51'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option is_lan '1'
        option macaddr '44:D4:37:71:B5:51'

config interface 'wan'
        option device 'eth4'
        option proto 'dhcp'
        option macaddr '44:D4:37:71:B5:52'
        option hostname 'eagle-44d43771b550'
        option vendorid 'dslforum.org'
        option sendopts '124:00000DE90403757370 125:00000DE91C0106343444343337020B593037323131343030383603054541474C45'
        option reqopts '125 43'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'wan6'
        option device 'eth4'
        option proto 'dhcpv6'
        option macaddr '44:D4:37:71:B5:52'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.2
$ obuspa -c get Device.DHCPv6.Client.*.Interface
Device.DHCPv6.Client.1.Interface => Device.IP.Interface.2
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
```

### 16. Switch WAN connection from DHCP to Static

- **TR-181 Commands**

```bash
obuspa -c set Device.DHCPv4.Client.1.Interface ""
obuspa -c set Device.DHCPv6.Client.1.Interface ""

obuspa -c add Device.IP.Interface.2.IPv4Address.
obuspa -c set Device.IP.Interface.2.IPv4Address.1.Enable 1
obuspa -c set Device.IP.Interface.2.IPv4Address.1.IPAddress 10.100.1.222
obuspa -c set Device.IP.Interface.2.IPv4Address.1.SubnetMask 255.255.255.0

obuspa -c add Device.IP.Interface.2.IPv4Address.
obuspa -c set Device.IP.Interface.2.IPv4Address.2.Enable 1
obuspa -c set Device.IP.Interface.2.IPv4Address.2.IPAddress 10.100.10.222
obuspa -c set Device.IP.Interface.2.IPv4Address.2.SubnetMask 255.255.255.0
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd7c:b8d8:8e46::/48'

config device 'br_lan'
        option name 'br-lan'
        option type 'bridge'
        list ports 'eth1'
        list ports 'eth3'
        option multicast_to_unicast '0'
        option macaddr '44:D4:37:71:B5:51'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option is_lan '1'
        option macaddr '44:D4:37:71:B5:51'

config interface 'wan'
        option device 'eth4'
        option proto 'none'
        option macaddr '44:D4:37:71:B5:52'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2_ipv4_1'
        option device 'eth4'
        option proto 'static'
        option disabled '0'
        option ipaddr '10.100.1.222'
        option netmask '255.255.255.0'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2_ipv4_2'
        option device 'eth4'
        option proto 'static'
        option disabled '0'
        option ipaddr '10.100.10.222'
        option netmask '255.255.255.0'
        option macaddr '44:D4:37:71:B5:54'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => 
$ obuspa -c get Device.DHCPv6.Client.*.Interface
Device.DHCPv6.Client.1.Interface => 
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
$ obuspa -c get Device.IP.Interface.2.IPv4Address.
Device.IP.Interface.2.IPv4Address.1.Enable => 1
Device.IP.Interface.2.IPv4Address.1.Status => Enabled
Device.IP.Interface.2.IPv4Address.1.Alias => cpe-1
Device.IP.Interface.2.IPv4Address.1.IPAddress => 10.100.1.222
Device.IP.Interface.2.IPv4Address.1.SubnetMask => 255.255.255.0
Device.IP.Interface.2.IPv4Address.1.AddressingType => Static
Device.IP.Interface.2.IPv4Address.2.Enable => 1
Device.IP.Interface.2.IPv4Address.2.Status => Enabled
Device.IP.Interface.2.IPv4Address.2.Alias => cpe-2
Device.IP.Interface.2.IPv4Address.2.IPAddress => 10.100.10.222
Device.IP.Interface.2.IPv4Address.2.SubnetMask => 255.255.255.0
Device.IP.Interface.2.IPv4Address.2.AddressingType => Static
```

### 17. Switch WAN connection from Static to PPP

- **TR-181 Commands**

```bash
obuspa -c del Device.IP.Interface.2.IPv4Address.1
obuspa -c del Device.IP.Interface.2.IPv4Address.2

obuspa -c set Device.IP.Interface.2.LowerLayers ""

obuspa -c add Device.PPP.Interface.
obuspa -c set Device.PPP.Interface.1.LowerLayers Device.Ethernet.Link.2
obuspa -c set Device.PPP.Interface.1.Username test
obuspa -c set Device.PPP.Interface.1.Password test
obuspa -c set Device.PPP.Interface.1.Enable 1

obuspa -c set Device.IP.Interface.2.LowerLayers Device.PPP.Interface.1
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd7c:b8d8:8e46::/48'

config device 'br_lan'
        option name 'br-lan'
        option type 'bridge'
        list ports 'eth1'
        list ports 'eth3'
        option multicast_to_unicast '0'
        option macaddr '44:D4:37:71:B5:51'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option is_lan '1'
        option macaddr '44:D4:37:71:B5:51'

config interface 'wan'
        option device 'eth4'
        option proto 'pppoe'
        option macaddr '44:D4:37:71:B5:52'
        option username 'test'
        option password 'test'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.PPP.Interface.1
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
Device.PPP.Interface.1.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => 
$ obuspa -c get Device.DHCPv6.Client.*.Interface
Device.DHCPv6.Client.1.Interface => 
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
```

### 18. Switch WAN connection from PPP to DHCP

- **TR-181 Commands**

```bash
obuspa -c set Device.IP.Interface.2.LowerLayers ""

obuspa -c del Device.PPP.Interface.1

obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2

obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.2
obuspa -c set Device.DHCPv6.Client.1.Interface Device.IP.Interface.2
```

- **Network UCI Config**

```bash
$ cat /etc/config/network 

config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option ula_prefix 'fd7c:b8d8:8e46::/48'

config device 'br_lan'
        option name 'br-lan'
        option type 'bridge'
        list ports 'eth1'
        list ports 'eth3'
        option multicast_to_unicast '0'
        option macaddr '44:D4:37:71:B5:51'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '60'
        option is_lan '1'
        option macaddr '44:D4:37:71:B5:51'

config interface 'wan'
        option device 'eth4'
        option proto 'dhcp'
        option macaddr '44:D4:37:71:B5:52'
        option hostname 'eagle-44d43771b550'
        option vendorid 'dslforum.org'
        option sendopts '124:00000DE90403757370 125:00000DE91C0106343444343337020B593037323131343030383603054541474C45'
        option reqopts '125 43'

config device 'dev_eth1'
        option enabled '1'
        option ifname 'eth1'
        option name 'eth1'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth3'
        option enabled '1'
        option ifname 'eth3'
        option name 'eth3'
        option eee '0'
        option pause '0'
        option macaddr '44:D4:37:71:B5:51'

config device 'dev_eth4'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4'
        option eee '0'
        option pause '1'
        option macaddr '44:D4:37:71:B5:52'

config interface 'wan6'
        option device 'eth4'
        option proto 'dhcpv6'
        option macaddr '44:D4:37:71:B5:52'

```

- **TR-181 Data Model**

```bash
$ obuspa -c get Device.IP.Interface.*.LowerLayers
Device.IP.Interface.1.LowerLayers => Device.Ethernet.Link.1
Device.IP.Interface.2.LowerLayers => Device.Ethernet.Link.2
$ obuspa -c get Device.PPP.Interface.*.LowerLayers
$ obuspa -c get Device.DHCPv4.Client.*.Interface
Device.DHCPv4.Client.1.Interface => Device.IP.Interface.2
$ obuspa -c get Device.DHCPv6.Client.*.Interface
Device.DHCPv6.Client.1.Interface => Device.IP.Interface.2
$ obuspa -c get Device.Ethernet.Link.*.LowerLayers
Device.Ethernet.Link.1.LowerLayers => Device.Bridging.Bridge.1.Port.1
Device.Ethernet.Link.2.LowerLayers => Device.Ethernet.Interface.3
```

## Limitations

- Device.Bridging.Bridge.{i}.Port.{i}.LowerLayers: its value will be generated automatically when user defines **'ManagementPort'** parameter as **1**
- If user forgets to define a Bridge.{i}.Port. instance as management port, then there is no way to assign that Bridge.{i}.Port.{i}. for any interface(Device.Ethernet.Link.{i}.)
- Only one device port(ethx) is allowed for each Bridge{i}.Port. instance
- There are other deployment scenarios that can be configured by our devices using TR-181 data model, but we describe only the most important ones above
