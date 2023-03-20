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

obuspa -c add Device.Bridging.Bridge.

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.2

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.4.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.4.Enable 1
obuspa -c set Device.Bridging.Bridge.1.Port.4.LowerLayers Device.Ethernet.Interface.3

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
        option ula_prefix 'fd7c:2b31:87e0::/48'

config device 'dev_br1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1'
        list ports 'eth3'
        list ports 'eth4'
        option macaddr '44:D4:37:71:B5:53'
        option name 'br-iface1'

config interface 'iface1'
        option disabled '0'
        option device 'br-iface1'
        option proto 'dhcp'
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

obuspa -c add Device.Bridging.Bridge.

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.1.ManagementPort 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.2.LowerLayers Device.Ethernet.Interface.1
obuspa -c set Device.Bridging.Bridge.1.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.1.Port.
obuspa -c set Device.Bridging.Bridge.1.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.1.Port.3.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.1.Port.3.Enable 1

obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c set Device.Bridging.Bridge.1.VLAN.1.VLANID 100

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.VLAN Device.Bridging.Bridge.1.VLAN.1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.1.Port Device.Bridging.Bridge.1.Port.2

obuspa -c add Device.Bridging.Bridge.1.VLANPort.
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Enable 1
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.Port Device.Bridging.Bridge.1.Port.3
obuspa -c set Device.Bridging.Bridge.1.VLANPort.2.VLAN Device.Bridging.Bridge.1.VLAN.1

obuspa -c add Device.Bridging.Bridge.

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.1.ManagementPort 1

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.2.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.2.LowerLayers Device.Ethernet.Interface.2
obuspa -c set Device.Bridging.Bridge.2.Port.2.Enable 1

obuspa -c add Device.Bridging.Bridge.2.Port.
obuspa -c set Device.Bridging.Bridge.2.Port.3.ManagementPort 0
obuspa -c set Device.Bridging.Bridge.2.Port.3.LowerLayers Device.Ethernet.Interface.3
obuspa -c set Device.Bridging.Bridge.2.Port.3.Enable 1

obuspa -c add Device.Bridging.Bridge.2.VLAN.
obuspa -c set Device.Bridging.Bridge.2.VLAN.1.VLANID 200

obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Port Device.Bridging.Bridge.2.Port.2
obuspa -c set Device.Bridging.Bridge.2.VLANPort.1.Enable 1

obuspa -c add Device.Bridging.Bridge.2.VLANPort.
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.VLAN Device.Bridging.Bridge.2.VLAN.1
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.Port Device.Bridging.Bridge.2.Port.3
obuspa -c set Device.Bridging.Bridge.2.VLANPort.2.Enable 1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Bridging.Bridge.2.Port.1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.3.LowerLayers Device.Ethernet.Interface.3

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.3.Enable 1
obuspa -c set Device.IP.Interface.3.LowerLayers Device.Ethernet.Link.3

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
        option ula_prefix 'fd5d:5778:318b::/48'

config device 'dev_br1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.100'
        list ports 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'
        option name 'br-iface1'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth1.100'
        option ifname 'eth1'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option ifname 'eth4'
        option name 'eth4.100'
        option vid '100'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_br2'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth3.200'
        list ports 'eth4.200'
        option macaddr '44:D4:37:71:B5:54'
        option name 'br-iface2'

config device 'br_2_port_1'
        option type '8021q'
        option vid '200'
        option name 'eth3.200'
        option ifname 'eth3'
        option enabled '1'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_2'
        option type '8021q'
        option vid '200'
        option name 'eth4.200'
        option ifname 'eth4'
        option enabled '1'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-iface1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'none'
        option disabled '0'
        option device 'br-iface2'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface3'
        option disabled '0'
        option device 'eth4'
        option proto 'dhcp'
        option macaddr '44:D4:37:71:B5:55'

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

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Ethernet.Interface.3

obuspa -c add Device.Ethernet.VLANTermination
obuspa -c set Device.Ethernet.VLANTermination.1.VLANID 100
obuspa -c set Device.Ethernet.VLANTermination.1.LowerLayers Device.Ethernet.Link.2

obuspa -c add Device.Ethernet.VLANTermination
obuspa -c set Device.Ethernet.VLANTermination.2.VLANID 200
obuspa -c set Device.Ethernet.VLANTermination.2.LowerLayers Device.Ethernet.Link.2

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.VLANTermination.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.3.Enable 1
obuspa -c set Device.IP.Interface.3.LowerLayers Device.Ethernet.VLANTermination.2

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.4.Enable 1
obuspa -c set Device.IP.Interface.4.LowerLayers Device.Ethernet.Link.2

obuspa -c add Device.DHCPv4.Client.
obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.4
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
        option ula_prefix 'fd13:df4a:13ea::/48'

config device 'dev_br1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1'
        list ports 'eth3'
        option macaddr '44:D4:37:71:B5:53'
        option name 'br-iface1'

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

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-iface1'
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
        option disabled '0'
        option device 'eth4'
        option proto 'dhcp'
        option macaddr '44:D4:37:71:B5:56'

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
        option ula_prefix 'fdfa:067b:d702::/48'

config device 'dev_br1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.100'
        option macaddr '44:D4:37:71:B5:53'
        option name 'br-iface1'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth1.100'
        option ifname 'eth1'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth3.100'
        option ifname 'eth3'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_3'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth4.100'
        option ifname 'eth4'
        option macaddr '44:D4:37:71:B5:53'

config device 'dev_br2'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.200'
        list ports 'eth3.200'
        list ports 'eth4.200'
        option macaddr '44:D4:37:71:B5:54'
        option name 'br-iface2'

config device 'br_2_port_1'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option name 'eth1.200'
        option ifname 'eth1'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_2'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option name 'eth3.200'
        option ifname 'eth3'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_2_port_3'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option name 'eth4.200'
        option ifname 'eth4'
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
        option device 'br-iface1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option proto 'none'
        option disabled '0'
        option device 'br-iface2'
        option macaddr '44:D4:37:71:B5:54'

config interface 'iface3'
        option disabled '0'
        option device 'eth4.300'
        option proto 'dhcp'
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

### 5. One VLAN per Customer

- **TR-181 Commands**

```bash

```

- **Network UCI Config**

```bash

```

- **TR-181 Data Model**

```bash

```

### 6. VLAN Translation

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

obuspa -c add Device.Bridging.Bridge.1.VLAN.
obuspa -c set Device.Bridging.Bridge.1.VLAN.2.VLANID 200

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
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.VLAN Device.Bridging.Bridge.1.VLAN.2
obuspa -c set Device.Bridging.Bridge.1.VLANPort.3.Port Device.Bridging.Bridge.1.Port.4

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Bridging.Bridge.1.Port.1

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.2.LowerLayers Device.Ethernet.Interface.3

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.Link.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.2.Enable 1
obuspa -c set Device.IP.Interface.2.LowerLayers Device.Ethernet.Link.2

obuspa -c add Device.DHCPv4.Client.
obuspa -c set Device.DHCPv4.Client.1.Enable 1
obuspa -c set Device.DHCPv4.Client.1.Interface Device.IP.Interface.2
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
        option ula_prefix 'fde4:1aa3:4bd7::/48'

config device 'dev_br1'
        option type 'bridge'
        option bridge_empty '1'
        option macaddr '44:D4:37:71:B5:53'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.200'
        option name 'br-iface1'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth1.100'
        option ifname 'eth1'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth3.100'
        option ifname 'eth3'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_3'
        option type '8021q'
        option enabled '1'
        option vid '200'
        option name 'eth4.200'
        option ifname 'eth4'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface1'
        option proto 'none'
        option disabled '0'
        option device 'br-iface1'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface2'
        option disabled '0'
        option device 'eth4'
        option proto 'dhcp'
        option macaddr '44:D4:37:71:B5:54'

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

### 7. Managed Bridge

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
        option ula_prefix 'fd73:3a3a:1060::/48'

config device 'dev_br1'
        option type 'bridge'
        option bridge_empty '1'
        list ports 'eth1.100'
        list ports 'eth3.100'
        list ports 'eth4.100'
        option name 'br-iface1'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth1.100'
        option ifname 'eth1'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_2'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth3.100'
        option ifname 'eth3'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_1_port_3'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth4.100'
        option ifname 'eth4'
        option macaddr '44:D4:37:71:B5:53'

config interface 'iface1'
        option disabled '0'
        option device 'br-iface1'
        option proto 'dhcp'
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

### 8. QinQ lan untagged to wan double tagged (Bridge mode)

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

obuspa -c set Device.Bridging.ProviderBridge.1.Type S-VLAN
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
        option ula_prefix 'fda2:6377:44eb::/48'

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
        option name 'eth4.100'
        option ifname 'eth4'
        option macaddr '44:D4:37:71:B5:55'

config device 'br_4_port_1'
        option enabled '1'
        option vid '300'
        option type '8021ad'
        option name 'eth4.100.300'
        option ifname 'eth4.100'
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
Device.Bridging.ProviderBridge.1.Type => S-VLAN
Device.Bridging.ProviderBridge.1.SVLANcomponent => Device.Bridging.Bridge.4
Device.Bridging.ProviderBridge.1.CVLANcomponents => Device.Bridging.Bridge.1,Device.Bridging.Bridge.2
```

### 9. QinQ lan single tagged to wan double tagged (Bridge mode)

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

obuspa -c set Device.Bridging.ProviderBridge.1.Type S-VLAN
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
        option ula_prefix 'fd34:1635:80a9::/48'

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
        option name 'eth1.100'
        option ifname 'eth1'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_2_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth3.100'
        option ifname 'eth3'
        option macaddr '44:D4:37:71:B5:53'

config device 'br_3_port_1'
        option type '8021q'
        option enabled '1'
        option vid '100'
        option name 'eth4.100'
        option ifname 'eth4'
        option macaddr '44:D4:37:71:B5:54'

config device 'br_4_port_1'
        option enabled '1'
        option vid '300'
        option type '8021ad'
        option name 'eth4.100.300'
        option ifname 'eth4.100'
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
Device.Bridging.ProviderBridge.1.Type => S-VLAN
Device.Bridging.ProviderBridge.1.SVLANcomponent => Device.Bridging.Bridge.4
Device.Bridging.ProviderBridge.1.CVLANcomponents => Device.Bridging.Bridge.1,Device.Bridging.Bridge.2
```

### 10. QinQ (Route mode)

- **TR-181 Commands**

```bash
obuspa -c del Device.DHCPv4.Client.*
obuspa -c del Device.DHCPv6.Client.*
obuspa -c del Device.Ethernet.Link.*
obuspa -c del Device.Bridging.Bridge.*
obuspa -c del Device.IP.Interface.*

obuspa -c add Device.Ethernet.Link.
obuspa -c set Device.Ethernet.Link.1.LowerLayers Device.Ethernet.Interface.3

obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c set Device.Ethernet.VLANTermination.1.VLANID 100
obuspa -c set Device.Ethernet.VLANTermination.1.LowerLayers Device.Ethernet.Link.1

obuspa -c add Device.Ethernet.VLANTermination.
obuspa -c set Device.Ethernet.VLANTermination.2.TPID 34984
obuspa -c set Device.Ethernet.VLANTermination.2.VLANID 200
obuspa -c set Device.Ethernet.VLANTermination.2.LowerLayers Device.Ethernet.VLANTermination.1

obuspa -c add Device.IP.Interface.
obuspa -c set Device.IP.Interface.1.Enable 1
obuspa -c set Device.IP.Interface.1.LowerLayers Device.Ethernet.VLANTermination.2

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
        option ula_prefix 'fd01:b1cb:215b::/48'

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

config interface 'iface1'
        option disabled '0'
        option device 'eth4.100.200'
        option proto 'dhcp'
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

## Limitations

- Regarding above scenarios, it's better to follow the sequence as described in each scenario to avoid misconfiguration issues
- Device.Bridging.Bridge.{i}.Port.{i}.LowerLayers: its value will be generated automatically when user defines **'ManagementPort'** parameter as **1**
- If user forgets to define a Bridge.{i}.Port. instance as management port, then there is no way to assign that Bridge.{i}.Port.{i}. for any interface(Device.Ethernet.Link.{i}.)
- Only one device port(ethx) is allowed for each Bridge{i}.Port. instance
- There are other deployment scenarios that can be configured by our devices using TR-181 data model, but we describe only the most important ones above
