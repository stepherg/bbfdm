# TR181 GRE datamodel

Aim of this document is to explain how the Device.GRE.Tunnel.{i}. and Device.GRE.Tunnel.{i}.Interface.{i}. datamodel objects are mapped to network UCI.

As per the definition in TR-181:

- Device.GRE.Tunnel.{i}. allows configuration of a tunnel with respect to a certain remote IP Address.
- Device.GRE.Tunnel.{i}.Interface.{i}. allows configuration of a tunnel interface, which will have to be LowerLayer of a Device.IP.Interface.{i}. object.

## Configuration
A tunnel can be set up in five broad steps:
- Add a Device.GRE.Tunnel. object.
- Set its Device.GRE.Tunnel.{i}.RemoteEndpoints parameter.
- Add a Device.GRE.Tunnel.{i}.Interface. object.
- Set Device.GRE.Tunnel.{i}.Interface.{i}.LowerLayers to the interface with whose address we want to bind this tunnel (default is wan).
- Set up a Device.IP.Interface object.
- Set appropriate Device.IP.Interface.{i}.LowerLayers to point to above added Device.GRE.Tunnel.{i}.Interface. object.

Please compare the data model values with *ip addr* state below for a clearer picture.

### Example data model configuration

```bash
# add IP.Interface
obuspa -c add Device.IP.Interface.
obuspa -c add Device.IP.Interface.3.IPv4Address.
obuspa -c set Device.IP.Interface.3.IPv4Address.1.IPAddress 172.17.0.5
obuspa -c set Device.IP.Interface.3.IPv4Address.1.SubnetMask 255.255.255.0
obuspa -c set Device.IP.Interface.3.IPv4Address.1.Enable 1
obuspa -c set Device.IP.Interface.3.Enable 1

# add GRE.
obuspa -c add Device.GRE.Tunnel.
obuspa -c set Device.GRE.Tunnel.1.RemoteEndpoints 10.101.52.1
obuspa -c add Device.GRE.Tunnel.1.Interface.
obuspa -c set Device.GRE.Tunnel.1.Interface.1.LowerLayers Device.IP.Interface.2.

# set IP.Interface LowerLayer
obuspa -c set Device.IP.Interface.3.LowerLayers Device.GRE.Tunnel.1.Interface.1.

```

after the above config, the object should should look as follows:

```bash
root@iopsys:~# obuspa -c get Device.GRE.
Device.GRE.TunnelNumberOfEntries => 1
Device.GRE.Tunnel.1.Enable => 1
Device.GRE.Tunnel.1.Status => Enabled
Device.GRE.Tunnel.1.Alias => cpe-1
Device.GRE.Tunnel.1.RemoteEndpoints => 10.101.52.1
Device.GRE.Tunnel.1.DeliveryHeaderProtocol => IPv4
Device.GRE.Tunnel.1.ConnectedRemoteEndpoint => 10.101.52.1
Device.GRE.Tunnel.1.InterfaceNumberOfEntries => 1
Device.GRE.Tunnel.1.Interface.1.Enable => 1
Device.GRE.Tunnel.1.Interface.1.Status => Unknown
Device.GRE.Tunnel.1.Interface.1.Alias => cpe-1
Device.GRE.Tunnel.1.Interface.1.Name => gre_d1i1
Device.GRE.Tunnel.1.Interface.1.LastChange => 227
Device.GRE.Tunnel.1.Interface.1.LowerLayers => Device.IP.Interface.2
Device.GRE.Tunnel.1.Interface.1.UseChecksum => 0
Device.GRE.Tunnel.1.Interface.1.UseSequenceNumber => 0
Device.GRE.Tunnel.1.Interface.1.Stats.BytesSent => 84
Device.GRE.Tunnel.1.Interface.1.Stats.BytesReceived => 84
Device.GRE.Tunnel.1.Interface.1.Stats.PacketsSent => 1
Device.GRE.Tunnel.1.Interface.1.Stats.PacketsReceived => 1
Device.GRE.Tunnel.1.Interface.1.Stats.ErrorsSent => 0
Device.GRE.Tunnel.1.Interface.1.Stats.ErrorsReceived => 0
```

```bash
root@iopsys:~# obuspa -c get Device.IP.Interface.3.
Device.IP.Interface.3.Enable => 1
Device.IP.Interface.3.IPv6Enable => 1
Device.IP.Interface.3.ULAEnable => 1
Device.IP.Interface.3.Status => Down
Device.IP.Interface.3.Alias => cpe-3
Device.IP.Interface.3.Name => iface3
Device.IP.Interface.3.LastChange => 0
Device.IP.Interface.3.LowerLayers => Device.GRE.Tunnel.1.Interface.1
Device.IP.Interface.3.Router => Device.Routing.Router.1
Device.IP.Interface.3.Reset => 0
Device.IP.Interface.3.MaxMTUSize => 1500
Device.IP.Interface.3.Type => Normal
Device.IP.Interface.3.Loopback => 0
Device.IP.Interface.3.IPv4AddressNumberOfEntries => 1
Device.IP.Interface.3.IPv6AddressNumberOfEntries => 0
Device.IP.Interface.3.IPv6PrefixNumberOfEntries => 0
Device.IP.Interface.3.IPv4Address.1.Enable => 1
Device.IP.Interface.3.IPv4Address.1.Status => Enabled
Device.IP.Interface.3.IPv4Address.1.Alias => cpe-1
Device.IP.Interface.3.IPv4Address.1.IPAddress => 172.17.0.5
Device.IP.Interface.3.IPv4Address.1.SubnetMask => 255.255.255.0
Device.IP.Interface.3.IPv4Address.1.AddressingType => Static
Device.IP.Interface.3.Stats.BytesSent => 0
Device.IP.Interface.3.Stats.BytesReceived => 0
Device.IP.Interface.3.Stats.PacketsSent => 0
Device.IP.Interface.3.Stats.PacketsReceived => 0
Device.IP.Interface.3.Stats.ErrorsSent => 0
Device.IP.Interface.3.Stats.ErrorsReceived => 0
Device.IP.Interface.3.Stats.DiscardPacketsSent => 0
Device.IP.Interface.3.Stats.DiscardPacketsReceived => 0
Device.IP.Interface.3.Stats.MulticastPacketsReceived => 0
```

NOTE: The status might be down for *Device.IP.Interface.3.Status* but the IP will be assigned properly in ifconfig output.

```bash
gre4-gre_d1i1 Link encap:UNSPEC  HWaddr 0A-65-34-64-00-00-00-00-00-00-00-00-00-00-00-00  
          inet addr:172.17.0.5  P-t-P:172.17.0.5  Mask:255.255.255.0
          inet6 addr: fe80::5efe:a65:3464/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1280  Metric:1
          RX packets:1 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:84 (84.0 B)  TX bytes:84 (84.0 B)
```

## Network UCI with added new section for GRE Tunnel

```bash
config device 'gre_dev_1'
	option name 'gre_dev_1'
	option type 'tunnel'
	option mode 'greip'
	option remote '10.101.52.1'

config interface 'gre_d1i1'
	option proto 'gre'
	option device 'gre_dev_1'
	option disabled '0'
	option tunlink 'wan'
	option peeraddr '10.101.52.1'

config interface 'gre_ll_1'
	option proto 'static'
	option ipaddr '172.17.0.5'
	option netmask '255.255.255.0'
	option device 'gre4-gre_d1i1'

```

### IP addr state

```bash
23: gre4-gre_d1i1@eth0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc noqueue state UNKNOWN group default qlen 1000
    link/gre 10.101.52.100 peer 10.101.52.1
    inet 172.17.0.5/24 brd 172.17.0.255 scope global gre4-gre_d1i1
       valid_lft forever preferred_lft forever
    inet6 fe80::5efe:c0a8:101/64 scope link
       valid_lft forever preferred_lft forever
```

## Limitations
- Current system expects one to one mapping between Device.Tunnel.{i}. and Device.Tunnel.{i}.Interface and Device.IP.Interface.{i}.LowerLayer at a time, that is,
at the moment, we can only functionally support single value in Device.GRE.Tunnel.1.Interface.1.LowerLayers and not comma separated list of values.
- When Device.IP.Interface.{i}.LowerLayer is set to Device.GRE.Tunnel.{i}.Interface.{i}., the system finds the Linux generated tunnel name for the Tunnel and sets it to option device in the Device.IP.Interface.{i}. interface section, this is to avoid using "@" notation of referring to interfaces, which causes problems in processing of interfaces in the data model implementation.
- The lowerlayer of the GRE.Tunnel.Interface object maps to option tunlink in the UCI. If not specified, openwrt by default picks wan interface as tunlink. That means if you have a config interface 'wan' section in your UCI, then the IP.Interface object corresponding to this will automatically become the lowerlayer of Tunnel.Interface object. It is strongly recommended that you do not rely on this however, and for clarity, always specify the value of Tunnel.Interface.Lowerlayer parameter, even though, functionally, your tunnel may even be setup if you leave it as blank provided a config interface wan section exists in your network UCI. In such a scenario, even though you have left the Lowerlayer value as blank, the "wan" interface will be used internally as the default value for option tunlink.
