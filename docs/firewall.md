# Firewall
Aim of this document to explain the TR181 firewall datamodel parameter mappings with firewall and network uci.

In TR-181 firewall definition, we have Device.Firewall.Level., Deivce.Firewall.Chain. and Firewall.Chain.{i}.Rules., which does not have one to one mapping with firewall uci sections.

So for each new network interface created by libbbf, a new firewall uci zone will be created as follow:
- Create a Network interface section
- Create a Firewall zone section corresponding to the Interface section in the network uci file
- Give it the same name as the interface section in the network uci file.
- Set the default firewall zone value of input/output/forward to ACCEPT/ACCEPT/ACCEPT for all bridge interface and REJECT/ACCEPT/REJECT for all non bridge interfaces

So basically, if the network uci has this section for an interface
```bash
config interface ‘iptv’
    option device ‘ethx.y’
    option proto ‘dhcp’
```

Then below zone gets created by libbbf in firewall uci:
```bash
config zone ‘iptv’
    option network ‘iptv’
    option input ‘REJECT’
    option output ‘ACCEPT’
    option forward ‘REJECT’
```

Further, Per interface default policy can be configured by adding a rule in chain for each direction. So, if its required to have ACCEPT policy for input direction, then specify a rule as Chain.1.Rule.x.SourceInterface = Device.IP.Interface.3 and Rule.x.Target = ACCEPT and this result into corresponding firewall uci which does the same.

```bash
config rule ‘x’
    option src ‘iptv’
    option target ‘ACCEPT’
```

> Note: when trying to define a rule as Chain.1.Rule.x.SourceInterface = Device.IP.Interface.x and the zone for this interface (Device.IP.Interface.x) doesn't exist in the firewall uci file so, a new firewall zone section corresponding to this interface section will be created.

Similarly, to configure firewall rules for each interfaces, add rule objects in Device.Firewall.Chain.{i}.Rule.{i}. table to the existing Device.Firewall.Chain.{i}. in the order in which they should be applied.

# Limitations
- Multiple Device.Firewall.Level.{i}. objects are not supported
- Multiple Device.Firewall.Chain.{i}. objects are not supported
- Device.Firewall.Chain.{i}.Rule.{i}.TargetChain not supported
- Device.Firewall.Chain.{i}.Rule.{i}.Order not supported, firewall rule applied in the order in which they are created, lower index rule has higher priority.
- Device.Firewall.Config only supports 'Advanced' mode

# How Device.Firewall.Chain.{i}.Rule.{i}. Object handles the Protocol parameter:

For Firewall rule sections, if the protocol(proto option) is not defined or if there are multiple protocols defined in the rule like proto='tcp udp' then in those cases the 'Device.Firewall.Chain.{i}.Rule.{i}.Protocol' parameter will have as value '255' which is reserved in the protocol specification.

# References
1. [Firewall uci](https://openwrt.org/docs/guide-user/firewall/firewall_configuration)
2. [Network uci](https://openwrt.org/docs/guide-user/base-system/basic-networking)
