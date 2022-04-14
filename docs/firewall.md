# Firewall
To configure firewall rules for all interfaces, add Device.Firewall.Chain.{i}.Rule.{i}. objects to the existing Device.Firewall.Chain.{i}. in the order in which they should be applied.

# Limitations
- Multiple Device.Firewall.Level.{i}. objects are not supported
- Multiple Device.Firewall.Chain.{i}. objects are not supported
- Device.Firewall.Chain.{i}.Rule.{i}.TargetChain not supported
- Device.Firewall.Chain.{i}.Rule.{i}.Order not supported, firewall rule applied in the order in which they are created, lower index rule has higher priority.
- Device.Firewall.Config only supports 'Advanced' mode

# How Device.Firewall.Chain.{i}.Rule.{i}. Object handles the Protocol parameter:

For Firewall rule sections, if the protocol(proto option) is not defined or if there are multiple protocols defined in the rule like proto='tcp udp' then in those cases the 'Device.Firewall.Chain.{i}.Rule.{i}.Protocol' parameter will have as value '255' which is reserved in the protocol specification.
