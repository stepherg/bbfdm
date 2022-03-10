# How Device.Firewall.Chain.{i}.Rule.{i}. Object handles the Protocol parameter:

For Firewall rule sections, if the protocol(proto option) is not defined or if there are multiple protocols defined in the rule like proto='tcp udp' then in those cases the 'Device.Firewall.Chain.{i}.Rule.{i}.Protocol' parameter will have as value '255' which is reserved in the protocol specification.