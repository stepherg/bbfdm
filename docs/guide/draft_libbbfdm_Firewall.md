# Firewall manager design proposal

Aim of this document is to propose design for a firewall manager.

The current implementation of Device.Firewall is plagued with many complexities
and limitation which significantly impacts the usage of Device.Firewall object and
implementation of new object within it. Further, due to the prevalent complexities,
maintainance of the current data model is also a heave burden.

Hence, the proposal is to have a firewall manager which:
- Simplifies mapping of data model objects to uci
- Allows better coverage of objects defined in Device.Firewall
- Much better conformance to data model.
- Easier implementation, maintenance and future extension of the data model.
- Remove dependency on config include for implementation of data model parameters.
  Please note: that at the uci, the config include section can still be used as
  suitable by the customer, its just that it will be avoided as much as possible
  while mapping data model objects to the uci.
- Abstract the underlying fw3/fw4; this will also simplify future migration to fw4.
- Overcome all the limitation in the current implementation, which are:
  - Multiple Device.Firewall.Level.{i}. objects are not supported
  - Multiple Device.Firewall.Chain.{i}. objects are not supported
  - Device.Firewall.Chain.{i}.Rule.{i}.TargetChain not supported
  - Device.Firewall.Chain.{i}.Rule.{i}.Order not supported, firewall rule applied in the order in which they are created, lower index rule has higher priority.
  - Device.Firewall.Config only supports 'Advanced' mode


# Design

The firewall manager should have a uci which is mapped directly with the objects
that are available in the data model. The reload operation of firewall manager should
then library functions that translate the firewall manager uci config to firewall
uci config. These library functions are available at /lib/fwmngr/fwmngr.sh and are
hence, the custodians of the fwmngr to firewall uci mapping. The firewall uci then
on reload uses fw3 or fw4 for generating the iptables or netfilter rules.

Let's take the example of our current system default. So, the current tr181 setting

Device.Firewall.Enable => 1
Device.Firewall.Config => Advanced
Device.Firewall.AdvancedLevel => Device.Firewall.Level.1
Device.Firewall.LevelNumberOfEntries => 1
Device.Firewall.ChainNumberOfEntries => 1
Device.Firewall.DMZNumberOfEntries => 0
Device.Firewall.ServiceNumberOfEntries => 0
Device.Firewall.Level.1.Alias => cpe-1
Device.Firewall.Level.1.Name => 
Device.Firewall.Level.1.Description => 
Device.Firewall.Level.1.Chain => Device.Firewall.Chain.1
Device.Firewall.Level.1.PortMappingEnabled => 1
Device.Firewall.Level.1.DefaultPolicy => Reject
Device.Firewall.Level.1.DefaultLogPolicy => 0
Device.Firewall.Chain.1.Enable => 1
Device.Firewall.Chain.1.Alias => cpe-1
Device.Firewall.Chain.1.Name => Defaults Configuration
Device.Firewall.Chain.1.Creator => Defaults
Device.Firewall.Chain.1.RuleNumberOfEntries => 11
Device.Firewall.Chain.1.Rule.1.Enable => 1
Device.Firewall.Chain.1.Rule.1.Status => Enabled
Device.Firewall.Chain.1.Rule.1.Order => 1
Device.Firewall.Chain.1.Rule.1.Alias => cpe-1
Device.Firewall.Chain.1.Rule.1.Description => 
Device.Firewall.Chain.1.Rule.1.Target => Accept
Device.Firewall.Chain.1.Rule.1.Log => 0
Device.Firewall.Chain.1.Rule.1.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.1.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.1.SourceInterface => Device.IP.Interface.1
Device.Firewall.Chain.1.Rule.1.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.1.DestInterface => 
Device.Firewall.Chain.1.Rule.1.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.1.IPVersion => -1
Device.Firewall.Chain.1.Rule.1.DestIP => 
Device.Firewall.Chain.1.Rule.1.DestMask => 
Device.Firewall.Chain.1.Rule.1.SourceIP => 
Device.Firewall.Chain.1.Rule.1.SourceMask => 
Device.Firewall.Chain.1.Rule.1.Protocol => 255
Device.Firewall.Chain.1.Rule.1.DestPort => -1
Device.Firewall.Chain.1.Rule.1.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.1.SourcePort => -1
Device.Firewall.Chain.1.Rule.1.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.2.Enable => 1
Device.Firewall.Chain.1.Rule.2.Status => Enabled
Device.Firewall.Chain.1.Rule.2.Order => 2
Device.Firewall.Chain.1.Rule.2.Alias => cpe-2
Device.Firewall.Chain.1.Rule.2.Description => Allow-DHCP-Renew
Device.Firewall.Chain.1.Rule.2.Target => Accept
Device.Firewall.Chain.1.Rule.2.Log => 0
Device.Firewall.Chain.1.Rule.2.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.2.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.2.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.2.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.2.DestInterface => 
Device.Firewall.Chain.1.Rule.2.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.2.IPVersion => 4
Device.Firewall.Chain.1.Rule.2.DestIP => 
Device.Firewall.Chain.1.Rule.2.DestMask => 
Device.Firewall.Chain.1.Rule.2.SourceIP => 
Device.Firewall.Chain.1.Rule.2.SourceMask => 
Device.Firewall.Chain.1.Rule.2.Protocol => 17
Device.Firewall.Chain.1.Rule.2.DestPort => 68
Device.Firewall.Chain.1.Rule.2.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.2.SourcePort => -1
Device.Firewall.Chain.1.Rule.2.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.3.Enable => 1
Device.Firewall.Chain.1.Rule.3.Status => Enabled
Device.Firewall.Chain.1.Rule.3.Order => 3
Device.Firewall.Chain.1.Rule.3.Alias => cpe-3
Device.Firewall.Chain.1.Rule.3.Description => Allow-Ping
Device.Firewall.Chain.1.Rule.3.Target => Accept
Device.Firewall.Chain.1.Rule.3.Log => 0
Device.Firewall.Chain.1.Rule.3.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.3.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.3.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.3.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.3.DestInterface => 
Device.Firewall.Chain.1.Rule.3.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.3.IPVersion => 4
Device.Firewall.Chain.1.Rule.3.DestIP => 
Device.Firewall.Chain.1.Rule.3.DestMask => 
Device.Firewall.Chain.1.Rule.3.SourceIP => 
Device.Firewall.Chain.1.Rule.3.SourceMask => 
Device.Firewall.Chain.1.Rule.3.Protocol => 1
Device.Firewall.Chain.1.Rule.3.DestPort => -1
Device.Firewall.Chain.1.Rule.3.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.3.SourcePort => -1
Device.Firewall.Chain.1.Rule.3.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.4.Enable => 1
Device.Firewall.Chain.1.Rule.4.Status => Enabled
Device.Firewall.Chain.1.Rule.4.Order => 4
Device.Firewall.Chain.1.Rule.4.Alias => cpe-4
Device.Firewall.Chain.1.Rule.4.Description => Allow-IGMP
Device.Firewall.Chain.1.Rule.4.Target => Accept
Device.Firewall.Chain.1.Rule.4.Log => 0
Device.Firewall.Chain.1.Rule.4.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.4.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.4.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.4.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.4.DestInterface => 
Device.Firewall.Chain.1.Rule.4.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.4.IPVersion => 4
Device.Firewall.Chain.1.Rule.4.DestIP => 
Device.Firewall.Chain.1.Rule.4.DestMask => 
Device.Firewall.Chain.1.Rule.4.SourceIP => 
Device.Firewall.Chain.1.Rule.4.SourceMask => 
Device.Firewall.Chain.1.Rule.4.Protocol => 2
Device.Firewall.Chain.1.Rule.4.DestPort => -1
Device.Firewall.Chain.1.Rule.4.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.4.SourcePort => -1
Device.Firewall.Chain.1.Rule.4.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.5.Enable => 1
Device.Firewall.Chain.1.Rule.5.Status => Enabled
Device.Firewall.Chain.1.Rule.5.Order => 5
Device.Firewall.Chain.1.Rule.5.Alias => cpe-5
Device.Firewall.Chain.1.Rule.5.Description => Allow-DHCPv6
Device.Firewall.Chain.1.Rule.5.Target => Accept
Device.Firewall.Chain.1.Rule.5.Log => 0
Device.Firewall.Chain.1.Rule.5.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.5.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.5.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.5.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.5.DestInterface => 
Device.Firewall.Chain.1.Rule.5.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.5.IPVersion => 6
Device.Firewall.Chain.1.Rule.5.DestIP => 
Device.Firewall.Chain.1.Rule.5.DestMask => 
Device.Firewall.Chain.1.Rule.5.SourceIP => 
Device.Firewall.Chain.1.Rule.5.SourceMask => 
Device.Firewall.Chain.1.Rule.5.Protocol => 17
Device.Firewall.Chain.1.Rule.5.DestPort => 546
Device.Firewall.Chain.1.Rule.5.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.5.SourcePort => -1
Device.Firewall.Chain.1.Rule.5.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.6.Enable => 1
Device.Firewall.Chain.1.Rule.6.Status => Enabled
Device.Firewall.Chain.1.Rule.6.Order => 6
Device.Firewall.Chain.1.Rule.6.Alias => cpe-6
Device.Firewall.Chain.1.Rule.6.Description => Allow-MLD
Device.Firewall.Chain.1.Rule.6.Target => Accept
Device.Firewall.Chain.1.Rule.6.Log => 0
Device.Firewall.Chain.1.Rule.6.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.6.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.6.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.6.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.6.DestInterface => 
Device.Firewall.Chain.1.Rule.6.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.6.IPVersion => 6
Device.Firewall.Chain.1.Rule.6.DestIP => 
Device.Firewall.Chain.1.Rule.6.DestMask => 
Device.Firewall.Chain.1.Rule.6.SourceIP => fe80::
Device.Firewall.Chain.1.Rule.6.SourceMask => fe80::/10
Device.Firewall.Chain.1.Rule.6.Protocol => 1
Device.Firewall.Chain.1.Rule.6.DestPort => -1
Device.Firewall.Chain.1.Rule.6.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.6.SourcePort => -1
Device.Firewall.Chain.1.Rule.6.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.7.Enable => 1
Device.Firewall.Chain.1.Rule.7.Status => Enabled
Device.Firewall.Chain.1.Rule.7.Order => 7
Device.Firewall.Chain.1.Rule.7.Alias => cpe-7
Device.Firewall.Chain.1.Rule.7.Description => Allow-ICMPv6-Input
Device.Firewall.Chain.1.Rule.7.Target => Accept
Device.Firewall.Chain.1.Rule.7.Log => 0
Device.Firewall.Chain.1.Rule.7.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.7.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.7.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.7.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.7.DestInterface => 
Device.Firewall.Chain.1.Rule.7.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.7.IPVersion => 6
Device.Firewall.Chain.1.Rule.7.DestIP => 
Device.Firewall.Chain.1.Rule.7.DestMask => 
Device.Firewall.Chain.1.Rule.7.SourceIP => 
Device.Firewall.Chain.1.Rule.7.SourceMask => 
Device.Firewall.Chain.1.Rule.7.Protocol => 1
Device.Firewall.Chain.1.Rule.7.DestPort => -1
Device.Firewall.Chain.1.Rule.7.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.7.SourcePort => -1
Device.Firewall.Chain.1.Rule.7.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.8.Enable => 1
Device.Firewall.Chain.1.Rule.8.Status => Enabled
Device.Firewall.Chain.1.Rule.8.Order => 8
Device.Firewall.Chain.1.Rule.8.Alias => cpe-8
Device.Firewall.Chain.1.Rule.8.Description => Allow-ICMPv6-Forward
Device.Firewall.Chain.1.Rule.8.Target => Accept
Device.Firewall.Chain.1.Rule.8.Log => 0
Device.Firewall.Chain.1.Rule.8.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.8.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.8.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.8.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.8.DestInterface => 
Device.Firewall.Chain.1.Rule.8.DestAllInterfaces => 1
Device.Firewall.Chain.1.Rule.8.IPVersion => 6
Device.Firewall.Chain.1.Rule.8.DestIP => 
Device.Firewall.Chain.1.Rule.8.DestMask => 
Device.Firewall.Chain.1.Rule.8.SourceIP => 
Device.Firewall.Chain.1.Rule.8.SourceMask => 
Device.Firewall.Chain.1.Rule.8.Protocol => 1
Device.Firewall.Chain.1.Rule.8.DestPort => -1
Device.Firewall.Chain.1.Rule.8.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.8.SourcePort => -1
Device.Firewall.Chain.1.Rule.8.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.9.Enable => 1
Device.Firewall.Chain.1.Rule.9.Status => Enabled
Device.Firewall.Chain.1.Rule.9.Order => 9
Device.Firewall.Chain.1.Rule.9.Alias => cpe-9
Device.Firewall.Chain.1.Rule.9.Description => Allow-IPSec-ESP
Device.Firewall.Chain.1.Rule.9.Target => Accept
Device.Firewall.Chain.1.Rule.9.Log => 0
Device.Firewall.Chain.1.Rule.9.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.9.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.9.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.9.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.9.DestInterface => Device.IP.Interface.1
Device.Firewall.Chain.1.Rule.9.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.9.IPVersion => -1
Device.Firewall.Chain.1.Rule.9.DestIP => 
Device.Firewall.Chain.1.Rule.9.DestMask => 
Device.Firewall.Chain.1.Rule.9.SourceIP => 
Device.Firewall.Chain.1.Rule.9.SourceMask => 
Device.Firewall.Chain.1.Rule.9.Protocol => 50
Device.Firewall.Chain.1.Rule.9.DestPort => -1
Device.Firewall.Chain.1.Rule.9.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.9.SourcePort => -1
Device.Firewall.Chain.1.Rule.9.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.10.Enable => 1
Device.Firewall.Chain.1.Rule.10.Status => Enabled
Device.Firewall.Chain.1.Rule.10.Order => 10
Device.Firewall.Chain.1.Rule.10.Alias => cpe-10
Device.Firewall.Chain.1.Rule.10.Description => Allow-ISAKMP
Device.Firewall.Chain.1.Rule.10.Target => Accept
Device.Firewall.Chain.1.Rule.10.Log => 0
Device.Firewall.Chain.1.Rule.10.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.10.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.10.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.10.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.10.DestInterface => Device.IP.Interface.1
Device.Firewall.Chain.1.Rule.10.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.10.IPVersion => -1
Device.Firewall.Chain.1.Rule.10.DestIP => 
Device.Firewall.Chain.1.Rule.10.DestMask => 
Device.Firewall.Chain.1.Rule.10.SourceIP => 
Device.Firewall.Chain.1.Rule.10.SourceMask => 
Device.Firewall.Chain.1.Rule.10.Protocol => 17
Device.Firewall.Chain.1.Rule.10.DestPort => 500
Device.Firewall.Chain.1.Rule.10.DestPortRangeMax => -1
Device.Firewall.Chain.1.Rule.10.SourcePort => -1
Device.Firewall.Chain.1.Rule.10.SourcePortRangeMax => -1
Device.Firewall.Chain.1.Rule.11.Enable => 1
Device.Firewall.Chain.1.Rule.11.Status => Enabled
Device.Firewall.Chain.1.Rule.11.Order => 11
Device.Firewall.Chain.1.Rule.11.Alias => cpe-11
Device.Firewall.Chain.1.Rule.11.Description => Support-UDP-Traceroute
Device.Firewall.Chain.1.Rule.11.Target => Reject
Device.Firewall.Chain.1.Rule.11.Log => 0
Device.Firewall.Chain.1.Rule.11.CreationDate => 0001-01-01T00:00:00Z
Device.Firewall.Chain.1.Rule.11.ExpiryDate => 9999-12-31T23:59:59Z
Device.Firewall.Chain.1.Rule.11.SourceInterface => Device.IP.Interface.2
Device.Firewall.Chain.1.Rule.11.SourceAllInterfaces => 0
Device.Firewall.Chain.1.Rule.11.DestInterface => 
Device.Firewall.Chain.1.Rule.11.DestAllInterfaces => 0
Device.Firewall.Chain.1.Rule.11.IPVersion => 4
Device.Firewall.Chain.1.Rule.11.DestIP => 
Device.Firewall.Chain.1.Rule.11.DestMask => 
Device.Firewall.Chain.1.Rule.11.SourceIP => 
Device.Firewall.Chain.1.Rule.11.SourceMask => 
Device.Firewall.Chain.1.Rule.11.Protocol => 17
Device.Firewall.Chain.1.Rule.11.DestPort => 33434
Device.Firewall.Chain.1.Rule.11.DestPortRangeMax => 33689
Device.Firewall.Chain.1.Rule.11.SourcePort => -1
Device.Firewall.Chain.1.Rule.11.SourcePortRangeMax => -1


will translate to the following fwmngr uci config
config firewall 'firewall'
    option enable '1'
    option config '2' # 0 - High, 1 - Low, 2 - Advanced, 3 - Policy
    option advanced_level 'level1'
    
    
config level 'level1'
    option name 'level1'
    option description 'iowrt default level'
    option chain 'chain1'
    option port_mapping_enabled '1'
    option default_policy '2' # 0 - Drop, 1 - ACCEPT, 2 - Reject
    option default_log_policy '0'
    
config chain 'chain1'
    option enable '1'
    option name 'default configurations'
    option creator '0' # 0-defaults, 1-portmapping,2-WANIPv6FirewallControl,3-ACS,4-UserInterface,5-Other
    
config rule 'rule1'
    option enable '1'
    option chain 'default configurations'
    option order '1'
    option target '1' # 0-Drop, 1-Accept,2-REJECT,3-return,4-targetchain
    option source_interface 'lan'

.......so on

which would then be translated into the corresponding firewall uci on reload of
fwmngr.

This approach basically makes all sorts of config from tr181 possible.

Note: The same is then extended for the Device.NAT as well, that is, the Device.NAT
object is mapped to fwmngr uci and the reload of fwmngr uci file generates the corresponding
redirect sections in the firewall uci which is then picked by the fw3/fw4 for generating
corresponding iptables/nftables rules.

    

