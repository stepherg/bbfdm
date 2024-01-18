# TR181 DNS datamodel

Aim of this document is to explain how the DNS Client and Relay datamodel objects are mapped in dnsmasq uci.

As per the definition in TR-181, Device.DNS.Client resolves FQDN on behalf of device internal application and Device.DNS.Relay allows the forwarding of local network DNS queries to local or external DNS servers.

For DNS resolution `dnsmasq` package has been used and as per the default configuration of `dnsmasq` it listens on all interfaces and performs the role of both the DNS client and DNS relay by default.

## Default config
```bash
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '0'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	option localservice '1'
	option dhcpscript '/usr/lib/dnsmasq/user-dhcp-script.sh'
	option ednspacket_max '1232'
```

Now datamodel gives the provision to enable/disable DNS relay/client. So if any user disables the DNS relay that means resolution of the DNS queries from LAN network will stop but internal DNS queries from the device itself will be resolved and if the DNS client has been disabled then internal DNS queries will not resolve but DNS queries from LAN network should be resolved.

To achieve this requirement whenever DNS client or relay object gets disabled we add a new section of dnsmasq in the UCI. This new section is then dedicated to DNS client and the section is named as `dns_client`, where as the existing dnsmasq section is then used for DNS relay only. We introduce two separate `dnsmasq` sections one for client and one for relay so that, at any point of time we can enable/disable the client and/or the relay without any effect to the other's work.

## UCI with added new section for DNS client
```bash
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '0'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	option localservice '1'
	option dhcpscript '/usr/lib/dnsmasq/user-dhcp-script.sh'
	option ednspacket_max '1232'
	list notinterface 'loopback'

config dnsmasq 'dns_client'
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option localservice '0'
	option rebind_protection '0'
	option rebind_localhost '1'
	option expandhosts '1'
	option nonegcache '0'
	option authoritative '1'
	option readethers '1'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	option ednspacket_max '1232'
	list interface 'loopback'
```
