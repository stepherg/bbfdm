/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "device.h"
#include "deviceinfo.h"
#include "managementserver.h"
#include "times.h"
#include "upnp.h"
#include "ip.h"
#include "ethernet.h"
#include "bridging.h"
#include "wifi.h"
#include "atm.h"
#include "ptm.h"
#include "dhcpv4.h"
#include "hosts.h"
#include "nat.h"
#include "ppp.h"
#include "routing.h"
#include "firewall.h"
#include "dns.h"
#include "users.h"
#include "dsl.h"
#include "fast.h"
#include "dhcpv6.h"
#include "interfacestack.h"
#include "qos.h"
#include "usb.h"
#include "datamodelversion.h"
#include "gre.h"
#include "dynamicdns.h"
#include "lanconfigsecurity.h"
#include "security.h"
#include "ieee1905.h"
#include "softwaremodules.h"
#ifdef BBF_TR104
#include "servicesvoiceservice.h"
#endif

/* *** BBFDM *** */
DMOBJ tEntry181Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceObj, tDeviceParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, BBFDM_BOTH},
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH},
{"ManagementServer", &DMREAD, NULL, NULL, "file:/etc/config/cwmp", NULL, NULL, NULL, NULL, tManagementServerParams, NULL, BBFDM_BOTH},
{"Time", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH},
{"UPnP", &DMREAD, NULL, NULL, "file:/etc/config/upnpd", NULL, NULL, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH},
#ifdef BBF_TR104
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesObj, NULL, NULL, BBFDM_BOTH},
#endif
{"Bridging", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH},
{"WiFi", &DMREAD, NULL, NULL, "file:/etc/config/wireless", NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH},
{"IP", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH},
{"Ethernet", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH},
{"DSL", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tDSLObj, tDSLParams, NULL, BBFDM_BOTH},
{"FAST", &DMREAD, NULL, NULL, "ubus:fast", NULL, NULL, NULL, tFASTObj, NULL, NULL, BBFDM_BOTH},
{"ATM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tATMObj, NULL, NULL, BBFDM_BOTH},
{"PTM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tPTMObj, NULL, NULL, BBFDM_BOTH},
{"DHCPv4", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcp.sh", NULL, NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH},
{"DHCPv6", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcpv6.sh", NULL, NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH},
{"Hosts", &DMREAD, NULL, NULL, "ubus:router.network->hosts", NULL, NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH},
{"NAT", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH},
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh", NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH},
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH},
{"Firewall", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH},
{"DNS", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, NULL, tDNSObj, tDNSParams, NULL, BBFDM_BOTH},
{"Users", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, tUsersObj, tUsersParams, NULL, BBFDM_BOTH},
{"IEEE1905", &DMREAD, NULL, NULL, "file:/etc/config/ieee1905,/etc/config/topology;ubus:ieee1905->info,topology->dump", NULL, NULL, NULL, tIEEE1905Obj, tIEEE1905Params, NULL, BBFDM_BOTH},
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH},
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH},
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh", NULL, NULL, NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH},
{"DynamicDNS", &DMREAD, NULL, NULL, "file:/etc/config/ddns", NULL, NULL, NULL, tDynamicDNSObj, tDynamicDNSParams, NULL, BBFDM_BOTH},
{"QoS", &DMREAD, NULL, NULL, "file:/etc/config/qos", NULL, NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH},
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH},
{"SoftwareModules", &DMREAD, NULL, NULL, "ubus:swmodules", NULL, NULL, NULL, tSoftwareModulesObj, tSoftwareModulesParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH},
{0}
};
