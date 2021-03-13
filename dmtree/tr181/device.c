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
#include "x_iopsys_eu_igmp.h"
#include "x_iopsys_eu_mld.h"
#include "x_iopsys_eu_syslog.h"
#include "x_iopsys_eu_owsd.h"
#include "x_iopsys_eu_dropbear.h"
#include "x_iopsys_eu_buttons.h"
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, tDeviceObj, tDeviceParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, BBFDM_BOTH},
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH},
{"ManagementServer", &DMREAD, NULL, NULL, "file:/etc/config/cwmp", NULL, NULL, NULL, tManagementServerParams, NULL, BBFDM_BOTH},
{"Time", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH},
{"UPnP", &DMREAD, NULL, NULL, "file:/etc/config/upnpd", NULL, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH},
#ifdef BBF_TR104
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, tServicesObj, NULL, NULL, BBFDM_BOTH},
#endif
{CUSTOM_PREFIX"Syslog", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, tSe_SyslogParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"OWSD", &DMREAD, NULL, NULL, "file:/etc/config/owsd", NULL, NULL, X_IOPSYS_EU_OWSDObj, X_IOPSYS_EU_OWSDParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"IGMP", &DMREAD, NULL, NULL, "file:/etc/config/mcast", NULL, NULL, X_IOPSYS_EU_IGMPObj, X_IOPSYS_EU_IGMPParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"MLD", &DMREAD, NULL, NULL, "file:/etc/config/mcast", NULL, NULL, X_IOPSYS_EU_MLDObj, X_IOPSYS_EU_MLDParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Dropbear", &DMWRITE, add_dropbear_instance, delete_dropbear_instance, "file:/etc/config/dropbear", browseXIopsysEuDropbear, NULL, NULL, X_IOPSYS_EU_DropbearParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Buttons", &DMREAD, NULL, NULL, "file:/etc/config/buttons", browseXIopsysEuButton, NULL, NULL, X_IOPSYS_EU_ButtonParams, NULL, BBFDM_BOTH},
{"Bridging", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH},
{"WiFi", &DMREAD, NULL, NULL, "file:/etc/config/wireless", NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH},
{"IP", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH},
{"Ethernet", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH},
{"DSL", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, tDSLObj, tDSLParams, NULL, BBFDM_BOTH},
{"FAST", &DMREAD, NULL, NULL, "ubus:fast", NULL, NULL, tFASTObj, NULL, NULL, BBFDM_BOTH},
{"ATM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, tATMObj, NULL, NULL, BBFDM_BOTH},
{"PTM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, tPTMObj, NULL, NULL, BBFDM_BOTH},
{"DHCPv4", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcp.sh", NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH},
{"DHCPv6", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcpv6.sh", NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH},
#ifdef GENERIC_OPENWRT
{"Hosts", &DMREAD, NULL, NULL, NULL, NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH},
#else
{"Hosts", &DMREAD, NULL, NULL, "ubus:router.network->hosts", NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH},
#endif
{"NAT", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH},
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh", NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH},
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH},
{"Firewall", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH},
{"DNS", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, tDNSObj, tDNSParams, NULL, BBFDM_BOTH},
{"Users", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, tUsersObj, tUsersParams, NULL, BBFDM_BOTH},
{"IEEE1905", &DMREAD, NULL, NULL, "file:/etc/config/ieee1905,/etc/config/topology;ubus:ieee1905->info,topology->dump", NULL, NULL, tIEEE1905Obj, tIEEE1905Params, NULL, BBFDM_BOTH},
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH},
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH},
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh", NULL,  NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH},
{"DynamicDNS", &DMREAD, NULL, NULL, "file:/etc/config/ddns", NULL, NULL, tDynamicDNSObj, tDynamicDNSParams, NULL, BBFDM_BOTH},
{"QoS", &DMREAD, NULL, NULL, "file:/etc/config/qos", NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH},
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH},
{"SoftwareModules", &DMREAD, NULL, NULL, "ubus:swmodules", NULL, NULL, tSoftwareModulesObj, tSoftwareModulesParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH},
{0}
};
