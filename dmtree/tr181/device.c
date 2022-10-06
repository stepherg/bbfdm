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
#include "gre.h"
#include "dynamicdns.h"
#include "lanconfigsecurity.h"
#include "security.h"
#include "ieee1905.h"
#include "routeradvertisement.h"
#include "gatewayinfo.h"
#ifdef BBF_TR104
#include "servicesvoiceservice.h"
#endif

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Device_InterfaceStackNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseInterfaceStackInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Device_RootDataModelVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = DEFAULT_DMVERSION;
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_Device_Reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return !dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0) ? CMD_SUCCESS : CMD_FAIL;
}

static int operate_Device_FactoryReset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return !dmcmd_no_wait("/sbin/defaultreset", 0) ? CMD_SUCCESS : CMD_FAIL;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** BBFDM *** */
DMOBJ tEntry181Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceObj, tDeviceParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device. *** */
DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"ManagementServer", &DMREAD, NULL, NULL, "file:/etc/config/cwmp", NULL, NULL, NULL, tManagementServerObj, tManagementServerParams, NULL, BBFDM_CWMP, NULL, "2.1"},
{"Time", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"UPnP", &DMREAD, NULL, NULL, "file:/etc/config/upnpd", NULL, NULL, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH, NULL, "2.0"},
{"WiFi", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Bridging", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"IP", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Ethernet", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"DSL", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tDSLObj, tDSLParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"FAST", &DMREAD, NULL, NULL, "ubus:fast", NULL, NULL, NULL, tFASTObj, tFASTParams, NULL, BBFDM_BOTH, NULL, "2.11"},
{"ATM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tATMObj, NULL, NULL, BBFDM_BOTH, NULL, "2.0"},
{"PTM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tPTMObj, NULL, NULL, BBFDM_BOTH, NULL, "2.0"},
{"DHCPv4", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcp.sh,/etc/config/dhcp", NULL, NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH, NULL, "2.0"},
{"DHCPv6", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcpv6.sh,/etc/config/dhcp", NULL, NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH, NULL, "2.2"},
{"Hosts", &DMREAD, NULL, NULL, "file:/etc/config/hosts", NULL, NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"NAT", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh,/etc/config/network", NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Firewall", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"DNS", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tDNSObj, tDNSParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Users", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, tUsersObj, tUsersParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"IEEE1905", &DMREAD, NULL, NULL, "file:/etc/config/ieee1905", NULL, NULL, NULL, tIEEE1905Obj, tIEEE1905Params, NULL, BBFDM_BOTH, NULL, "2.9"},
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh,/etc/config/network", NULL, NULL, NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH, NULL, "2.8"},
{"DynamicDNS", &DMREAD, NULL, NULL, "file:/etc/config/ddns", NULL, NULL, NULL, tDynamicDNSObj, tDynamicDNSParams, NULL, BBFDM_BOTH, NULL, "2.10"},
{"QoS", &DMREAD, NULL, NULL, "file:/etc/config/qos", NULL, NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH, NULL, "2.0"},
#if defined(LOPENSSL) || defined(LMBEDTLS) || defined(LWOLFSSL)
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH, NULL, "2.4"},
#endif
{"RouterAdvertisement", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, NULL, tRouterAdvertisementObj, tRouterAdvertisementParams, NULL, BBFDM_BOTH, NULL, "2.2"},
#ifdef BBF_TR104
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesObj, NULL, NULL, BBFDM_BOTH, NULL, "2.0"},
#endif
{"GatewayInfo", &DMREAD, NULL,NULL, NULL, NULL, NULL, NULL, NULL, tGatewayInfoParams, NULL, BBFDM_CWMP, NULL, "2.0"},
{0}
};

DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH, "2.4"},
{"Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_Reboot, BBFDM_USP, "2.12"},
{"FactoryReset()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_FactoryReset, BBFDM_USP, "2.12"},
//{"Boot!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP, "2.12"},
{0}
};
