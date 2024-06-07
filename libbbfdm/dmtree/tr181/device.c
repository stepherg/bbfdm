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
#include "times.h"
#include "upnp.h"
#include "ip.h"
#include "ethernet.h"
#include "bridging.h"
#include "wifi.h"
#include "atm.h"
#include "ptm.h"
#include "dhcpv4.h"
#include "nat.h"
#include "ppp.h"
#include "routing.h"
#include "firewall.h"
#include "dns.h"
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
#include "mqtt.h"
#include "ssh.h"
#include "userinterface.h"
#include "packetcapture.h"
#include "selftest.h"

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
	*value = "2.16";
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_Device_Reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0);
	if (res) bbfdm_set_fault_message(ctx, "Reboot: ubus 'system reboot' method doesn't exist");
	return !res ? 0 : USP_FAULT_COMMAND_FAILURE;
}

static int operate_Device_FactoryReset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = dmcmd_no_wait("/sbin/defaultreset", 0);
	if (res) bbfdm_set_fault_message(ctx, "FactoryReset: '/sbin/defaultreset' command doesn't exist");
	return !res ? 0 : USP_FAULT_COMMAND_FAILURE;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** BBFDM *** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.", tDeviceObj, tDeviceParams},
{0}
};

DMOBJ tEntryRoot[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceObj, tDeviceParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device. *** */
DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
#ifdef BBFDM_TR181_DEVICEINFO
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_TIME
{"Time", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_UPNP
{"UPnP", &DMREAD, NULL, NULL, "file:/etc/init.d/ssdpd", NULL, NULL, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_WIFI
{"WiFi", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_BRIDGING
{"Bridging", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_IP
{"IP", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_ETHERNET
{"Ethernet", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_DSL
{"DSL", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tDSLObj, tDSLParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_FAST
{"FAST", &DMREAD, NULL, NULL, "ubus:fast", NULL, NULL, NULL, tFASTObj, tFASTParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_ATM
{"ATM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tATMObj, NULL, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_PTM
{"PTM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, tPTMObj, NULL, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_DHCPv4
{"DHCPv4", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcp.sh,/etc/config/dhcp", NULL, NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_DHCPv6
{"DHCPv6", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcpv6.sh,/etc/config/dhcp", NULL, NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_NAT
{"NAT", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_PPP
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh,/etc/config/network", NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_ROUTING
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_FIREWALL
{"Firewall", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_DNS
{"DNS", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tDNSObj, tDNSParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_IEEE1905
{"IEEE1905", &DMREAD, NULL, NULL, "file:/etc/config/ieee1905", NULL, NULL, NULL, tIEEE1905Obj, tIEEE1905Params, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_INTERFACESTACK
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_USB
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_GRE
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh,/etc/config/network", NULL, NULL, NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_DDNS
{"DynamicDNS", &DMREAD, NULL, NULL, "file:/etc/config/ddns", NULL, NULL, NULL, tDynamicDNSObj, tDynamicDNSParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_QOS
{"QoS", &DMREAD, NULL, NULL, "file:/etc/config/qos", NULL, NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_LANCONFSEC
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_SECURITY
#if defined(LOPENSSL) || defined(LMBEDTLS) || defined(LWOLFSSL)
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH, NULL},
#endif
#endif
#ifdef BBFDM_TR181_ROUTERADVERTISEMENT
{"RouterAdvertisement", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, NULL, tRouterAdvertisementObj, tRouterAdvertisementParams, NULL, BBFDM_BOTH, NULL},
#endif
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_BOTH, NULL},
#ifdef BBFDM_TR181_GATEWAYINFO
{"GatewayInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGatewayInfoParams, NULL, BBFDM_CWMP, NULL},
#endif
#ifdef BBFDM_TR181_MQTT
{"MQTT", &DMREAD, NULL, NULL, "file:/etc/config/mosquitto", NULL, NULL, NULL, tMQTTObj, tMQTTParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_SSH
{"SSH", &DMREAD, NULL, NULL, "file:/etc/config/dropbear", NULL, NULL, NULL, tSSHObj, tSSHParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_USERINTERFACE
{"UserInterface", &DMREAD, NULL, NULL, "file:/etc/config/userinterface", NULL, NULL, NULL, tUIHTTPAccessObj, tUIParams, NULL, BBFDM_BOTH, NULL},
#endif
#ifdef BBFDM_TR181_PACKETCAPTURE
{"PacketCaptureDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tPacketCaptureObj, tPacketCaptureParams, NULL, BBFDM_CWMP, NULL},
#endif
#ifdef BBFDM_TR181_SELFTEST
{"SelfTestDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tSelfTestParams, NULL, BBFDM_CWMP, NULL},
#endif
{0}
};

DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
#ifdef BBFDM_TR181_INTERFACESTACK
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, BBFDM_BOTH},
#endif
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{"Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_Reboot, BBFDM_USP},
{"FactoryReset()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_FactoryReset, BBFDM_USP},
#ifdef BBFDM_TR181_PACKETCAPTURE
{"PacketCaptureDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_packetCapture, operate_Device_packetCapture, BBFDM_USP},
#endif
#ifdef BBFDM_TR181_SELFTEST
{"SelfTestDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_SelfTest, operate_Device_SelfTest, BBFDM_USP},
#endif
//{"Boot!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP},
{0}
};

