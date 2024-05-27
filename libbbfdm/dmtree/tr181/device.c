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
#include "ip.h"
#include "wifi.h"
#include "ppp.h"
#include "routing.h"
#include "interfacestack.h"
#include "gre.h"
#include "lanconfigsecurity.h"
#include "security.h"
#include "routeradvertisement.h"
#include "gatewayinfo.h"
#include "mqtt.h"

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
	*value = "2.17";
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

/* *** Device. *** */
DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH, NULL},
{"WiFi", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH, NULL},
{"IP", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH, NULL},
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh,/etc/config/network", NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH, NULL},
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH, NULL},
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH, NULL},
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh,/etc/config/network", NULL, NULL, NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH, NULL},
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH, NULL},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH, NULL},
{"RouterAdvertisement", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, NULL, tRouterAdvertisementObj, tRouterAdvertisementParams, NULL, BBFDM_BOTH, NULL},
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_BOTH, NULL},
{"GatewayInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGatewayInfoParams, NULL, BBFDM_CWMP, NULL},
{"MQTT", &DMREAD, NULL, NULL, "file:/etc/config/mosquitto", NULL, NULL, NULL, tMQTTObj, tMQTTParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, BBFDM_BOTH},
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{"Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_Reboot, BBFDM_USP},
{"FactoryReset()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_FactoryReset, BBFDM_USP},
//{"Boot!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP},
{0}
};

