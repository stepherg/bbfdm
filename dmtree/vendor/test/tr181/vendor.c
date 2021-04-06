/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "device.h"
#include "deviceinfo.h"
#include "firewall.h"
#include "vendor.h"

DM_MAP_OBJ tVendorExtensionOverwriteTEST[] = {
/* parentobj, nextobject, parameter */
{"Device.DeviceInfo.", NULL, tTEST_DeviceInfoParams},
{"Device.Firewall.Chain.{i}.Rule.{i}.", NULL, tTEST_FirewallRuleParams},
{0}
};

DM_MAP_OBJ tVendorExtensionTEST[] = {
/* parentobj, nextobject, parameter */
{"Device.", tTEST_DeviceObj, NULL},
{"Device.Firewall.Chain.{i}.Rule.{i}.", tTEST_FirewallChainRuleObj, tTEST_FirewallChainRuleParams},
{0}
};

char *VendorExtensionExcludeTEST[] = {
	"Device.USB.", //Object
	"Device.DeviceInfo.VendorConfigFile.{i}.", //Object
	"Device.DSL.Channel.{i}.Stats.", //Object

	"Device.QoS.Queue.{i}.SchedulerAlgorithm", //Parameter
	"Device.FAST.Line.{i}.Stats.CurrentDay.ErroredSecs", //Parameter
	"Device.Ethernet.RMONStats.{i}.Packets1024to1518Bytes", //Parameter

	NULL
};
