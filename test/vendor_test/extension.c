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
#include "extension.h"

DMOBJ tTEST_DSLChannelObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_NONE},
{0}
};

DMLEAF tTEST_QoSQueueParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SchedulerAlgorithm", &DMREAD, DMT_STRING, NULL, NULL, BBFDM_NONE},
{0}
};

DMLEAF tFASTLineStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ErroredSecs", &DMREAD, DMT_UNINT, NULL, NULL, BBFDM_NONE},
{0}
};

DMLEAF tTEST_EthernetRMONStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Packets1024to1518Bytes", &DMREAD, DMT_UNLONG, NULL, NULL, BBFDM_NONE},
{0}
};

DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.", tTEST_DeviceObj, NULL}, // Overwrite 'X_IOPSYS_EU_Dropbear' && Exclude 'USB'
{"Device.Firewall.Chain.{i}.Rule.{i}.", tTEST_FirewallChainRuleObj, tTEST_FirewallChainRuleParams}, // Extend 'X_TEST_COM_TimeSpan', etc.. && Overwrite 'ExpiryDate'
{"Device.DeviceInfo.", tTEST_DeviceInfoObj, tTEST_DeviceInfoParams}, // Overwrite 'Manufacturer' && Exclude 'VendorConfigFile' from the tree
{"Device.DSL.Channel.{i}.", tTEST_DSLChannelObj, NULL}, // Exclude 'Stats' from the tree
{"Device.QoS.Queue.{i}.", NULL, tTEST_QoSQueueParams}, // Exclude 'SchedulerAlgorithm' from the tree
{"Device.FAST.Line.{i}.Stats.CurrentDay.", NULL, tFASTLineStatsParams}, // Exclude 'ErroredSecs' from the tree
{"Device.Ethernet.RMONStats.{i}.", NULL, tTEST_EthernetRMONStatsParams}, // Exclude 'Packets1024to1518Bytes' from the tree
{0}
};
