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
#include "bridging.h"
#include "ethernet.h"
#include "ieee1905.h"
#include "ip.h"
#include "times.h"
#include "vendor.h"

DM_MAP_OBJ tVendorExtensionIOPSYS[] = {
/* parentobj, nextobject, parameter */
{"Device.", tIOPSYS_DeviceObj, NULL},
{"Device.DeviceInfo.", NULL, tIOPSYS_DeviceInfoParams},
{"Device.Ethernet.VLANTermination.{i}.", NULL, tIOPSYS_EthernetVLANTerminationParams},
{"Device.Time.", NULL, tIOPSYS_TimeParams},
{"Device.IEEE1905.AL.NetworkTopology.", tIOPSYS_IEEE1905ALNetworkTopologyObj, tIOPSYS_IEEE1905ALNetworkTopologyParams},
{"Device.Bridging.Bridge.{i}.Port.{i}.", NULL, tIOPSYS_BridgingBridgePortParams},
{"Device.Bridging.Bridge.{i}.VLAN.{i}.", NULL, tIOPSYS_BridgingBridgeVLANParams},
{0}
};
