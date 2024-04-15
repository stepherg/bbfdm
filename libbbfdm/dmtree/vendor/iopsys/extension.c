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
#include "ip.h"
#include "times.h"
#include "wifi.h"
#include "extension.h"

DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.DeviceInfo.", NULL, tIOPSYS_DeviceInfoParams},
{"Device.Bridging.Bridge.{i}.Port.{i}.", NULL, tIOPSYS_BridgingBridgePortParams},
{"Device.WiFi.AccessPoint.{i}.", NULL, tIOPSYS_WiFiAccessPointParams},
{0}
};
