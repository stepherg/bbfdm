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
#include "ip.h"
#include "times.h"
#include "wifi.h"
#include "../tr104/servicesvoiceservicecallcontrol.h"
#include "../tr104/servicesvoiceservicecalllog.h"
#include "../tr104/servicesvoiceservicedect.h"
#include "vendor.h"

DM_MAP_OBJ tVendorExtensionIOPSYS[] = {
/* parentobj, nextobject, parameter */
{"Device.", tIOPSYS_DeviceObj, NULL},
{"Device.DeviceInfo.", NULL, tIOPSYS_DeviceInfoParams},
{"Device.Ethernet.", tIOPSYS_EthernetObj, NULL},
{"Device.Time.", NULL, tIOPSYS_TimeParams},
{"Device.Bridging.Bridge.{i}.Port.{i}.", NULL, tIOPSYS_BridgingBridgePortParams},
{"Device.Services.VoiceService.{i}.CallLog.{i}.", NULL, tIOPSYS_VoiceServiceCallLogParams},
{"Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.RTP.", NULL, tIOPSYS_VoiceServiceCallLogSessionSourceRTPParams},
{"Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.RTP.", NULL, tIOPSYS_VoiceServiceCallLogSessionDestinationRTPParams},
{"Device.Services.VoiceService.{i}.DECT.Portable.{i}.", NULL, tIOPSYS_VoiceServiceDECTPortableParams},
{"Device.Services.VoiceService.{i}.CallControl.Extension.{i}.", NULL, tIOPSYS_VoiceServiceCallControlExtensionParams},
{"Device.WiFi.AccessPoint.{i}.", NULL, tIOPSYS_WiFiAccessPointParams},
{0}
};
