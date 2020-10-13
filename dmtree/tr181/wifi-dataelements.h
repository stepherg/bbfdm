/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Saurabh Verma <saurabh.verma@iopsys.eu>
 *
 */

#ifndef __WIFI_DATAELEMENTS_H
#define __WIFI_DATAELEMENTS_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tWiFiDataElementsObj[];
extern DMOBJ tWiFiDataElementsNetworkObj[];
extern DMLEAF tWiFiDataElementsNetworkParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[];
extern DMOBJ tWiFiDataElementsAssociationEventObj[];
extern DMLEAF tWiFiDataElementsAssociationEventParams[];
extern DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[];
extern DMOBJ tWiFiDataElementsDisassociationEventObj[];
extern DMLEAF tWiFiDataElementsDisassociationEventParams[];
extern DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[];
#endif
