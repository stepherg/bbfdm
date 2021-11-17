/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __WIFI_H
#define __WIFI_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tWiFiObj[];
extern DMLEAF tWiFiParams[];
extern DMOBJ tWiFiRadioObj[];
extern DMOBJ tWiFiAccessPointObj[];
extern DMOBJ tWiFiSSIDObj[];
extern DMLEAF tWiFiAccessPointParams[];
extern DMLEAF tWiFiSSIDParams[];
extern DMLEAF tWiFiRadioParams[];
extern DMLEAF tWiFiAccessPointSecurityParams[];
extern DMLEAF tWiFiAccessPointAssociatedDeviceParams[];
extern DMOBJ tWiFiAccessPointAssociatedDeviceObj[];
extern DMLEAF tWiFiAccessPointAssociatedDeviceStatsParams[];
extern DMLEAF tWiFiRadioStatsParams[];
extern DMLEAF tWiFiSSIDStatsParams[];
extern DMOBJ tWiFiNeighboringWiFiDiagnosticObj[];
extern DMLEAF tWiFiNeighboringWiFiDiagnosticParams[];
extern DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[];
extern DMLEAF tWiFiAccessPointWPSParams[];
extern DMLEAF tWiFiAccessPointAccountingParams[];
extern DMOBJ tWiFiEndPointObj[];
extern DMLEAF tWiFiEndPointParams[];
extern DMLEAF tWiFiEndPointSecurityParams[];
extern DMLEAF tWiFiEndPointWPSParams[];
extern DMOBJ tWiFiEndPointProfileObj[];
extern DMLEAF tWiFiEndPointProfileParams[];
extern DMLEAF tWiFiEndPointProfileSecurityParams[];
extern DMOBJ tWiFiDataElementsObj[];
extern DMOBJ tWiFiDataElementsNetworkObj[];
extern DMLEAF tWiFiDataElementsNetworkParams[];
extern DMLEAF tWiFiDataElementsNetworkSSIDParams[];
extern DMLEAF tWiFiDataElementsNetworkMultiAPSteeringSummaryStatsParams[];
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
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanCapabilityObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStatsParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceDefault8021QParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceSSIDtoVIDMappingParams[];
extern DMOBJ tWiFiDataElementsAssociationEventObj[];
extern DMLEAF tWiFiDataElementsAssociationEventParams[];
extern DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[];
extern DMOBJ tWiFiDataElementsDisassociationEventObj[];
extern DMLEAF tWiFiDataElementsDisassociationEventParams[];
extern DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[];

#endif
