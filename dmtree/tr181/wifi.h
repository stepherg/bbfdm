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

#include "libbbf_api/dmcommon.h"

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
extern DMLEAF tWiFiDataElementsNetworkDeviceDefault8021QParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceSSIDtoVIDMappingParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceCACStatusObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceCACStatusParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceSPRuleParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceIEEE1905SecurityParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelsParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStatsParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioScanCapabilityObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRoleParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARoleParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioSpatialReuseParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSMultiAPSteeringParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSSTAObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[];
extern DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAObj[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStatsParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6CapabilitiesParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[];
extern DMLEAF tWiFiDataElementsNetworkDeviceRadioMultiAPRadioParams[];
extern DMOBJ tWiFiDataElementsAssociationEventObj[];
extern DMLEAF tWiFiDataElementsAssociationEventParams[];
extern DMOBJ tWiFiDataElementsAssociationEventAssociationEventDataObj[];
extern DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[];
extern DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataWiFi6CapabilitiesParams[];
extern DMOBJ tWiFiDataElementsDisassociationEventObj[];
extern DMLEAF tWiFiDataElementsDisassociationEventParams[];
extern DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[];
extern DMOBJ tWiFiDataElementsFailedConnectionEventObj[];
extern DMLEAF tWiFiDataElementsFailedConnectionEventParams[];
extern DMLEAF tWiFiDataElementsFailedConnectionEventFailedConnectionEventDataParams[];

#endif
