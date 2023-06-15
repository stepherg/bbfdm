/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#ifndef __SERVICESVOICESERVICECALLCONTROL_H
#define __SERVICESVOICESERVICECALLCONTROL_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ tServicesVoiceServiceCallControlObj[];
extern DMOBJ tServicesVoiceServiceCallControlLineObj[];
extern DMLEAF tServicesVoiceServiceCallControlLineParams[];
extern DMOBJ tServicesVoiceServiceCallControlLineStatsObj[];
extern DMLEAF tServicesVoiceServiceCallControlLineStatsIncomingCallsParams[];
extern DMLEAF tServicesVoiceServiceCallControlLineStatsOutgoingCallsParams[];
extern DMLEAF tServicesVoiceServiceCallControlLineStatsRTPParams[];
extern DMLEAF tServicesVoiceServiceCallControlLineStatsDSPParams[];
extern DMLEAF tServicesVoiceServiceCallControlIncomingMapParams[];
extern DMLEAF tServicesVoiceServiceCallControlOutgoingMapParams[];
extern DMLEAF tServicesVoiceServiceCallControlGroupParams[];
extern DMLEAF tServicesVoiceServiceCallControlExtensionParams[];
extern DMLEAF tServicesVoiceServiceCallControlNumberingPlanParams[];
extern DMOBJ tServicesVoiceServiceCallControlNumberingPlanObj[];
extern DMLEAF tServicesVoiceServiceCallControlNumberingPlanPrefixInfoParams[];
extern DMOBJ tServicesVoiceServiceCallControlCallingFeaturesObj[];
extern DMOBJ tServicesVoiceServiceCallControlCallingFeaturesSetObj[];
extern DMLEAF tServicesVoiceServiceCallControlCallingFeaturesSetParams[];
extern DMLEAF tServicesVoiceServiceCallControlCallingFeaturesSetSCREJParams[];

#endif //__SERVICESVOICESERVICECALLCONTROL_H

