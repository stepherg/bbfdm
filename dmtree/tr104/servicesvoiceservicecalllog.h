/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#ifndef __SERVICESVOICESERVICECALLLOG_H
#define __SERVICESVOICESERVICECALLLOG_H

#include "libbbf_api/dmcommon.h"

extern DMOBJ tServicesVoiceServiceCallLogObj[];
extern DMLEAF tServicesVoiceServiceCallLogParams[];
extern DMOBJ tServicesVoiceServiceCallLogSessionObj[];
extern DMLEAF tServicesVoiceServiceCallLogSessionParams[];
extern DMOBJ tServicesVoiceServiceCallLogSessionDestinationObj[];
extern DMOBJ tServicesVoiceServiceCallLogSessionSourceObj[];
extern DMOBJ tServicesVoiceServiceCallLogSessionDestinationDSPObj[];
extern DMOBJ tServicesVoiceServiceCallLogSessionSourceDSPObj[];
extern DMLEAF tServicesVoiceServiceCallLogSessionDestinationDSPCodecParams[];
extern DMLEAF tServicesVoiceServiceCallLogSessionSourceDSPCodecParams[];
extern DMLEAF tServicesVoiceServiceCallLogSessionSourceRTPParams[];

#endif //__SERVICESVOICESERVICECALLLOG_H

