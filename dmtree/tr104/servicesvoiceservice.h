/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#ifndef __SERVICESVOICESERVICE_H
#define __SERVICESVOICESERVICE_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tServicesObj[];
extern DMOBJ tServicesVoiceServiceObj[];
extern DMLEAF tServicesVoiceServiceParams[];
extern DMOBJ tServicesVoiceServiceCapabilitiesObj[];
extern DMLEAF tServicesVoiceServiceCapabilitiesParams[];
extern DMLEAF tServicesVoiceServiceReservedPortsParams[];
extern DMOBJ tServicesVoiceServicePOTSObj[];
extern DMLEAF tServicesVoiceServicePOTSParams[];
extern DMOBJ tServicesVoiceServiceSIPObj[];
extern DMOBJ tServicesVoiceServiceCallControlObj[];
extern DMLEAF tServicesVoiceServiceCallLogParams[];
extern DMOBJ tServicesVoiceServiceVoIPProfileObj[];
extern DMLEAF tServicesVoiceServiceVoIPProfileParams[];
extern DMLEAF tServicesVoiceServiceCodecProfileParams[];

int browseVoiceServiceSIPProviderInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int delObjVoiceServiceSIPProvider(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

#endif //__SERVICESVOICESERVICE_H

