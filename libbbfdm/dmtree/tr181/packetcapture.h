/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 */

#ifndef __PACKETCAPTURE_H
#define __PACKETCAPTURE_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ tPacketCaptureObj[];
extern DMLEAF tPacketCaptureParams[];
extern DMLEAF tPacketCaptureResultParams[];

int get_operate_args_packetCapture(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int operate_Device_packetCapture(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
#endif

