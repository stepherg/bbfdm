/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 *
 */

#ifndef __IPLAYERCAP_H
#define __IPLAYERCAP_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ tIPLayerCapacityObj[];
extern DMLEAF tIPLayerCapacityParams[];
extern DMLEAF tIPLayerCapacityModalResultParams[];
extern DMLEAF tIPLayerCapacityIncrementalResultParams[];

int operate_IPDiagnostics_IPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_operate_args_IPDiagnostics_IPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPDiagnosticsIPLayerCapacity_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPDiagnosticsIPLayerCapacity_MaxConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPDiagnosticsIPLayerCapacity_MaxIncrementalResult(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPDiagnosticsIPLayerCapacity_ControlProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPDiagnosticsIPLayerCapacity_SupportedMetrics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#endif

