/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 */

#ifndef __SELFTEST_H
#define __SELFTEST_H

#include "libbbfdm-api/dmcommon.h"

extern DMLEAF tSelfTestParams[];

int get_operate_args_SelfTest(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int operate_Device_SelfTest(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
#endif

