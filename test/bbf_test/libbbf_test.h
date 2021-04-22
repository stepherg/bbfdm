/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __LIBBBFD_TEST_H
#define __LIBBBFD_TEST_H

extern DMOBJ tDynamicManagementServerObj[];
extern DMLEAF tDynamicManagementServerParams[];
extern DMLEAF tManagementServerInformParameterParams[];
extern DMOBJ tDynamicDeviceObj[];
extern DMLEAF tX_IOPSYS_EU_SyslogParam[];

opr_ret_t DynamicDevicePingOperate(struct dmctx *dmctx, char *path, json_object *input);
opr_ret_t DynamicDeviceRebootOperate(struct dmctx *dmctx, char *path, json_object *input);

#endif //__LIBBBFD_TEST_H

