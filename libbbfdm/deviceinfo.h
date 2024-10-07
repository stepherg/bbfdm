/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 */

#ifndef __DEVICE_INFO_H
#define __DEVICE_INFO_H

#include "libbbfdm-api/dmcommon.h"

extern DMLEAF tDeviceInfoParams[];
extern DMLEAF tDeviceInfoVendorConfigFileParams[];
extern DMLEAF tDeviceInfoMemoryStatusParams[];
extern DMOBJ tDeviceInfoProcessStatusObj[];
extern DMLEAF tDeviceInfoProcessStatusParams[];
extern DMOBJ tDeviceInfoObj[];
extern DMLEAF tDeviceInfoProcessStatusProcessParams[];
extern DMLEAF tDeviceInfoProcessorParams[];
extern DMLEAF tDeviceInfoSupportedDataModelParams[];
extern DMLEAF tDeviceInfoFirmwareImageParams[];

void _exec_reboot(const void *arg1, const void *arg2);
#endif
