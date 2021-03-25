/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "device.h"
#include "x_iopsys_eu_igmp.h"
#include "x_iopsys_eu_mld.h"

DMOBJ tIOPSYS_DeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{BBF_VENDOR_PREFIX"IGMP", &DMREAD, NULL, NULL, "file:/etc/config/mcast", NULL, NULL, NULL, X_IOPSYS_EU_IGMPObj, X_IOPSYS_EU_IGMPParams, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"MLD", &DMREAD, NULL, NULL, "file:/etc/config/mcast", NULL, NULL, NULL, X_IOPSYS_EU_MLDObj, X_IOPSYS_EU_MLDParams, NULL, BBFDM_BOTH},
{0}
};
