/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#ifndef __VENDOR_PLUGIN_H__
#define __VENDOR_PLUGIN_H__

#include "../dmcommon.h"

void load_vendor_dynamic_arrays(DMOBJ *entryobj, DM_MAP_VENDOR *VendorExtension[], DM_MAP_VENDOR_EXCLUDE *VendorExtensionExclude);

#endif //__VENDOR_PLUGIN_H__
