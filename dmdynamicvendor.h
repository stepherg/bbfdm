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

#ifndef __DMENTRYVENDOR_H__
#define __DMENTRYVENDOR_H__

#include <libbbf_api/dmcommon.h>

void load_vendor_dynamic_arrays(struct dmctx *ctx);
void free_vendor_dynamic_arrays(DMOBJ *dm_entryobj);

#endif //__DMENTRYVENDOR_H__
