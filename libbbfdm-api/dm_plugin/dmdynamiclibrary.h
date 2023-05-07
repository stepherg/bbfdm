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

#ifndef __DMENTRYLIBRARY_H__
#define __DMENTRYLIBRARY_H__

#include "../dmcommon.h"

#define LIBRARY_FOLDER_PATH "/usr/lib/bbfdm"

int load_library_dynamic_arrays(struct dmctx *ctx);
void free_library_dynamic_arrays(DMOBJ *dm_entryobj);

#endif //__DMENTRYLIBRARY_H__
