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

#ifndef __DOTSO_PLUGIN_H__
#define __DOTSO_PLUGIN_H__

#include "../dmcommon.h"

int load_dotso_plugins(DMOBJ *entryobj, const char *path);
int free_dotso_plugins(void);

#endif //__DOTSO_PLUGIN_H__
