/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#ifndef __INTERFACESTACK_H
#define __INTERFACESTACK_H

#include "libbbfdm-api/dmcommon.h"

extern DMLEAF tInterfaceStackParams[];

int browseInterfaceStackInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

#endif //__INTERFACESTACK_H
