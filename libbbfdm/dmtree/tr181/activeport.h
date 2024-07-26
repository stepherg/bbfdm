/*
 * Copyright (C) 2024 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Mohd Husaam Mehdi <husaam.mehdi@iopsys.eu>
 */

#ifndef __ACTIVE_PORT_H
#define __ACTIVE_PORT_H

#include "libbbfdm-api/dmcommon.h"

extern DMLEAF tIPActivePortParams[];
int browseIPActivePortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

#endif

