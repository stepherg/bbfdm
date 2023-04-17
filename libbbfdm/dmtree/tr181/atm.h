/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#ifndef __ATM_H
#define __ATM_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ tATMObj[];
extern DMOBJ tATMLinkObj[];
extern DMLEAF tATMLinkParams[];
extern DMLEAF tATMLinkStatsParams[];

void remove_device_from_interface(struct uci_section *interface_s, char *device);

#endif
