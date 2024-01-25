/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#ifndef __PPP_H
#define __PPP_H

#include "libbbfdm-api/dmcommon.h"

#define IPCP 0
#define IPCPv6 1

extern DMOBJ tPPPObj[];
extern DMLEAF tPPPParams[];
extern DMOBJ tPPPInterfaceObj[];
extern DMLEAF tPPPInterfaceParams[];
extern DMLEAF tPPPInterfacePPPoEParams[];
extern DMLEAF tPPPInterfaceIPCPParams[];
extern DMLEAF tPPPInterfaceIPv6CPParams[];
extern DMLEAF tPPPInterfaceStatsParams[];

#endif
