/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef _FIREWALL_H
#define _FIREWALL_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ tFirewallObj[];
extern DMLEAF tFirewallParams[];
extern DMLEAF tFirewallLevelParams[];
extern DMLEAF tFirewallChainParams[];
extern DMOBJ tFirewallChainObj[];
extern DMLEAF tFirewallChainRuleParams[];
extern DMLEAF tFirewallDMZParams[];

void firewall__create_zone_section(char *s_name);

#endif
