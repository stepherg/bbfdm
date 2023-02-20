/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __BRIDGING_H
#define __BRIDGING_H

#include "libbbf_api/dmcommon.h"

struct bridge_port_args
{
	struct uci_section *bridge_sec;
	struct uci_section *bridge_dmmap_sec;
	struct uci_section *bridge_port_sec;
	struct uci_section *bridge_port_dmmap_sec;
	bool is_management_port;
	char *br_inst;
};

extern DMOBJ tBridgingObj[];
extern DMLEAF tBridgingParams[];
extern DMOBJ tBridgingBridgeObj[];
extern DMLEAF tBridgingBridgeParams[];
extern DMLEAF tBridgingBridgeSTPParams[];
extern DMLEAF tBridgingBridgeVLANParams[];
extern DMLEAF tBridgingBridgePortParams[];
extern DMLEAF tBridgingBridgeVLANPortParams[];
extern DMOBJ tBridgingBridgePortObj[];
extern DMLEAF tBridgingBridgePortStatsParams[];
extern DMLEAF tBridgingProviderBridgeParams[];

void bridging_get_priority_list(char *uci_opt_name, void *data, char **value);
void bridging_set_priority_list(char *uci_opt_name, void *data, char *value);

#endif
