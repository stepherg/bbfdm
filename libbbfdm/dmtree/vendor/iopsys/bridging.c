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

#include "dmlayer.h"
#include "bridging.h"

struct bridge_port_args
{
	struct uci_section *bridge_sec;
	struct uci_section *bridge_dmmap_sec;
	struct uci_section *bridge_port_sec;
	struct uci_section *bridge_port_dmmap_sec;
	bool is_management_port;
	char *br_inst;
};

static int get_BridgingBridgePort_Egress_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bridging___get_priority_list(((struct bridge_port_args *)data)->bridge_port_sec, "egress_qos_mapping", data, value);
	return 0;
}

static int set_BridgingBridgePort_Egress_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *type = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt_list(ctx, value, 8, 8, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
			if (((struct bridge_port_args *)data)->is_management_port || DM_STRLEN(type) == 0)
				return FAULT_9007;

			return 0;
		case VALUESET:
			bridging___set_priority_list(((struct bridge_port_args *)data)->bridge_port_sec, "egress_qos_mapping", data, value);
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMLEAF tIOPSYS_BridgingBridgePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"EgressPriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Egress_PriorityRegeneration, set_BridgingBridgePort_Egress_PriorityRegeneration, BBFDM_BOTH},
{0}
};
