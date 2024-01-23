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

#include "firewall.h"

static int get_rule_icmp_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *v= NULL;
	struct uci_element *e = NULL;
	char *ptr = NULL;

	dmasprintf(value, "%s", "");
	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "icmp_type", &v);
	if (v != NULL) {
		uci_foreach_element(v, e) {
			ptr = dmstrdup(*value);
			dmfree(*value);

			if (DM_STRLEN(ptr) == 0)
				dmasprintf(value, "%s", e->name);
			else {
				dmasprintf(value, "%s %s", ptr, e->name);
				dmfree(ptr);
			}
		}
	}
	return 0;
}

static int get_rule_source_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_mac", &v);
	*value = (v) ? v : "";
	return 0;
}

static int get_time_span_supported_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "mon,tue,wed,thu,fri,sat,sun";
	return 0;
}

static int get_time_span_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "weekdays", &v);
	*value = (v) ? v : "";
	return 0;
}

static int get_time_span_start_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "start_time", &v);
	*value = (v) ? v : "";
	return 0;
}

static int get_time_span_stop_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "stop_time", &v);
	*value = (v) ? v : "";
	return 0;
}

static int set_rule_icmp_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int i;
	size_t length;
	char **devices = NULL;

	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "icmp_type", "");
			devices = strsplit(value, " ", &length);
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "icmp_type", devices[i]);
			break;
	}
	return 0;
}

static int set_rule_source_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_mac", value);
			break;
	}
	return 0;
}

static int set_time_span_supported_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int set_time_span_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "weekdays", value);
			break;
	}
	return 0;
}

static int set_time_span_start_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "start_time", value);
			break;
	}
	return 0;
}

static int set_time_span_stop_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "stop_time", value);
			break;
	}
	return 0;
}

static int test__get_firewall_expriydate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "2030-07-02T14:33:51Z";
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Firewall.Chain.{i}.Rule.{i}. *** */
DMOBJ tTEST_FirewallChainRuleObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"X_TEST_COM_TimeSpan", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tTEST_FirewallChainRuleTimeSpanParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tTEST_FirewallChainRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"X_TEST_COM_ICMPType", &DMWRITE, DMT_STRING, get_rule_icmp_type, set_rule_icmp_type, BBFDM_BOTH},
{"X_TEST_COM_SourceMACAddress", &DMWRITE, DMT_STRING, get_rule_source_mac, set_rule_source_mac, BBFDM_BOTH},
{"ExpiryDate", &DMWRITE, DMT_TIME, test__get_firewall_expriydate, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tTEST_FirewallChainRuleTimeSpanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SupportedDays", &DMWRITE, DMT_STRING, get_time_span_supported_days, set_time_span_supported_days, BBFDM_BOTH},
{"Days", &DMWRITE, DMT_STRING, get_time_span_days, set_time_span_days, BBFDM_BOTH},
{"StartTime", &DMWRITE, DMT_STRING, get_time_span_start_time, set_time_span_start_time, BBFDM_BOTH},
{"StopTime", &DMWRITE, DMT_STRING, get_time_span_stop_time, set_time_span_stop_time, BBFDM_BOTH},
{0}
};

