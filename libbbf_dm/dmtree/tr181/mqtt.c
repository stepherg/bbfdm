/*
 * Copyright (C) 2022 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 */

#include "mqtt.h"

static bool duplicate_entry_exist(char *name, char *section_type)
{
	bool exist = false;
	struct uci_section *s = NULL, *stmp = NULL;

	uci_foreach_sections_safe("mosquitto", section_type, stmp, s) {
		char *sec_name = section_name(s);
		if (DM_STRCMP(name, sec_name) == 0) {
			exist = true;
			break;
		}
	}

	return exist;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addMQTTBroker(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_broker = NULL;
	char sec_name[40];

	snprintf(sec_name, sizeof(sec_name), "broker_%s", *instance);

	if (dmuci_add_section("mosquitto", "listener", &s) == 0) {
		dmuci_rename_section_by_section(s, sec_name);
		dmuci_set_value_by_section(s, "enabled", "0");
		dmuci_set_value_by_section(s, "port", "1883");
		dmuci_add_section_bbfdm("dmmap_mqtt", "listener", &dmmap_broker);
		dmuci_set_value_by_section(dmmap_broker, "section_name", sec_name);
		dmuci_set_value_by_section(dmmap_broker, "listener_instance", *instance);
	}

	return 0;
}

static int delMQTTBroker(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
		dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("mosquitto", "listener", stmp, s) {
			struct uci_section *dmmap_section = NULL;
			get_dmmap_section_of_config_section("dmmap_mqtt", "listener", section_name(s), &dmmap_section);
			dmuci_delete_by_section(s, NULL, NULL);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
static int browseMQTTBrokerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("mosquitto", "listener", "dmmap_mqtt", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "listener_instance", "listener_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_MQTT_BrokerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseMQTTBrokerInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_MQTTBroker_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "listener_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_MQTTBroker_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "listener_alias", value);
			return 0;
	}
	return 0;
}

static int get_MQTTBroker_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "0");
	return 0;
}

static int set_MQTTBroker_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_MQTTBroker_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "section_name", value);
	return 0;
}

static int set_MQTTBroker_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *curr_name = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;

			// Check if the value is empty
			if (*value == '\0')
				return FAULT_9007;

			// Check if new name is same as current name
			curr_name = section_name(((struct dmmap_dup *)data)->config_section);
			if (DM_STRCMP(curr_name, value) == 0)
				break;

			// check if duplicate entry already exists
			if (duplicate_entry_exist(value, "listener"))
				return FAULT_9001;

			break;
		case VALUESET:
			// If new name is same as current name then nothing to do
			curr_name = section_name(((struct dmmap_dup *)data)->config_section);
			if (DM_STRCMP(curr_name, value) == 0)
				break;

			// Update mosquitto config
			if (0 != dmuci_rename_section_by_section(((struct dmmap_dup *)data)->config_section, value))
				return FAULT_9001;

			// Update dmmap_mqtt file
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "section_name", value);

			break;
	}
	return 0;
}

static int get_MQTTBroker_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "port", value);
	return 0;
}

static int set_MQTTBroker_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "port", value);
			break;
	}
	return 0;
}

static int get_MQTTBroker_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *intf = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface", &intf);
	if (DM_STRLEN(intf) == 0)
		return 0;

	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", intf, value);
	return 0;
}

static int set_MQTTBroker_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *iface = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &iface);
			if (DM_STRLEN(iface) != 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "interface", iface);
			break;
	}
	return 0;
}

static int get_MQTTBroker_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "username", value);
	return 0;
}

static int set_MQTTBroker_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;

			// Check if the value is empty
			if (*value == '\0')
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "username", value);
			break;
	}
	return 0;
}

static int get_MQTTBroker_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_MQTTBroker_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "password", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                        OBJ & LEAF DEFINITION
**********************************************************************************************************************************/
/* *** Device.MQTT.Broker. *** */
DMOBJ tMQTTObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Broker", &DMWRITE, addMQTTBroker, delMQTTBroker, NULL, browseMQTTBrokerInst, NULL, NULL, NULL, tMQTTBrokerParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Name", NULL}, "2.10"},
{0}
};

DMLEAF tMQTTParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BrokerNumberOfEntries", &DMREAD, DMT_UNINT, get_MQTT_BrokerNumberOfEntries, NULL, BBFDM_BOTH, "2.10"},
{0}
};

DMLEAF tMQTTBrokerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_MQTTBroker_Enable, set_MQTTBroker_Enable, BBFDM_BOTH, "2.10"},
{"Alias", &DMWRITE, DMT_STRING, get_MQTTBroker_Alias, set_MQTTBroker_Alias, BBFDM_BOTH, "2.10"},
{"Name", &DMWRITE, DMT_STRING, get_MQTTBroker_Name, set_MQTTBroker_Name, BBFDM_BOTH, "2.10"},
//{"Status", &DMREAD, DMT_STRING, get_MQTTBroker_Status, NULL, BBFDM_BOTH, "2.10"},
{"Port", &DMWRITE, DMT_UNINT, get_MQTTBroker_Port, set_MQTTBroker_Port, BBFDM_BOTH, "2.10"},
{"Interface", &DMWRITE, DMT_STRING, get_MQTTBroker_Interface, set_MQTTBroker_Interface, BBFDM_BOTH, "2.10"},
{"Username", &DMWRITE, DMT_STRING, get_MQTTBroker_Username, set_MQTTBroker_Username, BBFDM_BOTH, "2.10"},
{"Password", &DMWRITE, DMT_STRING, get_MQTTBroker_Password, set_MQTTBroker_Password, BBFDM_BOTH, "2.10"},
{0}
};

