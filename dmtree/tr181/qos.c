/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Rohit Topno <r.topno@gxgroup.eu>
 */

#include "qos.h"

/*************************************************************
 * ENTRY METHOD
*************************************************************/
static int get_linker_qqueue(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? dmstrdup(section_name(((struct dmmap_dup *)data)->config_section)) : "";
	return 0;
}

static int browseQoSClassificationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *value = NULL;
	char *ret = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "classify", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		//synchronizing option src_ip of uci classify section to src_mask/src_ip of dmmap's classify section
		dmuci_get_value_by_section_string(p->config_section, "src_ip", &value);
		//checking if src_ip is an ip-prefix or ip address and synchronizing accordingly
		ret = DM_LSTRSTR(value, "/");
		if (ret)
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "src_mask", value);
		else
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "src_ip", value);

		//synchronizing option dest_ip of uci classify section to dest_mask/dest_ip of dmmap's classify section
		dmuci_get_value_by_section_string(p->config_section, "dest_ip", &value);
		//checking if src_ip is an ip-prefix or ip address and synchronizing accordingly
		ret = DM_LSTRSTR(value, "/");
		if (ret)
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "dest_mask", value);
		else
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "dest_ip", value);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "classify_instance", "classifyalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseQoSPolicerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "policer", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "policer_instance", "policeralias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.QoS.Queue.{i}.!UCI:qos/queue/dmmap_qos*/
static int browseQoSQueueInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "queue", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "queueinstance", "queuealias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseQoSQueueStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_qstats", "queue_stats", s) {

		inst = handle_instance(dmctx, parent_node, s, "q_instance", "q_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseQoSShaperInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "shaper", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "shaperinstance", "shaperalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
 * ADD & DEL OBJ
*************************************************************/
static int addObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;
	char buf[32] = {0};

	snprintf(buf, sizeof(buf), "classify_%s", *instance);

	dmuci_add_section("qos", "classify", &s);
	dmuci_rename_section_by_section(s, buf);
	dmuci_set_value_by_section(s, "enable", "0");

	dmuci_add_section_bbfdm("dmmap_qos", "classify", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", buf);
	dmuci_set_value_by_section(dmmap, "classify_instance", *instance);
	return 0;
}

static int delObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
		dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("qos", "classify", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjQoSPolicer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	dmuci_add_section("qos", "policer", &s);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "committed_rate", "0");
	dmuci_set_value_by_section(s, "committed_burst_size", "0");
	dmuci_set_value_by_section(s, "excess_burst_size", "0");
	dmuci_set_value_by_section(s, "peak_rate", "0");
	dmuci_set_value_by_section(s, "peak_burst_size", "0");
	dmuci_set_value_by_section(s, "meter_type", "0");
	dmuci_set_value_by_section(s, "name", section_name(s));

	dmuci_add_section_bbfdm("dmmap_qos", "policer", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "policer_instance", *instance);
	return 0;
}

static int delObjQoSPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *sec = NULL;
	char *p_name = NULL;

	switch (del_action) {
		case DEL_INST:
			// store section name to update corresponding classification
			// section if any
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", &p_name);

			// Set the Classification.Policer to blank if corresponding
			// Policer instance has been deleted
			uci_foreach_option_eq("qos", "classify", "policer", p_name, sec) {
				dmuci_set_value_by_section(sec, "policer", "");
			}

			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("qos", "policer", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_qos", "policer", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}

			// Since all policer have been deleted, we can safely set the
			// value of all Classification.Policer params to empty
			uci_foreach_sections("qos", "classify", sec) {
				dmuci_set_value_by_section(sec, "policer", "");
			}
			break;
	}
	return 0;
}

static int addObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section  *dmmap = NULL, *s = NULL;

	dmuci_add_section("qos", "queue", &s);
	dmuci_set_value_by_section(s, "enable", "false");
	dmuci_set_value_by_section(s, "weight", "0");
	dmuci_set_value_by_section(s, "precedence", "1");
	dmuci_set_value_by_section(s, "burst_size", "0");
	dmuci_set_value_by_section(s, "scheduling", "SP");
	dmuci_set_value_by_section(s, "rate", "-1");

	dmuci_add_section_bbfdm("dmmap_qos", "queue", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "queueinstance", *instance);
	return 0;
}

static int delObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("qos", "queue", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *qstats_sec = NULL;

	dmuci_add_section_bbfdm("dmmap_qstats", "queue_stats", &qstats_sec);
	dmuci_set_value_by_section(qstats_sec, "q_instance", *instance);
	return 0;
}

static int delObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_qstats", "queue_stats", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section  *dmmap = NULL, *s = NULL;

	dmuci_add_section("qos", "shaper", &s);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "burst_size", "0");
	dmuci_set_value_by_section(s, "rate", "0");

	dmuci_add_section_bbfdm("dmmap_qos", "shaper", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "shaperinstance", *instance);
	return 0;
}

static int delObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("qos", "shaper", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* COMMON Functions
**************************************************************/
static int get_QInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname = NULL;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ifname", &ifname);

	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", ifname, value);
	if (!(*value) || (*value)[0] == 0)
		adm_entry_get_linker_param(ctx, "Device.PPP.Interface.", ifname, value);
	if (!(*value) || (*value)[0] == 0)
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", ifname, value);
	if (!(*value) || (*value)[0] == 0)
		adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", ifname, value);

	return 0;
}

static int set_QInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.IP.Interface.",
			"Device.PPP.Interface.",
			"Device.Ethernet.Interface.",
			"Device.WiFi.Radio.",
			NULL};
	char *linker = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, NULL))
			return FAULT_9007;

		if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
			return FAULT_9007;

		break;
	case VALUESET:
		adm_entry_get_linker_value(ctx, value, &linker);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ifname", linker ? linker : "");
		break;
	}
	return 0;
}

/*************************************************************
 * GET & SET PARAM
*************************************************************/
/*#Device.QoS.ClassificationNumberOfEntries!UCI:qos/classify/*/
static int get_QClassificationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseQoSClassificationInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_QPolicerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseQoSPolicerInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.QoS.QueueNumberOfEntries!UCI:qos/queue*/
static int get_QQueueNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseQoSQueueInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_QQueueStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseQoSQueueStatsInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_QShaperNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseQoSShaperInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "1");
	return 0;
}

static int set_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", (b) ? "1" : "0");
		break;
	}
	return 0;
}

static int get_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "dest_mask", value);
	return 0;
}

static int set_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dest_ip = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 49 , NULL, IPPrefix))
			return FAULT_9007;
		break;
	case VALUESET:
		/* Set received value of dest. mask in /etc/bbfdm/dmmap/dmmap_qos.
		 * If received value is an empty string then get the value of dest. ip. from dmmap_qos and set it as dest_ip in qos uci file.
		 * If both received value of dest. mask and the dest. ip from dmmap_qos is empty then delete the dest_ip option from qos uci file.
		 * Note: setting an empty string as option value in uci or dmmap will delete that option.
		 * */
		dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "dest_mask", value);
		if (value[0] == '\0') {
			//get source ip value from /etc/bbfdm/dmmap/dmmap_qos and set as dest_ip
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "dest_ip", &dest_ip);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", dest_ip);
		} else {
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", value);
		}
		break;
	}
	return 0;
}

static int get_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "src_mask", value);
	return 0;
}

static int set_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src_ip = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 49 , NULL, IPPrefix))
			return FAULT_9007;
		break;
	case VALUESET:
		/* Set received value of src. mask in /etc/bbfdm/dmmap/dmmap_qos.
		 * If received value is an empty string then get the value of src. ip. from dmmap_qos and set it as src_ip in qos uci file.
		 * If both received value of src. mask and the src. ip from dmmap_qos is empty then  delete the src_ip option from qos uci file.
		 * Note: setting an empty string as option value in uci or dmmap will delete that option.
		 * */
		dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "src_mask", value);
		if (value[0] == '\0') {
			//get source ip value from /etc/bbfdm/dmmap/dmmap_qos and set as src_ip
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "src_ip", &src_ip);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_ip", src_ip);
		} else {
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_ip", value);
		}
		break;
	}
	return 0;
}

static int get_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "classifyalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 64, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "classifyalias", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QInterface(refparam, ctx, data, instance, value);
}

static int set_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_QInterface(refparam, ctx, data, instance, value, action);
}

static int get_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "dest_ip", value);
	return 0;
}

static int set_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dest_mask = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 45 , NULL, IPAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		/* If dest. mask parameter from /etc/bbfdm/dmmap/dmmap_qos is present, set this (dest. mask) value as dest_ip in qos uci file
		 * Else write received dest. ip to /etc/bbfdm/dmmap/dmmap_qos and qos uci file.
		 * Also write the received dest. ip value to /etc/bbfdm/dmmap/dmmap_qos.
		 * */
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "dest_mask", &dest_mask);

		if (dest_mask[0] != '\0') {
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", dest_mask);
		} else 	{
			//note: setting an option to an empty string will delete that option
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", value);
		}
		dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "dest_ip", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "src_ip", value);
	return 0;
}

static int set_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src_mask = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 45 , NULL, IPAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		/*if source mask parameter from /etc/bbfdm/dmmap/dmmap_qos is present, set this (source mask) value as src_ip in qos uci file
		Else write received source ip to /etc/bbfdm/dmmap/dmmap_qos and qos uci file.
		also write the received source ip value to /etc/bbfdm/dmmap/dmmap_qos.
		*/
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "src_mask", &src_mask);

		if (src_mask[0] != '\0') {
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_ip", src_mask);
		} else 	{
			//note: setting an option to an empty string will delete that option
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_ip", value);
		}
		dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "src_ip", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "proto", "-1");
	return 0;
}

static int set_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","255"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "proto", value);
		break;
	}
	return 0;
}


static int get_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "dest_port", "-1");
	return 0;
}

static int set_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_port", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "dest_port_range", "-1");
	return 0;
}

static int set_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_port_range", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "src_port", "-1");
	return 0;
}

static int set_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_port", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "src_port_range", "-1");
	return 0;
}

static int set_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_port_range", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_mac", value);
	return 0;
}

static int set_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 17, NULL, MACAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_mac", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dst_mac", value);
	return 0;
}

static int set_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 17, NULL, MACAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dst_mac", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "ethertype", "-1");
	return 0;
}

static int set_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ethertype", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_vendor_class_id", value);
	return 0;
}

static int set_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 255, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		// Set received value of source Vendor ClassID in /etc/config/qos.
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_vendor_class_id", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dst_vendor_class_id", value);
	return 0;
}

static int set_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 255, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		// Set received value of Destination Vendor ClassID in /etc/config/qos.
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dst_vendor_class_id", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *srcclid = NULL, hex[256] = {0};

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_client_id", &srcclid);

	if (srcclid && *srcclid)
		convert_string_to_hex(srcclid, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_to_string(value, res, sizeof(res));
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_client_id", res);
			break;
	}
	return 0;
}

static int get_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dstclid = NULL, hex[256] = {0};

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dst_client_id", &dstclid);

	if (dstclid && *dstclid)
		convert_string_to_hex(dstclid, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_to_string(value, res, sizeof(res));
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dst_client_id", res);
			break;
	}
	return 0;
}

static int get_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *srcusrclid = NULL, hex[256] = {0};

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_user_class_id", &srcusrclid);

	if (srcusrclid && *srcusrclid)
		convert_string_to_hex(srcusrclid, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char res[256] = {0};

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		convert_hex_to_string(value, res, sizeof(res));
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_user_class_id", res);
		break;
	}
	return 0;
}

static int get_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dstusrclid = NULL, hex[256] = {0};

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dst_user_class_id", &dstusrclid);

	if (dstusrclid && *dstusrclid)
		convert_string_to_hex(dstusrclid, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char res[256] = {0};

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		convert_hex_to_string(value, res, sizeof(res));
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dst_user_class_id", res);
		break;
	}
	return 0;
}

static int get_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "ip_len_min", "0");
	return 0;
}

static int set_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"0",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ip_len_min", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "ip_len_max", "0");
	return 0;
}

static int set_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"0",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ip_len_max", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "dscp_filter", "-1");
	return 0;
}

static int set_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","63"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dscp_filter", value);
		break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DSCPMark!UCI:qos/classify,@i-1/dscp*/
static int get_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "dscp_mark", "-1");
	return 0;
}

static int set_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dscp_mark", value);
		break;
	}
	return 0;
}
static int get_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "pcp_check", "-1");
	return 0;
}

static int set_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "pcp_check", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "vid_check", "-1");
	return 0;
}

static int set_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "vid_check", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "traffic_class", "-1");
	return 0;
}

static int set_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "traffic_class", value);
		break;
	}
	return 0;
}

static int get_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;
	char *p_inst = NULL;
	struct uci_section *dmmap_s = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "policer", &linker);
	get_dmmap_section_of_config_section_eq("dmmap_qos", "policer", "section_name", linker, &dmmap_s);
	if (dmmap_s != NULL) {
		dmuci_get_value_by_section_string(dmmap_s, "policer_instance", &p_inst);
		dmasprintf(value, "Device.QoS.Policer.%s", p_inst);
	}

	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_s = NULL;
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRNCMP(value, "Device.QoS.Policer.", 19) == 0 && strlen(value) >= 20) {
				char link_inst[8] = {0};
				snprintf(link_inst, sizeof(link_inst), "%c", value[19]); // TODO implementation need to be revisited
				get_dmmap_section_of_config_section_eq("dmmap_qos", "policer", "policer_instance", link_inst, &dmmap_s);
				dmuci_get_value_by_section_string(dmmap_s, "section_name", &linker);
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "policer", linker);
			}

			break;
	}
	return 0;
}

static int get_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "1");
	return 0;
}

static int set_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_QoSPolicer_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enable", value);
	*value = (*value[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "policeralias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "policeralias", value);
			break;
	}
	return 0;
}

static int get_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "committed_rate", value);
	return 0;
}

static int set_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "committed_rate", value);
			break;
	}
	return 0;
}

static int get_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "committed_burst_size", value);
	return 0;
}

static int set_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "committed_burst_size", value);
			break;
	}
	return 0;
}

static int get_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "excess_burst_size", value);
	return 0;
}

static int set_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "excess_burst_size", value);
			break;
	}
	return 0;
}

static int get_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "peak_rate", value);
	return 0;
}

static int set_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "peak_rate", value);
			break;
	}
	return 0;
}

static int get_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "peak_burst_size", value);
	return 0;
}

static int set_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "peak_burst_size", value);
			break;
	}
	return 0;
}

static int get_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "meter_type", value);
	if (DM_LSTRNCMP(*value, "1", 1) == 0)
		*value = "SingleRateThreeColor";
	else if (DM_LSTRNCMP(*value, "2", 1) == 0)
		*value = "TwoRateThreeColor";
	else
		*value = "SimpleTokenBucket";

	return 0;
}

static int set_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if ((DM_LSTRCMP(value, "SimpleTokenBucket") != 0) && (DM_LSTRCMP(value, "SingleRateThreeColor") != 0) && (DM_LSTRCMP(value, "TwoRateThreeColor") != 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "SimpleTokenBucket") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "meter_type", "0");
			else if (DM_LSTRCMP(value, "SingleRateThreeColor") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "meter_type", "1");
			else if (DM_LSTRCMP(value, "TwoRateThreeColor") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "meter_type", "2");
			break;
	}
	return 0;
}

static int get_QoSPolicer_PossibleMeterTypes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "SimpleTokenBucket,SingleRateThreeColor,TwoRateThreeColor";
	return 0;
}

static int get_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "1");
	return 0;
}

static int set_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_QoSQueue_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enable", value);
	*value = (*value[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "queuealias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "queuealias", value);
			break;
	}
	return 0;
}

static int get_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "traffic_class", value);
	return 0;
}

static int set_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "traffic_class", value);
			break;
	}
	return 0;
}

static int get_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QInterface(refparam, ctx, data, instance, value);
}

static int set_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_QInterface(refparam, ctx, data, instance, value, action);
}

static int get_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "weight", "0");
	return 0;
}

static int set_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
			case VALUESET:
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "weight", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Queue.{i}.Precedence!UCI:qos/queue,@i-1/precedence*/
static int get_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "precedence", "1");
	return 0;
}

static int set_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "precedence", value);
			break;
	}
	return 0;
}

static int get_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "scheduling", "SP");
	return 0;
}

static int set_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SchedulerAlgorithm, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "scheduling", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Queue.{i}.ShapingRate!UCI:qos/class,@i-1/rate*/
static int get_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "rate", "-1");
	return 0;
}


static int set_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "rate", value);
			break;
	}
	return 0;
}

static int get_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "burst_size", "0");
	return 0;
}

static int set_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "burst_size", value);
			break;
	}
	return 0;
}

static int get_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enabled", "0");
	return 0;
}

static int set_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_QoSQueueStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_QoSQueueStats_Enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;

}

static int get_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "alias", value);
			break;
	}
	return 0;
}

static int get_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *queue_link = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "queue", &queue_link);
	adm_entry_get_linker_param(ctx, "Device.QoS.Queue.", queue_link, value);
	return 0;
}

static int set_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.QoS.Queue.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section((struct uci_section *)data, "queue", linker ? linker : "");
			break;
	}
	return 0;
}

static int get_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *intf_link = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &intf_link);
	adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", intf_link, value);
	if (!(*value) || (*value)[0] == 0)
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", intf_link, value);
	if (!(*value) || (*value)[0] == 0)
		adm_entry_get_linker_param(ctx, "Device.PPP.Interface.", intf_link, value);

	return 0;
}

static int set_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.Ethernet.Interface.",
			"Device.IP.Interface.",
			"Device.PPP.Interface.",
			NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section((struct uci_section *)data, "interface", linker ? linker : "");
			break;
	}
	return 0;
}

static int get_QoSQueueStats_value(void *data, char *option, char **value)
{
	char *queue_link = NULL, *intf_link = NULL;

	*value = "0";
	dmuci_get_value_by_section_string((struct uci_section *)data, "queue", &queue_link);
	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &intf_link);

	if (queue_link && *queue_link && intf_link && *intf_link) {
		json_object *res = NULL;
		char queue_id[8] = {0};

		snprintf(queue_id, sizeof(queue_id), "%c", queue_link[2]);
		dmubus_call("qos", "queue_stats", UBUS_ARGS{{"ifname", intf_link, String}, {"qid", queue_id, Integer}}, 2, &res);
		DM_ASSERT(res, *value = "0");
		json_object *queue_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "queues");
		*value = dmjson_get_value(queue_obj, 1, option);
	}
	return 0;
}

static int get_QoSQueueStats_OutputPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QoSQueueStats_value(data, "tx_packets", value);
}

static int get_QoSQueueStats_OutputBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QoSQueueStats_value(data, "tx_bytes", value);
}

static int get_QoSQueueStats_DroppedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QoSQueueStats_value(data, "tx_dropped_packets", value);
}

static int get_QoSQueueStats_DroppedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QoSQueueStats_value(data, "tx_dropped_bytes", value);
}

static int get_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "1");
	return 0;
}

static int set_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_QoSShaper_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enable", value);
	*value = (*value[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "shaperalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dmmap_dup *)data)->dmmap_section, "shaperalias", value);
			break;
	}
	return 0;
}

static int get_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_QInterface(refparam, ctx, data, instance, value);
}

static int set_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_QInterface(refparam, ctx, data, instance, value, action);
}

static int get_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "rate", "-1");
	return 0;
}

static int set_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "rate", value);
			break;
	}
	return 0;
}

static int get_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "burst_size", "0");
	return 0;
}

static int set_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "burst_size", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.QoS. *** */
DMOBJ tQoSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Classification", &DMWRITE, addObjQoSClassification, delObjQoSClassification, NULL, browseQoSClassificationInst, NULL, NULL, NULL, tQoSClassificationParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
{"QueueStats", &DMWRITE, addObjQoSQueueStats, delObjQoSQueueStats, NULL, browseQoSQueueStatsInst, NULL, NULL, NULL, tQoSQueueStatsParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Queue", "Interface", NULL}, "2.0"},
//{"App", &DMWRITE, addObjQoSApp, delObjQoSApp, NULL, browseQoSAppInst, NULL, NULL, NULL, tQoSAppParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
//{"Flow", &DMWRITE, addObjQoSFlow, delObjQoSFlow, NULL, browseQoSFlowInst, NULL, NULL, NULL, tQoSFlowParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
{"Policer", &DMWRITE, addObjQoSPolicer, delObjQoSPolicer, NULL, browseQoSPolicerInst, NULL, NULL, NULL, tQoSPolicerParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
{"Queue", &DMWRITE, addObjQoSQueue, delObjQoSQueue, NULL, browseQoSQueueInst, NULL, NULL, NULL, tQoSQueueParams, get_linker_qqueue, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
{"Shaper", &DMWRITE, addObjQoSShaper, delObjQoSShaper, NULL, browseQoSShaperInst, NULL, NULL, NULL, tQoSShaperParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tQoSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ClassificationNumberOfEntries", &DMREAD, DMT_UNINT, get_QClassificationNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"QueueStatsNumberOfEntries", &DMREAD, DMT_UNINT, get_QQueueStatsNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"ShaperNumberOfEntries", &DMREAD, DMT_UNINT, get_QShaperNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"QueueNumberOfEntries", &DMREAD, DMT_UNINT, get_QQueueNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
//{"MaxClassificationEntries", &DMREAD, DMT_UNINT, get_QMaxClassificationEntries, NULL, BBFDM_BOTH, "2.0"},
//{"MaxAppEntries", &DMREAD, DMT_UNINT, get_QMaxAppEntries, NULL, BBFDM_BOTH, "2.0"},
//{"AppNumberOfEntries", &DMREAD, DMT_UNINT, get_QAppNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
//{"MaxFlowEntries", &DMREAD, DMT_UNINT, get_QMaxFlowEntries, NULL, BBFDM_BOTH, "2.0"},
//{"FlowNumberOfEntries", &DMREAD, DMT_UNINT, get_QFlowNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
//{"MaxPolicerEntries", &DMREAD, DMT_UNINT, get_QMaxPolicerEntries, NULL, BBFDM_BOTH, "2.0"},
{"PolicerNumberOfEntries", &DMREAD, DMT_UNINT, get_QPolicerNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
//{"MaxQueueEntries", &DMREAD, DMT_UNINT, get_QMaxQueueEntries, NULL, BBFDM_BOTH, "2.0"},
//{"MaxShaperEntries", &DMREAD, DMT_UNINT, get_QMaxShaperEntries, NULL, BBFDM_BOTH, "2.0"},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QDefaultForwardingPolicy, set_QDefaultForwardingPolicy, BBFDM_BOTH, "2.0"},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QDefaultTrafficClass, set_QDefaultTrafficClass, BBFDM_BOTH, "2.0"},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QDefaultPolicer, set_QDefaultPolicer, BBFDM_BOTH, "2.0"},
//{"DefaultQueue", &DMWRITE, DMT_STRING, get_QDefaultQueue, set_QDefaultQueue, BBFDM_BOTH, "2.0"},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QDefaultDSCPMark, set_QDefaultDSCPMark, BBFDM_BOTH, "2.0"},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QDefaultEthernetPriorityMark, set_QDefaultEthernetPriorityMark, BBFDM_BOTH, "2.0"},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QDefaultInnerEthernetPriorityMark, set_QDefaultInnerEthernetPriorityMark, BBFDM_BOTH, "2.7"},
//{"AvailableAppList", &DMREAD, DMT_STRING, get_QAvailableAppList, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.QoS.Classification.{i}. *** */
DMLEAF tQoSClassificationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSClassification_Enable, set_QoSClassification_Enable, BBFDM_BOTH, "2.0"},
//{"Status", &DMREAD, DMT_STRING, get_QoSClassification_Status, NULL, BBFDM_BOTH, "2.0"},
//{"Order", &DMWRITE, DMT_UNINT, get_QoSClassification_Order, set_QoSClassification_Order, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_QoSClassification_Alias, set_QoSClassification_Alias, BBFDM_BOTH, "2.0"},
//{"DHCPType", &DMWRITE, DMT_STRING, get_QoSClassification_DHCPType, set_QoSClassification_DHCPType, BBFDM_BOTH, "2.2"},
{"Interface", &DMWRITE, DMT_STRING, get_QoSClassification_Interface, set_QoSClassification_Interface, BBFDM_BOTH, "2.0"},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_QoSClassification_AllInterfaces, set_QoSClassification_AllInterfaces, BBFDM_BOTH, "2.0"},
{"DestIP", &DMWRITE, DMT_STRING, get_QoSClassification_DestIP, set_QoSClassification_DestIP, BBFDM_BOTH, "2.0"},
{"DestMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMask, set_QoSClassification_DestMask, BBFDM_BOTH, "2.0"},
//{"DestIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestIPExclude, set_QoSClassification_DestIPExclude, BBFDM_BOTH, "2.0"},
{"SourceIP", &DMWRITE, DMT_STRING, get_QoSClassification_SourceIP, set_QoSClassification_SourceIP, BBFDM_BOTH, "2.0"},
{"SourceMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMask, set_QoSClassification_SourceMask, BBFDM_BOTH, "2.0"},
//{"SourceIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceIPExclude, set_QoSClassification_SourceIPExclude, BBFDM_BOTH, "2.0"},
{"Protocol", &DMWRITE, DMT_INT, get_QoSClassification_Protocol, set_QoSClassification_Protocol, BBFDM_BOTH, "2.0"},
//{"ProtocolExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_ProtocolExclude, set_QoSClassification_ProtocolExclude, BBFDM_BOTH, "2.0"},
{"DestPort", &DMWRITE, DMT_INT, get_QoSClassification_DestPort, set_QoSClassification_DestPort, BBFDM_BOTH, "2.0"},
{"DestPortRangeMax", &DMWRITE, DMT_INT, get_QoSClassification_DestPortRangeMax, set_QoSClassification_DestPortRangeMax, BBFDM_BOTH, "2.0"},
//{"DestPortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestPortExclude, set_QoSClassification_DestPortExclude, BBFDM_BOTH, "2.0"},
{"SourcePort", &DMWRITE, DMT_INT, get_QoSClassification_SourcePort, set_QoSClassification_SourcePort, BBFDM_BOTH, "2.0"},
{"SourcePortRangeMax", &DMWRITE, DMT_INT, get_QoSClassification_SourcePortRangeMax, set_QoSClassification_SourcePortRangeMax, BBFDM_BOTH, "2.0"},
//{"SourcePortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourcePortExclude, set_QoSClassification_SourcePortExclude, BBFDM_BOTH, "2.0"},
{"SourceMACAddress", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACAddress, set_QoSClassification_SourceMACAddress, BBFDM_BOTH, "2.0"},
//{"SourceMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACMask, set_QoSClassification_SourceMACMask, BBFDM_BOTH, "2.0"},
//{"SourceMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceMACExclude, set_QoSClassification_SourceMACExclude, BBFDM_BOTH, "2.0"},
{"DestMACAddress", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACAddress, set_QoSClassification_DestMACAddress, BBFDM_BOTH, "2.0"},
//{"DestMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACMask, set_QoSClassification_DestMACMask, BBFDM_BOTH, "2.0"},
//{"DestMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestMACExclude, set_QoSClassification_DestMACExclude, BBFDM_BOTH, "2.0"},
{"Ethertype", &DMWRITE, DMT_INT, get_QoSClassification_Ethertype, set_QoSClassification_Ethertype, BBFDM_BOTH, "2.0"},
//{"EthertypeExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthertypeExclude, set_QoSClassification_EthertypeExclude, BBFDM_BOTH, "2.0"},
//{"SSAP", &DMWRITE, DMT_INT, get_QoSClassification_SSAP, set_QoSClassification_SSAP, BBFDM_BOTH, "2.0"},
//{"SSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SSAPExclude, set_QoSClassification_SSAPExclude, BBFDM_BOTH, "2.0"},
//{"DSAP", &DMWRITE, DMT_INT, get_QoSClassification_DSAP, set_QoSClassification_DSAP, BBFDM_BOTH, "2.0"},
//{"DSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSAPExclude, set_QoSClassification_DSAPExclude, BBFDM_BOTH, "2.0"},
//{"LLCControl", &DMWRITE, DMT_INT, get_QoSClassification_LLCControl, set_QoSClassification_LLCControl, BBFDM_BOTH, "2.0"},
//{"LLCControlExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_LLCControlExclude, set_QoSClassification_LLCControlExclude, BBFDM_BOTH, "2.0"},
//{"SNAPOUI", &DMWRITE, DMT_INT, get_QoSClassification_SNAPOUI, set_QoSClassification_SNAPOUI, BBFDM_BOTH, "2.0"},
//{"SNAPOUIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SNAPOUIExclude, set_QoSClassification_SNAPOUIExclude, BBFDM_BOTH, "2.0"},
{"SourceVendorClassID", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassID, set_QoSClassification_SourceVendorClassID, BBFDM_BOTH, "2.0"},
//{"SourceVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorClassIDv6, set_QoSClassification_SourceVendorClassIDv6, BBFDM_BOTH, "2.2"},
//{"SourceVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorClassIDExclude, set_QoSClassification_SourceVendorClassIDExclude, BBFDM_BOTH, "2.0"},
//{"SourceVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassIDMode, set_QoSClassification_SourceVendorClassIDMode, BBFDM_BOTH, "2.0"},
{"DestVendorClassID", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassID, set_QoSClassification_DestVendorClassID, BBFDM_BOTH, "2.0"},
//{"DestVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorClassIDv6, set_QoSClassification_DestVendorClassIDv6, BBFDM_BOTH, "2.2"},
//{"DestVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorClassIDExclude, set_QoSClassification_DestVendorClassIDExclude, BBFDM_BOTH, "2.0"},
//{"DestVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassIDMode, set_QoSClassification_DestVendorClassIDMode, BBFDM_BOTH, "2.0"},
{"SourceClientID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceClientID, set_QoSClassification_SourceClientID, BBFDM_BOTH, "2.0"},
//{"SourceClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceClientIDExclude, set_QoSClassification_SourceClientIDExclude, BBFDM_BOTH, "2.0"},
{"DestClientID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestClientID, set_QoSClassification_DestClientID, BBFDM_BOTH, "2.0"},
//{"DestClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestClientIDExclude, set_QoSClassification_DestClientIDExclude, BBFDM_BOTH, "2.0"},
{"SourceUserClassID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceUserClassID, set_QoSClassification_SourceUserClassID, BBFDM_BOTH, "2.0"},
//{"SourceUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceUserClassIDExclude, set_QoSClassification_SourceUserClassIDExclude, BBFDM_BOTH, "2.0"},
{"DestUserClassID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestUserClassID, set_QoSClassification_DestUserClassID, BBFDM_BOTH, "2.0"},
//{"DestUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestUserClassIDExclude, set_QoSClassification_DestUserClassIDExclude, BBFDM_BOTH, "2.0"},
//{"SourceVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorSpecificInfo, set_QoSClassification_SourceVendorSpecificInfo, BBFDM_BOTH, "2.0"},
//{"SourceVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorSpecificInfoExclude, set_QoSClassification_SourceVendorSpecificInfoExclude, BBFDM_BOTH, "2.0"},
//{"SourceVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_SourceVendorSpecificInfoEnterprise, set_QoSClassification_SourceVendorSpecificInfoEnterprise, BBFDM_BOTH, "2.0"},
//{"SourceVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_SourceVendorSpecificInfoSubOption, set_QoSClassification_SourceVendorSpecificInfoSubOption, BBFDM_BOTH, "2.0"},
//{"DestVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorSpecificInfo, set_QoSClassification_DestVendorSpecificInfo, BBFDM_BOTH, "2.0"},
//{"DestVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorSpecificInfoExclude, set_QoSClassification_DestVendorSpecificInfoExclude, BBFDM_BOTH, "2.0"},
//{"DestVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_DestVendorSpecificInfoEnterprise, set_QoSClassification_DestVendorSpecificInfoEnterprise, BBFDM_BOTH, "2.0"},
//{"DestVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_DestVendorSpecificInfoSubOption, set_QoSClassification_DestVendorSpecificInfoSubOption, BBFDM_BOTH, "2.0"},
//{"TCPACK", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACK, set_QoSClassification_TCPACK, BBFDM_BOTH, "2.0"},
//{"TCPACKExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACKExclude, set_QoSClassification_TCPACKExclude, BBFDM_BOTH, "2.0"},
{"IPLengthMin", &DMWRITE, DMT_UNINT, get_QoSClassification_IPLengthMin, set_QoSClassification_IPLengthMin, BBFDM_BOTH, "2.0"},
{"IPLengthMax", &DMWRITE, DMT_UNINT, get_QoSClassification_IPLengthMax, set_QoSClassification_IPLengthMax, BBFDM_BOTH, "2.0"},
//{"IPLengthExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_IPLengthExclude, set_QoSClassification_IPLengthExclude, BBFDM_BOTH, "2.0"},
{"DSCPCheck", &DMWRITE, DMT_INT, get_QoSClassification_DSCPCheck, set_QoSClassification_DSCPCheck, BBFDM_BOTH, "2.0"},
//{"DSCPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSCPExclude, set_QoSClassification_DSCPExclude, BBFDM_BOTH, "2.0"},
{"DSCPMark", &DMWRITE, DMT_INT, get_QoSClassification_DSCPMark, set_QoSClassification_DSCPMark, BBFDM_BOTH, "2.0"},
{"EthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityCheck, set_QoSClassification_EthernetPriorityCheck, BBFDM_BOTH, "2.0"},
//{"EthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetPriorityExclude, set_QoSClassification_EthernetPriorityExclude, BBFDM_BOTH, "2.0"},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityMark, set_QoSClassification_EthernetPriorityMark, BBFDM_BOTH, "2.0"},
//{"InnerEthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityCheck, set_QoSClassification_InnerEthernetPriorityCheck, BBFDM_BOTH, "2.7"},
//{"InnerEthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_InnerEthernetPriorityExclude, set_QoSClassification_InnerEthernetPriorityExclude, BBFDM_BOTH, "2.7"},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityMark, set_QoSClassification_InnerEthernetPriorityMark, BBFDM_BOTH, "2.7"},
//{"EthernetDEICheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetDEICheck, set_QoSClassification_EthernetDEICheck, BBFDM_BOTH, "2.7"},
//{"EthernetDEIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetDEIExclude, set_QoSClassification_EthernetDEIExclude, BBFDM_BOTH, "2.7"},
{"VLANIDCheck", &DMWRITE, DMT_INT, get_QoSClassification_VLANIDCheck, set_QoSClassification_VLANIDCheck, BBFDM_BOTH, "2.0"},
//{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_VLANIDExclude, set_QoSClassification_VLANIDExclude, BBFDM_BOTH, "2.0"},
//{"OutOfBandInfo", &DMWRITE, DMT_INT, get_QoSClassification_OutOfBandInfo, set_QoSClassification_OutOfBandInfo, BBFDM_BOTH, "2.0"},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSClassification_ForwardingPolicy, set_QoSClassification_ForwardingPolicy, BBFDM_BOTH, "2.0"},
{"TrafficClass", &DMWRITE, DMT_INT, get_QoSClassification_TrafficClass, set_QoSClassification_TrafficClass, BBFDM_BOTH, "2.0"},
{"Policer", &DMWRITE, DMT_STRING, get_QoSClassification_Policer, set_QoSClassification_Policer, BBFDM_BOTH, "2.0"},
//{"App", &DMWRITE, DMT_STRING, get_QoSClassification_App, set_QoSClassification_App, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.QoS.App.{i}. *** */
DMLEAF tQoSAppParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSApp_Enable, set_QoSApp_Enable, BBFDM_BOTH, "2.0"},
//{"Status", &DMREAD, DMT_STRING, get_QoSApp_Status, NULL, BBFDM_BOTH, "2.0"},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSApp_Alias, set_QoSApp_Alias, BBFDM_BOTH, "2.0"},
//{"ProtocolIdentifier", &DMWRITE, DMT_STRING, get_QoSApp_ProtocolIdentifier, set_QoSApp_ProtocolIdentifier, BBFDM_BOTH, "2.0"},
//{"Name", &DMWRITE, DMT_STRING, get_QoSApp_Name, set_QoSApp_Name, BBFDM_BOTH, "2.0"},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultForwardingPolicy, set_QoSApp_DefaultForwardingPolicy, BBFDM_BOTH, "2.0"},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultTrafficClass, set_QoSApp_DefaultTrafficClass, BBFDM_BOTH, "2.0"},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoSApp_DefaultPolicer, set_QoSApp_DefaultPolicer, BBFDM_BOTH, "2.0"},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultDSCPMark, set_QoSApp_DefaultDSCPMark, BBFDM_BOTH, "2.0"},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultEthernetPriorityMark, set_QoSApp_DefaultEthernetPriorityMark, BBFDM_BOTH, "2.0"},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultInnerEthernetPriorityMark, set_QoSApp_DefaultInnerEthernetPriorityMark, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.QoS.Flow.{i}. *** */
DMLEAF tQoSFlowParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSFlow_Enable, set_QoSFlow_Enable, BBFDM_BOTH, "2.0"},
//{"Status", &DMREAD, DMT_STRING, get_QoSFlow_Status, NULL, BBFDM_BOTH, "2.0"},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSFlow_Alias, set_QoSFlow_Alias, BBFDM_BOTH, "2.0"},
//{"Type", &DMWRITE, DMT_STRING, get_QoSFlow_Type, set_QoSFlow_Type, BBFDM_BOTH, "2.0"},
//{"TypeParameters", &DMWRITE, DMT_STRING, get_QoSFlow_TypeParameters, set_QoSFlow_TypeParameters, BBFDM_BOTH, "2.0"},
//{"Name", &DMWRITE, DMT_STRING, get_QoSFlow_Name, set_QoSFlow_Name, BBFDM_BOTH, "2.0"},
//{"App", &DMWRITE, DMT_STRING, get_QoSFlow_App, set_QoSFlow_App, BBFDM_BOTH, "2.0"},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSFlow_ForwardingPolicy, set_QoSFlow_ForwardingPolicy, BBFDM_BOTH, "2.0"},
//{"TrafficClass", &DMWRITE, DMT_UNINT, get_QoSFlow_TrafficClass, set_QoSFlow_TrafficClass, BBFDM_BOTH, "2.0"},
//{"Policer", &DMWRITE, DMT_STRING, get_QoSFlow_Policer, set_QoSFlow_Policer, BBFDM_BOTH, "2.0"},
//{"DSCPMark", &DMWRITE, DMT_INT, get_QoSFlow_DSCPMark, set_QoSFlow_DSCPMark, BBFDM_BOTH, "2.0"},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_EthernetPriorityMark, set_QoSFlow_EthernetPriorityMark, BBFDM_BOTH, "2.0"},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_InnerEthernetPriorityMark, set_QoSFlow_InnerEthernetPriorityMark, BBFDM_BOTH, "2.7"},
{0}
};

/* *** Device.QoS.Policer.{i}. *** */
DMLEAF tQoSPolicerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSPolicer_Enable, set_QoSPolicer_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_QoSPolicer_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_QoSPolicer_Alias, set_QoSPolicer_Alias, BBFDM_BOTH, "2.0"},
{"CommittedRate", &DMWRITE, DMT_UNINT, get_QoSPolicer_CommittedRate, set_QoSPolicer_CommittedRate, BBFDM_BOTH, "2.0"},
{"CommittedBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_CommittedBurstSize, set_QoSPolicer_CommittedBurstSize, BBFDM_BOTH, "2.0"},
{"ExcessBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_ExcessBurstSize, set_QoSPolicer_ExcessBurstSize, BBFDM_BOTH, "2.0"},
{"PeakRate", &DMWRITE, DMT_UNINT, get_QoSPolicer_PeakRate, set_QoSPolicer_PeakRate, BBFDM_BOTH, "2.0"},
{"PeakBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_PeakBurstSize, set_QoSPolicer_PeakBurstSize, BBFDM_BOTH, "2.0"},
{"MeterType", &DMWRITE, DMT_STRING, get_QoSPolicer_MeterType, set_QoSPolicer_MeterType, BBFDM_BOTH, "2.0"},
{"PossibleMeterTypes", &DMREAD, DMT_STRING, get_QoSPolicer_PossibleMeterTypes, NULL, BBFDM_BOTH, "2.0"},
//{"ConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_ConformingAction, set_QoSPolicer_ConformingAction, BBFDM_BOTH, "2.0"},
//{"PartialConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_PartialConformingAction, set_QoSPolicer_PartialConformingAction, BBFDM_BOTH, "2.0"},
//{"NonConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_NonConformingAction, set_QoSPolicer_NonConformingAction, BBFDM_BOTH, "2.0"},
//{"TotalCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedPackets, NULL, BBFDM_BOTH, "2.0"},
//{"TotalCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedBytes, NULL, BBFDM_BOTH, "2.0"},
//{"ConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedPackets, NULL, BBFDM_BOTH, "2.0"},
//{"ConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedBytes, NULL, BBFDM_BOTH, "2.0"},
//{"PartiallyConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedPackets, NULL, BBFDM_BOTH, "2.0"},
//{"PartiallyConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedBytes, NULL, BBFDM_BOTH, "2.0"},
//{"NonConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedPackets, NULL, BBFDM_BOTH, "2.0"},
//{"NonConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedBytes, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.QoS.Queue.{i}. *** */
DMLEAF tQoSQueueParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSQueue_Enable, set_QoSQueue_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_QoSQueue_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_QoSQueue_Alias, set_QoSQueue_Alias, BBFDM_BOTH, "2.0"},
{"TrafficClasses", &DMWRITE, DMT_STRING, get_QoSQueue_TrafficClasses, set_QoSQueue_TrafficClasses, BBFDM_BOTH, "2.0"},
{"Interface", &DMWRITE, DMT_STRING, get_QoSQueue_Interface, set_QoSQueue_Interface, BBFDM_BOTH, "2.0"},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_QoSQueue_AllInterfaces, set_QoSQueue_AllInterfaces, BBFDM_BOTH, "2.0"},
//{"HardwareAssisted", &DMREAD, DMT_BOOL, get_QoSQueue_HardwareAssisted, NULL, BBFDM_BOTH, "2.0"},
//{"BufferLength", &DMREAD, DMT_UNINT, get_QoSQueue_BufferLength, NULL, BBFDM_BOTH, "2.0"},
{"Weight", &DMWRITE, DMT_UNINT, get_QoSQueue_Weight, set_QoSQueue_Weight, BBFDM_BOTH, "2.0"},
{"Precedence", &DMWRITE, DMT_UNINT, get_QoSQueue_Precedence, set_QoSQueue_Precedence, BBFDM_BOTH, "2.0"},
//{"REDThreshold", &DMWRITE, DMT_UNINT, get_QoSQueue_REDThreshold, set_QoSQueue_REDThreshold, BBFDM_BOTH, "2.0"},
//{"REDPercentage", &DMWRITE, DMT_UNINT, get_QoSQueue_REDPercentage, set_QoSQueue_REDPercentage, BBFDM_BOTH, "2.0"},
//{"DropAlgorithm", &DMWRITE, DMT_STRING, get_QoSQueue_DropAlgorithm, set_QoSQueue_DropAlgorithm, BBFDM_BOTH, "2.0"},
{"SchedulerAlgorithm", &DMWRITE, DMT_STRING, get_QoSQueue_SchedulerAlgorithm, set_QoSQueue_SchedulerAlgorithm, BBFDM_BOTH, "2.0"},
{"ShapingRate", &DMWRITE, DMT_INT, get_QoSQueue_ShapingRate, set_QoSQueue_ShapingRate, BBFDM_BOTH, "2.0"},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, get_QoSQueue_ShapingBurstSize, set_QoSQueue_ShapingBurstSize, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.QoS.QueueStats.{i}. *** */
DMLEAF tQoSQueueStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSQueueStats_Enable, set_QoSQueueStats_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_QoSQueueStats_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_QoSQueueStats_Alias, set_QoSQueueStats_Alias, BBFDM_BOTH, "2.0"},
{"Queue", &DMWRITE, DMT_STRING, get_QoSQueueStats_Queue, set_QoSQueueStats_Queue, BBFDM_BOTH, "2.0"},
{"Interface", &DMWRITE, DMT_STRING, get_QoSQueueStats_Interface, set_QoSQueueStats_Interface, BBFDM_BOTH, "2.0"},
{"OutputPackets", &DMREAD, DMT_UNINT, get_QoSQueueStats_OutputPackets, NULL, BBFDM_BOTH, "2.0"},
{"OutputBytes", &DMREAD, DMT_UNINT, get_QoSQueueStats_OutputBytes, NULL, BBFDM_BOTH, "2.0"},
{"DroppedPackets", &DMREAD, DMT_UNINT, get_QoSQueueStats_DroppedPackets, NULL, BBFDM_BOTH, "2.0"},
{"DroppedBytes", &DMREAD, DMT_UNINT, get_QoSQueueStats_DroppedBytes, NULL, BBFDM_BOTH, "2.0"},
//{"QueueOccupancyPackets", &DMREAD, DMT_UNINT, get_QoSQueueStats_QueueOccupancyPackets, NULL, BBFDM_BOTH, "2.0"},
//{"QueueOccupancyPercentage", &DMREAD, DMT_UNINT, get_QoSQueueStats_QueueOccupancyPercentage, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.QoS.Shaper.{i}. *** */
DMLEAF tQoSShaperParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSShaper_Enable, set_QoSShaper_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_QoSShaper_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_QoSShaper_Alias, set_QoSShaper_Alias, BBFDM_BOTH, "2.0"},
{"Interface", &DMWRITE, DMT_STRING, get_QoSShaper_Interface, set_QoSShaper_Interface, BBFDM_BOTH, "2.0"},
{"ShapingRate", &DMWRITE, DMT_INT, get_QoSShaper_ShapingRate, set_QoSShaper_ShapingRate, BBFDM_BOTH, "2.0"},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, get_QoSShaper_ShapingBurstSize, set_QoSShaper_ShapingBurstSize, BBFDM_BOTH, "2.0"},
{0}
};
