/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "qos.h"

struct queuestats
{
	struct uci_section *dmsect;
	char dev[50];
	char user[50];
	char priomap[50];
	int noqueue;
	int pfifo_fast;
	int refcnt;
	int bands;
	int bytes_sent;
	int pkt_sent;
	int pkt_dropped;
	int pkt_overlimits;
	int pkt_requeues;
	int backlog_b;
	int backlog_p;
	int backlog_requeues;
};

/**************************************************************************
* Browse functions
***************************************************************************/
/*#Device.QoS.Classification.{i}.!UCI:qos/classify/dmmap_qos*/
static int openwrt__browseQoSClassificationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "classify", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "classifinstance", "classifalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static struct uci_section *get_dup_qstats_section_in_dmmap(char *dmmap_package, char *section_type, char *dev)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "dev_link", dev, s) {
		return s;
	}

	return NULL;
}

static int openwrt__browseQoSQueueStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *dmmap_sect;
	char *questatsout[256], *inst = NULL, *max_inst = NULL, *lastinstancestore = NULL, dev[50] = "", user[50] = "";
	static int length = 0, i, ret = 0;
	struct queuestats queuests = {0}, emptyquestats = {0};
	regex_t regex1 = {}, regex2 = {};

	regcomp(&regex1, "^qdisc noqueue [0-9]*: dev [[:alnum:]]* [[:alnum:]]* refcnt [0-9]*", 0);
	regcomp(&regex2, "^qdisc pfifo_fast [0-9]*: dev [[:alnum:]]* [[:alnum:]]* refcnt [0-9]*", 0);

	command_exec_output_to_array("tc -s qdisc", questatsout, &length);

	for (i = 0; i < length; i++) {
		switch (i%3) {
			case 0: ret = regexec(&regex1, questatsout[i], 0, NULL, 0);
				 	if (ret == 0)
				 		sscanf(questatsout[i], "qdisc noqueue %d: dev %49s %49s refcnt %d\n", &queuests.noqueue, dev, user, &queuests.refcnt);
				 	else {
				 		ret= regexec(&regex2, questatsout[i], 0, NULL, 0);
				 		if (ret == 0)
				 			sscanf(questatsout[i], "qdisc pfifo_fast %d: dev %49s %49s refcnt %d\n", &queuests.pfifo_fast, dev, user, &queuests.refcnt);
				 	}
					DM_STRNCPY(queuests.dev, dev, sizeof(queuests.dev));
					break;
			case 1: sscanf(questatsout[i], " Sent %d bytes %d pkt (dropped %d, overlimits %d requeues %d)\n", &queuests.bytes_sent, &queuests.pkt_sent, &queuests.pkt_dropped, &queuests.pkt_overlimits, &queuests.pkt_requeues);
					break;
			case 2: sscanf(questatsout[i], " backlog %db %dp requeues %d\n", &queuests.backlog_b, &queuests.backlog_p, &queuests.backlog_requeues);
					if ((dmmap_sect = get_dup_qstats_section_in_dmmap("dmmap_qos", "qqueue_stats", queuests.dev)) == NULL) {
						dmuci_add_section_bbfdm("dmmap_qos", "qqueue_stats", &dmmap_sect);
						dmuci_set_value_by_section_bbfdm(dmmap_sect, "dev_link", queuests.dev);
					}

					queuests.dmsect= dmmap_sect;

					if (lastinstancestore != NULL && max_inst != NULL)
						max_inst = dmstrdup(lastinstancestore);

					inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
						   dmmap_sect, "queuestatsinstance", "queuestatsalias");

					lastinstancestore = dmstrdup(max_inst);

					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&queuests, inst) == DM_STOP)
						goto end;

					queuests = emptyquestats;
					break;
		}
	}

	regfree(&regex1);
	regfree(&regex2);
end:
	return 0;
}

static int openwrt__addObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_qclassify;
	char qcomment[32];

	char *last_inst = get_last_instance_bbfdm("dmmap_qos", "classify", "classifinstance");
	snprintf(qcomment, sizeof(qcomment), "QoS classify %s", (last_inst) ? last_inst : "1");

	dmuci_add_section("qos", "classify", &s);
	dmuci_set_value_by_section(s, "comment", qcomment);

	dmuci_add_section_bbfdm("dmmap_qos", "classify", &dmmap_qclassify);
	dmuci_set_value_by_section(dmmap_qclassify, "section_name", section_name(s));
	*instance = update_instance(last_inst, 2, dmmap_qclassify, "classifinstance");
	return 0;
}

static int openwrt__delObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dmmap_dup *p = (struct dmmap_dup*)data;
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name(p->config_section))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "classify", "classifinstance", section_name(p->config_section), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "classifinstance", "dmmap_qos", "classify");
				dmuci_delete_by_section_unnamed(p->config_section, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(p->config_section), &dmmap_section);
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(p->config_section, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("qos", "classify", stmp, s) {
				get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int openwrt__addObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	return 0;
}

static int openwrt__delObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return 0;
}

/*#Device.QoS.ClassificationNumberOfEntries!UCI:qos/classify/*/
static int openwrt__get_QClassificationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	static int nbre= 0;

	uci_foreach_sections("qos", "classify", s) {
		nbre++;
	}

	dmasprintf(value, "%d", nbre);
	return 0;
}

static int openwrt__get_QQueueStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *questatsout[256];
	static int length = 0;

	command_exec_output_to_array("tc -s qdisc", questatsout, &length);
	dmasprintf(value, "%d", length/3);
	return 0;
}

static int openwrt__get_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->dmmap_section, "classifalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int openwrt__set_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->dmmap_section, "classifalias", value);
			break;
	}
	return 0;
}

static int openwrt__get_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p = (struct dmmap_dup *)data;
	struct uci_section *s = NULL;
	char *classes = NULL, **classesarr = NULL, *classgroup = NULL, *ifaceclassgrp = NULL, *targetclass = NULL;
	size_t length;

	dmuci_get_value_by_section_string(p->config_section, "target", &targetclass);
	uci_foreach_sections("qos", "classgroup", s) {
		dmuci_get_value_by_section_string(s, "classes", &classes);
		classesarr = strsplit(classes, " ", &length);
		if (classes != NULL && elt_exists_in_array(classesarr, targetclass, length)) {
			dmasprintf(&classgroup, "%s", section_name(s));
			break;
		}
	}
	if (classgroup == NULL)
		return 0;
	uci_foreach_sections("qos", "interface", s) {
		dmuci_get_value_by_section_string(s, "classgroup", &ifaceclassgrp);
		if (ifaceclassgrp != NULL && strcmp(ifaceclassgrp, classgroup) == 0) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", section_name(s), value);
			if (*value == NULL)
				adm_entry_get_linker_param(ctx, "Device.PPP.Interface.", section_name(s), value);
			if (*value == NULL)
				adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", section_name(s), value);
			if (*value == NULL)
				*value = "";
		}
	}
	return 0;
}

static int openwrt__set_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DestIP!UCI:qos/classify,@i-1/dsthost*/
static int openwrt__get_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "dsthost", value);
	return 0;
}

static int openwrt__set_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "dsthost", value);
			break;
	}
	return 0;
}



/*#Device.QoS.Classification.{i}.SourceIP!UCI:qos/classify,@i-1/srchost*/
static int openwrt__get_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "srchost", value);
	return 0;
}

static int openwrt__set_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "srchost", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.Protocol!UCI:qos/classify,@i-1/proto*/
static int openwrt__get_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "proto", value);
	return 0;
}

static int openwrt__set_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "proto", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DestPort!UCI:qos/classify,@i-1/dstports*/
static int openwrt__get_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "dstports", value);
	return 0;
}

static int openwrt__set_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "dstports", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DestPortRangeMax!UCI:qos/classify,@i-1/portrange*/
static int openwrt__get_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "portrange", value);
	return 0;
}

static int openwrt__set_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "portrange", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.SourcePort!UCI:qos/classify,@i-1/srcports*/
static int openwrt__get_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p = (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "srcports", value);
	return 0;
}

static int openwrt__set_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "srcports", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DSCPMark!UCI:qos/classify,@i-1/dscp*/
static int openwrt__get_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p = (struct dmmap_dup *)data;
	dmuci_get_value_by_section_string(p->config_section, "dscp", value);
	return 0;
}

static int openwrt__set_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup *)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "dscp", value);
			break;
	}
	return 0;
}

static int openwrt__get_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *qts= (struct queuestats*)data;
	dmuci_get_value_by_section_string(qts->dmsect, "queuestatsalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int openwrt__set_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct queuestats *qts= (struct queuestats*)data;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 64, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(qts->dmsect, "queuestatsalias", value);
		break;
	}
	return 0;
}

static int openwrt__get_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *qts = (struct queuestats*)data;

	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", qts->dev, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, "Device.PPP.Interface.", qts->dev, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", qts->dev, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", qts->dev, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int openwrt__set_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		break;
	}
	return 0;
}

static int openwrt__get_QoSQueueStats_OutputPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests = (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->pkt_sent);
	return 0;
}

static int openwrt__get_QoSQueueStats_OutputBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests = (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->bytes_sent);
	return 0;
}

static int openwrt__get_QoSQueueStats_DroppedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests = (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->pkt_dropped);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.QoS. *** */
DMOBJ tOPENWRT_QoSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Classification", &DMWRITE, openwrt__addObjQoSClassification, openwrt__delObjQoSClassification, NULL, openwrt__browseQoSClassificationInst, NULL, NULL, NULL, tOPENWRT_QoSClassificationParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"QueueStats", &DMWRITE, openwrt__addObjQoSQueueStats, openwrt__delObjQoSQueueStats, NULL, openwrt__browseQoSQueueStatsInst, NULL, NULL, NULL, tOPENWRT_QoSQueueStatsParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Queue", "Interface", NULL}},
{0}
};

DMLEAF tOPENWRT_QoSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ClassificationNumberOfEntries", &DMREAD, DMT_UNINT, openwrt__get_QClassificationNumberOfEntries, NULL, BBFDM_BOTH},
{"QueueStatsNumberOfEntries", &DMREAD, DMT_UNINT, openwrt__get_QQueueStatsNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Classification.{i}. *** */
DMLEAF tOPENWRT_QoSClassificationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, openwrt__get_QoSClassification_Alias, openwrt__set_QoSClassification_Alias, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, openwrt__get_QoSClassification_Interface, openwrt__set_QoSClassification_Interface, BBFDM_BOTH},
{"DestIP", &DMWRITE, DMT_STRING, openwrt__get_QoSClassification_DestIP, openwrt__set_QoSClassification_DestIP, BBFDM_BOTH},
{"SourceIP", &DMWRITE, DMT_STRING, openwrt__get_QoSClassification_SourceIP, openwrt__set_QoSClassification_SourceIP, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_INT, openwrt__get_QoSClassification_Protocol, openwrt__set_QoSClassification_Protocol, BBFDM_BOTH},
{"DestPort", &DMWRITE, DMT_INT, openwrt__get_QoSClassification_DestPort, openwrt__set_QoSClassification_DestPort, BBFDM_BOTH},
{"DestPortRangeMax", &DMWRITE, DMT_INT, openwrt__get_QoSClassification_DestPortRangeMax, openwrt__set_QoSClassification_DestPortRangeMax, BBFDM_BOTH},
{"SourcePort", &DMWRITE, DMT_INT, openwrt__get_QoSClassification_SourcePort, openwrt__set_QoSClassification_SourcePort, BBFDM_BOTH},
{"DSCPMark", &DMWRITE, DMT_INT, openwrt__get_QoSClassification_DSCPMark, openwrt__set_QoSClassification_DSCPMark, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.QueueStats.{i}. *** */
DMLEAF tOPENWRT_QoSQueueStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, openwrt__get_QoSQueueStats_Alias, openwrt__set_QoSQueueStats_Alias, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, openwrt__get_QoSQueueStats_Interface, openwrt__set_QoSQueueStats_Interface, BBFDM_BOTH},
{"OutputPackets", &DMREAD, DMT_UNINT, openwrt__get_QoSQueueStats_OutputPackets, NULL, BBFDM_BOTH},
{"OutputBytes", &DMREAD, DMT_UNINT, openwrt__get_QoSQueueStats_OutputBytes, NULL, BBFDM_BOTH},
{"DroppedPackets", &DMREAD, DMT_UNINT, openwrt__get_QoSQueueStats_DroppedPackets, NULL, BBFDM_BOTH},
{0}
};
