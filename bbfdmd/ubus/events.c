/*
 * events.c: Handler to generate bbfdm events on ubus
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "common.h"
#include "events.h"
#include "get_helper.h"
#include <libubus.h>

static struct event_map_list ev_map_list[] = {
	/* { event name,                     DM Path,   .arguments[] = { event_args, dm_args } } */
	{ "wifi.dataelements.Associated", "Device.WiFi.DataElements.AssociationEvent.Associated!",
		.args = {
			{ "eventTime", "TimeStamp" },
			{ "wfa-dataelements:AssociationEvent.AssocData.BSSID", "BSSID" },
			{ "wfa-dataelements:AssociationEvent.AssocData.MACAddress", "MACAddress" },
			{ "wfa-dataelements:AssociationEvent.AssocData.StatusCode", "StatusCode" },
			{ "wfa-dataelements:AssociationEvent.AssocData.HTCapabilities", "HTCapabilities" },
			{ "wfa-dataelements:AssociationEvent.AssocData.VHTCapabilities", "VHTCapabilities" },
			{ "wfa-dataelements:AssociationEvent.AssocData.HECapabilities", "HECapabilities" },
			{0}
		}
	},
	{ "wifi.dataelements.Disassociated", "Device.WiFi.DataElements.DisassociationEvent.Disassociated!",
		.args = {
			{ "eventTime", "TimeStamp" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.BSSID", "BSSID" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.MACAddress", "MACAddress" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.ReasonCode", "ReasonCode" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.BytesSent", "BytesSent" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.BytesReceived", "BytesReceived" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.PacketsSent", "PacketsSent" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.PacketsReceived", "PacketsReceived" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.ErrorsSent", "ErrorsSent" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.ErrorsReceived", "ErrorsReceived" },
			{ "wfa-dataelements:DisassociationEvent.DisassocData.RetransCount", "RetransCount" },
			{0}
		}
	},
	{ "periodicstat.push", "Device.PeriodicStatistics.SampleSet.{i}.Push!",
		.args = {
			{ "reference", "Parameter.{i}.Reference" },
			{ "values", "Parameter.{i}.Values" },
			{ "samplesecs", "Paramter.{i}.SampleSeconds" },
			{ "failures", "Parameter.{i}.Failures" },
			{0}
		}
	}
};

static char* get_events_dm_path(const char *event)
{
	unsigned int i;

	if (!event) {
		return NULL;
	}

	for (i = 0; i < sizeof(ev_map_list)/sizeof(ev_map_list[0]); i++) {
		if (strcmp(event, ev_map_list[i].event) == 0)
			return ev_map_list[i].dm_path;
	}

	return NULL;
}

static struct event_args_list* get_events_args(const char *event)
{
	unsigned int i;

	if (!event) {
		return NULL;
	}

	for (i = 0; i < sizeof(ev_map_list)/sizeof(ev_map_list[0]); i++) {
		if (strcmp(event, ev_map_list[i].event) == 0)
			return ev_map_list[i].args;
	}

	return NULL;
}

static void serialize_blob_msg(struct blob_attr *msg, char *node, struct list_head *pv_list)
{
	struct blob_attr *attr;
	size_t rem;

	blobmsg_for_each_attr(attr, msg, rem) {
		char path[MAX_DM_PATH], value[MAX_DM_VALUE];

		snprintf(path, sizeof(path), "%s%s%s",
									DM_STRLEN(node) ? node : "",
									blobmsg_name(attr),
									(blobmsg_type(attr) == BLOBMSG_TYPE_TABLE && DM_STRLEN(blobmsg_name(attr))) ? "." : "");

		switch (blobmsg_type(attr)) {
			case BLOBMSG_TYPE_STRING:
				snprintf(value, MAX_DM_VALUE, "%s", blobmsg_get_string(attr));
				add_pv_list(path, value, NULL, pv_list);
				break;
			case BLOBMSG_TYPE_INT8:
				snprintf(value, MAX_DM_VALUE, "%d", blobmsg_get_u8(attr));
				add_pv_list(path, value, NULL, pv_list);
				break;
			case BLOBMSG_TYPE_INT16:
				snprintf(value, MAX_DM_VALUE, "%d", blobmsg_get_u16(attr));
				add_pv_list(path, value, NULL, pv_list);
				break;
			case BLOBMSG_TYPE_INT32:
				snprintf(value, MAX_DM_VALUE, "%u", blobmsg_get_u32(attr));
				add_pv_list(path, value, NULL, pv_list);
				break;
			case BLOBMSG_TYPE_INT64:
				snprintf(value, MAX_DM_VALUE, "%"PRIu64"", blobmsg_get_u64(attr));
				add_pv_list(path, value, NULL, pv_list);
				break;
			case BLOBMSG_TYPE_TABLE:
				serialize_blob_msg(attr, path, pv_list);
		}
	}
}

static char *get_dm_arg_value(const char *event_arg, struct list_head *pv_list)
{
	struct pvNode *pv = NULL;

	list_for_each_entry(pv, pv_list, list) {
		if (strcmp(pv->param, event_arg) == 0)
			return pv->val;
	}

	return NULL;
}

static void generate_blob_input(struct blob_buf *b, const char *type, struct list_head *pv_list)
{
	struct event_args_list *args = get_events_args(type);
	if (args == NULL)
		return;

	for (int i = 0; args[i].event_arg; i++) {
		char *dm_arg = get_dm_arg_value(args[i].event_arg, pv_list);
		blobmsg_add_string(b, args[i].dm_arg, dm_arg ? dm_arg : "");
	}
}

static void generate_periodic_stat_input(struct blob_buf *b, const char *type, json_object *report)
{
	json_object *data_arr = NULL, *data_obj = NULL;
	int j = 0;

	struct event_args_list *args = get_events_args(type);
	if (args == NULL)
		return;

	dmjson_foreach_obj_in_array(report, data_arr, data_obj, j, 1, "push_items") {
		char instance[MAX_DM_KEY_LEN] = {0};
		snprintf(instance, sizeof(instance), "%d", j+1);

		for (int i = 0; args[i].event_arg; i++) {
			char *val = dmjson_get_value(data_obj, 1, args[i].event_arg);
			char *path = replace_str(args[i].dm_arg, "{i}", instance);

			if (path == NULL)
				continue;

			blobmsg_add_string(b, path, val ? val : "");
			FREE(path);
		}
	}
}

static void bbfdm_event_handler(struct ubus_context *ctx, struct ubus_event_handler *ev,
				const char *type, struct blob_attr *msg)
{
	(void)ev;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("Failed to get the bbfdm context");
		return;
	}

	if (!msg || !type)
		return;

	char *dm_path = get_events_dm_path(type);
	if (dm_path == NULL)
		return;

	struct blob_buf b, bb;
	char method_name[40] = {0};

	memset(&b, 0, sizeof(struct blob_buf));
	memset(&bb, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);
	blob_buf_init(&bb, 0);
	LIST_HEAD(pv_list);

	snprintf(method_name, sizeof(method_name), "%s.%s", u->config.out_name, BBF_EVENT);

	if (strcmp(dm_path, "Device.PeriodicStatistics.SampleSet.{i}.Push!") == 0) {
		const char *msg_str = blobmsg_format_json_indent(msg, true, -1);
		if (msg_str == NULL)
			goto out;

		json_object *report = json_tokener_parse(msg_str);
		free((char *)msg_str);

		if (report == NULL)
			goto out;

		char *instance = dmjson_get_value(report, 1, "sampleset_instance");
		if (instance == NULL) {
			json_object_put(report);
			goto out;
		}

		dm_path = replace_str(dm_path, "{i}", instance);
		generate_periodic_stat_input(&bb, type, report);
		json_object_put(report);

		blobmsg_add_string(&b, "name", dm_path);
		FREE(dm_path);
	} else {
		serialize_blob_msg(msg, "", &pv_list);
		generate_blob_input(&bb, type, &pv_list);

		blobmsg_add_string(&b, "name", dm_path);
	}

	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "input", blob_data(bb.head), blob_len(bb.head));
	ubus_send_event(ctx, method_name, b.head);
	DEBUG("Event[%s], for [%s] sent", method_name, dm_path);

	register_instance_refresh_timer(ctx, 2000);
out:
	blob_buf_free(&bb);
	blob_buf_free(&b);
	free_pv_list(&pv_list);
}

static void add_ubus_event_handler(struct ubus_event_handler *ev, struct list_head *ev_list)
{
	if (ev == NULL || ev_list == NULL)
		return;

	struct ev_handler_node *node = NULL;
	node = (struct ev_handler_node *) malloc(sizeof(struct ev_handler_node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	node->ev_handler = ev;
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, ev_list);
}

void free_ubus_event_handler(struct ubus_context *ctx, struct list_head *ev_list)
{
	struct ev_handler_node *iter = NULL, *node = NULL;

	if (ctx == NULL || ev_list == NULL)
		return;

	list_for_each_entry_safe(iter, node, ev_list, list) {
		if (iter->ev_handler != NULL) {
			ubus_unregister_event_handler(ctx, iter->ev_handler);
			free(iter->ev_handler);
		}

		list_del(&iter->list);
		free(iter);
	}
}

int register_events_to_ubus(struct ubus_context *ctx, struct list_head *ev_list)
{
	unsigned int i;

	if (ctx == NULL || ev_list == NULL)
		return -1;

	for (i = 0; i < sizeof(ev_map_list)/sizeof(ev_map_list[0]); i++) {
		if (ev_map_list[i].event == NULL) {
			continue;
		}

		struct ubus_event_handler *ev = (struct ubus_event_handler *)malloc(sizeof(struct ubus_event_handler));
		if (!ev) {
			ERR("Out of memory!");
			return -1;
		}

		memset(ev, 0, sizeof(struct ubus_event_handler));
		ev->cb = bbfdm_event_handler;

		if (0 != ubus_register_event_handler(ctx, ev, ev_map_list[i].event)) {
			ERR("Failed to register: %s", ev_map_list[i].event);
			return -1;
		}

		add_ubus_event_handler(ev, ev_list);
	}

	return 0;
}
