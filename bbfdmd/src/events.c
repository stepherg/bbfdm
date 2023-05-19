/*
 * events.c: Handler to generate bbfdm events on ubus
 *
 * Copyright (C) 2023 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "common.h"
#include "events.h"
#include "get_helper.h"
#include <libubus.h>

extern char UBUS_METHOD_NAME[32];
extern bool enable_plugins;

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

static void bbfdm_event_handler(struct ubus_context *ctx, struct ubus_event_handler *ev,
				const char *type, struct blob_attr *msg)
{
	(void)ev;

	if (!msg || !type)
		return;

	char *dm_path = get_events_dm_path(type);
	if (dm_path == NULL)
		return;

	LIST_HEAD(pv_list);

	serialize_blob_msg(msg, "", &pv_list);

	struct blob_buf b, bb;
	char method_name[40] = {0};

	memset(&b, 0, sizeof(struct blob_buf));
	memset(&bb, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);
	blob_buf_init(&bb, 0);

	snprintf(method_name, sizeof(method_name), "%s.%s", UBUS_METHOD_NAME, BBF_EVENT);

	blobmsg_add_string(&b, "name", dm_path);
	generate_blob_input(&bb, type, &pv_list);
	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "input", blob_data(bb.head), blob_len(bb.head));
	ubus_send_event(ctx, BBF_EVENT, b.head);

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

bool is_registered_event(char *name)
{
	bool ret = false;

	if (!name)
		return false;

	struct dmctx bbf_ctx = {
			.in_param = ROOT_NODE,
			.nextlevel = false,
			.iscommand = false,
			.isevent = true,
			.isinfo = false,
			.enable_plugins = enable_plugins,
			.instance_mode = INSTANCE_MODE_NUMBER,
			.dm_type = BBFDM_USP
	};

	bbf_init(&bbf_ctx);

	if (0 == bbfdm_dm_exec(&bbf_ctx, BBF_SCHEMA)) {
		struct dm_parameter *param;

		list_for_each_entry(param, &bbf_ctx.list_parameter, list) {
			if (strcmp(param->name, name) == 0) {
				ret = true;
				break;
			}
		}
	}

	bbf_cleanup(&bbf_ctx);

	return ret;
}
