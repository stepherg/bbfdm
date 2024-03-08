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
#include "bbfdmd.h"
#include <libubus.h>

static char *get_events_dm_path(struct list_head *ev_list, const char *event)
{
	struct ev_handler_node *iter = NULL;

	if (ev_list == NULL || event == NULL)
		return NULL;

	list_for_each_entry(iter, ev_list, list) {
		if (iter->ev_name && strcmp(iter->ev_name, event) == 0)
			return iter->dm_path;
	}

	return NULL;
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

	char *dm_path = get_events_dm_path(&u->event_handlers, type);
	if (dm_path == NULL)
		return;

	struct dmctx bbf_ctx = {
			.in_param = dm_path,
			.in_value = blobmsg_format_json(msg, true),
			.nextlevel = false,
			.iscommand = false,
			.isevent = true,
			.isinfo = false,
			.disable_mservice_browse = true,
			.instance_mode = INSTANCE_MODE_NUMBER,
			.dm_type = BBFDM_USP
	};

	bbf_init(&bbf_ctx);

	int ret = bbfdm_cmd_exec(&bbf_ctx, BBF_EVENT);
	if (ret)
		goto end;

	struct dm_parameter *param = NULL;
	struct blob_buf b = {0}, bb = {0};
	char method_name[256] = {0};

	memset(&b, 0, sizeof(struct blob_buf));
	memset(&bb, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);
	blob_buf_init(&bb, 0);

	list_for_each_entry(param, &bbf_ctx.list_parameter, list) {
		blobmsg_add_string(&bb, param->name, param->data);
	}

	snprintf(method_name, sizeof(method_name), "%s.%s", DM_STRLEN(u->config.out_root_obj) ? u->config.out_root_obj : u->config.out_name, BBF_EVENT_NAME);

	blobmsg_add_string(&b, "name", dm_path);
	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "input", blob_data(bb.head), blob_len(bb.head));

	ubus_send_event(ctx, method_name, b.head);
	DEBUG("Event[%s], for [%s] sent", method_name, dm_path);

	blob_buf_free(&bb);
	blob_buf_free(&b);

end:
	bbf_cleanup(&bbf_ctx);
}

static void add_ubus_event_handler(struct ubus_event_handler *ev, const char *ev_name, const char *dm_path, struct list_head *ev_list)
{
	if (ev == NULL || ev_list == NULL)
		return;

	struct ev_handler_node *node = NULL;
	node = (struct ev_handler_node *) malloc(sizeof(struct ev_handler_node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	node->ev_name = ev_name ? strdup(ev_name) : NULL;
	node->dm_path = dm_path ? strdup(dm_path) : NULL;
	node->ev_handler = ev;
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, ev_list);
}

int register_events_to_ubus(struct ubus_context *ctx, struct list_head *ev_list)
{
	int err = 0;

	if (ctx == NULL || ev_list == NULL)
		return -1;

	struct dmctx bbf_ctx = {
			.in_param = ROOT_NODE,
			.nextlevel = false,
			.iscommand = false,
			.isevent = true,
			.isinfo = false,
			.disable_mservice_browse = true,
			.instance_mode = INSTANCE_MODE_NUMBER,
			.dm_type = BBFDM_USP
	};

	bbf_init(&bbf_ctx);

	if (0 == bbfdm_cmd_exec(&bbf_ctx, BBF_SCHEMA)) {
		struct dm_parameter *param;

		list_for_each_entry(param, &bbf_ctx.list_parameter, list) {
			event_args *event = (event_args *)param->data;

			if (!param->name || !event || !event->name || !strlen(event->name))
				continue;

			struct ubus_event_handler *ev = (struct ubus_event_handler *)malloc(sizeof(struct ubus_event_handler));
			if (!ev) {
				ERR("Out of memory!");
				err = -1;
				goto end;
			}

			memset(ev, 0, sizeof(struct ubus_event_handler));
			ev->cb = bbfdm_event_handler;

			if (0 != ubus_register_event_handler(ctx, ev, event->name)) {
				ERR("Failed to register: %s", event->name);
				err = -1;
				goto end;
			}

			add_ubus_event_handler(ev, event->name, param->name, ev_list);
		}
	}

end:
	bbf_cleanup(&bbf_ctx);

	return err;
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

		if (iter->dm_path)
			free(iter->dm_path);

		if (iter->ev_name)
			free(iter->ev_name);

		list_del(&iter->list);
		free(iter);
	}
}
