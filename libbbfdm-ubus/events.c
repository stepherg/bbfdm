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

struct event_args {
	struct blob_attr *blob_data;
	char method_name[256];
};

struct dm_path_node {
	char *dm_path;
	struct list_head list;
};

struct ev_handler_node {
	char *ev_name;
	struct ubus_event_handler ev_handler;
	struct list_head dm_paths_list; // For dm path list
	struct list_head list; // For event list
};

static struct ev_handler_node *get_event_node(struct list_head *ev_list, const char *event_name)
{
	struct ev_handler_node *iter = NULL;

	if (!ev_list || !event_name)
		return NULL;

	list_for_each_entry(iter, ev_list, list) {
		if (iter->ev_name && strcmp(iter->ev_name, event_name) == 0)
			return iter;
	}

	return NULL;
}

void event_callback(const void *arg1, void *arg2)
{
	struct event_args *e_args = (struct event_args *)arg2;

	if (!e_args || !e_args->blob_data || !DM_STRLEN(e_args->method_name))
		return;

	struct ubus_context *ctx = ubus_connect(NULL);
	if (ctx == NULL) {
		BBF_ERR("Can't create UBUS context for event");
		return;
	}

	ubus_send_event(ctx, e_args->method_name, e_args->blob_data);
	BBF_INFO("Event[%s] sent", e_args->method_name);

	ubus_free(ctx);

	free(e_args->blob_data);
	free(e_args);
}

static void bbfdm_event_handler_cb(struct ubus_context *ctx __attribute__((unused)), struct ubus_event_handler *ev,
				const char *type __attribute__((unused)), struct blob_attr *msg)
{
	struct ev_handler_node *ev_node = NULL;
	struct dm_path_node *dp_iter = NULL;

	ev_node = container_of(ev, struct ev_handler_node, ev_handler);
	if (!ev_node) {
		BBF_ERR("Failed to get event node");
		return;
	}

	if (!msg) {
		BBF_ERR("Failed to get message from event");
		return;
	}

	list_for_each_entry(dp_iter, &ev_node->dm_paths_list, list) {
		char dm_path[MAX_DM_PATH];

		replace_str(dp_iter->dm_path, ".{i}.", ".*.", dm_path, sizeof(dm_path));
		if (strlen(dm_path) == 0)
			return;

		char *str = blobmsg_format_json(msg, true);

		struct dmctx bbf_ctx = {
				.in_param = dm_path,
				.in_value = str,
				.nextlevel = false,
				.iscommand = false,
				.isevent = true,
				.isinfo = false,
				.dm_type = BBFDM_USP
		};

		bbf_init(&bbf_ctx);

		int ret = bbfdm_cmd_exec(&bbf_ctx, BBF_EVENT);
		if (ret)
			goto end;

		size_t blob_data_len = blob_raw_len(bbf_ctx.bb.head);

		if (blob_data_len) {
			struct event_args *e_args = (struct event_args *)calloc(1, sizeof(struct event_args));
			if (!e_args)
				goto end;

			snprintf(e_args->method_name, sizeof(e_args->method_name), "%s.event", BBFDM_DEFAULT_UBUS_OBJ);

			e_args->blob_data = (struct blob_attr *)calloc(1, blob_data_len);

			memcpy(e_args->blob_data, bbf_ctx.bb.head, blob_data_len);

			bbfdm_task_schedule(event_callback, NULL, e_args, 6);
		}

		end:
			bbf_cleanup(&bbf_ctx);
			FREE(str);
	}
}

static void add_dm_path(struct ev_handler_node *node, const char *dm_path)
{
	struct dm_path_node *dp_iter = NULL;

	if (!node || !dm_path)
		return;

	// Prevent duplicate dm_paths
	list_for_each_entry(dp_iter, &node->dm_paths_list, list) {
		if (strcmp(dp_iter->dm_path, dm_path) == 0)
			return;
	}

	struct dm_path_node *dp_node = (struct dm_path_node *)calloc(1, sizeof(struct dm_path_node));
	if (!dp_node) {
		BBF_ERR("Out of memory adding DM path!");
		return;
	}

	INIT_LIST_HEAD(&dp_node->list);

	dp_node->dm_path = strdup(dm_path);

	list_add_tail(&dp_node->list, &node->dm_paths_list);
}

static void add_ubus_event_handler(struct ubus_context *ctx, const char *ev_name, const char *dm_path, struct list_head *ev_list)
{
	struct ev_handler_node *node;

	if (!ctx || !ev_name || !dm_path || !ev_list)
		return;

	node = get_event_node(ev_list, ev_name);

	if (!node) {
		// Create a new event node
		node = (struct ev_handler_node *)calloc(1, sizeof(struct ev_handler_node));
		if (!node) {
			BBF_ERR("Out of memory!");
			return;
		}

		INIT_LIST_HEAD(&node->list);
		INIT_LIST_HEAD(&node->dm_paths_list);

		list_add_tail(&node->list, ev_list);

		node->ev_name = strdup(ev_name);
		node->ev_handler.cb = bbfdm_event_handler_cb;
		ubus_register_event_handler(ctx, &node->ev_handler, ev_name);
	}

	add_dm_path(node, dm_path);
}

int register_events_to_ubus(struct ubus_context *ctx, struct list_head *ev_list)
{
	struct dmctx bbf_ctx = {
			.in_param = ROOT_NODE,
			.nextlevel = false,
			.iscommand = false,
			.isevent = true,
			.isinfo = false,
			.dm_type = BBFDM_USP
	};

	if (ctx == NULL || ev_list == NULL)
		return -1;

	bbf_init(&bbf_ctx);

	if (0 == bbfdm_cmd_exec(&bbf_ctx, BBF_SCHEMA)) {
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		blobmsg_for_each_attr(cur, bbf_ctx.bb.head, rem) {
			struct blob_attr *tb[2] = {0};
			const struct blobmsg_policy p[2] = {
					{ "path", BLOBMSG_TYPE_STRING },
					{ "data", BLOBMSG_TYPE_STRING }
			};

			blobmsg_parse(p, 2, tb, blobmsg_data(cur), blobmsg_len(cur));

			char *param_name = (tb[0]) ? blobmsg_get_string(tb[0]) : "";
			char *event_name = (tb[1]) ? blobmsg_get_string(tb[1]) : "";

			if (!param_name || !event_name || !strlen(event_name))
				continue;

			add_ubus_event_handler(ctx, event_name, param_name, ev_list);
		}
	}

	bbf_cleanup(&bbf_ctx);

	return 0;
}

void free_ubus_event_handler(struct ubus_context *ctx, struct list_head *ev_list)
	{
	struct ev_handler_node *iter = NULL, *tmp = NULL;
	struct dm_path_node *dp_iter = NULL, *dp_tmp = NULL;

	if (!ctx || !ev_list)
		return;

	list_for_each_entry_safe(iter, tmp, ev_list, list) {
		ubus_unregister_event_handler(ctx, &iter->ev_handler);

		if (iter->ev_name)
			free(iter->ev_name);

		list_for_each_entry_safe(dp_iter, dp_tmp, &iter->dm_paths_list, list) {
			if (dp_iter->dm_path)
				free(dp_iter->dm_path);

			list_del(&dp_iter->list);
			free(dp_iter);
		}

		list_del(&iter->list);
		free(iter);
	}
}
