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

	char *event_dm_path = get_events_dm_path(&u->event_handlers, type);
	if (event_dm_path == NULL)
		return;

	char dm_path[MAX_DM_PATH];

	replace_str(event_dm_path, ".{i}.", ".*.", dm_path, sizeof(dm_path));
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
			.disable_mservice_browse = true,
			.dm_type = BBFDM_USP
	};

	bbf_init(&bbf_ctx);

	int ret = bbfdm_cmd_exec(&bbf_ctx, BBF_EVENT);
	if (ret)
		goto end;

	cancel_instance_refresh_timer(ctx);

	char method_name[256] = {0};

	snprintf(method_name, sizeof(method_name), "%s.%s", DM_STRLEN(u->config.out_root_obj) ? u->config.out_root_obj : u->config.out_name, BBF_EVENT_NAME);

	ubus_send_event(ctx, method_name, bbf_ctx.bb.head);
	INFO("Event[%s], for [%s] sent", method_name, dm_path);

	register_instance_refresh_timer(ctx, 2000);

end:
	bbf_cleanup(&bbf_ctx);
	FREE(str);
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
			.dm_type = BBFDM_USP
	};

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

			struct ubus_event_handler *ev = (struct ubus_event_handler *)malloc(sizeof(struct ubus_event_handler));
			if (!ev) {
				ERR("Out of memory!");
				err = -1;
				goto end;
			}

			memset(ev, 0, sizeof(struct ubus_event_handler));
			ev->cb = bbfdm_event_handler;

			if (0 != ubus_register_event_handler(ctx, ev, event_name)) {
				ERR("Failed to register: %s", event_name);
				err = -1;
				goto end;
			}

			add_ubus_event_handler(ev, event_name, param_name, ev_list);
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
