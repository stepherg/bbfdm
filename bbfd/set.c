/*
 * set.c: Set handler for uspd
 *
 * Copyright (C) 2019 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
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

#include "set.h"
#include "get_helper.h"
#include <libubus.h>
#include <libbbfdm/dmbbfcommon.h>


static const struct blobmsg_policy dm_setm_value_policy[] = {
	[DM_SET_V_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_V_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
};

int usp_set_value(usp_data_t *data)
{
	struct blob_buf bb;
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	void *array = NULL;
	struct pvNode *pv = NULL;
	struct dmctx bbf_ctx;
	int fault = USP_ERR_OK;
	struct param_fault *p = NULL;
	void *table;
	bool fault_occured = false;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);

	ctx = data->ctx;
	req = data->req;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	list_for_each_entry(pv, data->pv_list, list) {
		fault = usp_dm_set(&bbf_ctx, pv->param, pv->val);
		if (fault == 0)
			fault = usp_dm_exec_apply(&bbf_ctx, CMD_SET_VALUE);

		if (fault) {
			if (fault_occured == false) {
				fault_occured = true;
				if (!array)
					array = blobmsg_open_array(&bb, "parameters");
			}

			while (bbf_ctx.list_fault_param.next != &bbf_ctx.list_fault_param) {
				p = list_entry(bbf_ctx.list_fault_param.next, struct param_fault, list);
				table = blobmsg_open_table(&bb, NULL);
				bb_add_string(&bb, "path", p->name);
				blobmsg_add_u8(&bb, "status", false);
				blobmsg_add_u32(&bb, "fault", (uint32_t)p->fault);
				blobmsg_close_table(&bb, table);
				del_list_fault_param(p);
			}
		}
	}

	if (fault_occured == false)
		blobmsg_add_u8(&bb, "status", true);

	if (array)
		blobmsg_close_array(&bb, array);

	ubus_send_reply(ctx, req, bb.head);

	// free
	blob_buf_free(&bb);
	bbf_cleanup(&bbf_ctx);

	return fault;
}

int fill_pvlist_from_table(char *bpath, struct blob_attr *blob_value, struct list_head *pv_list, int instance)
{
	struct blob_attr *attr;
	char path[MAX_DM_PATH], value[MAX_DM_VALUE];
	struct dmctx bbf_ctx;
	int fault = USP_ERR_OK;
	struct pathNode *p;
	size_t tlen;
	LIST_HEAD(resolved_paths);

	if (!blob_value)
		return 0;

	tlen = (size_t)blobmsg_data_len(blob_value);
	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	bbf_init(&bbf_ctx, instance);

	fault = get_resolved_paths(&bbf_ctx, bpath, &resolved_paths);
	if (fault) {
		bbf_cleanup(&bbf_ctx);
		free_path_list(&resolved_paths);
		return fault;
	}

	__blob_for_each_attr(attr, blobmsg_data(blob_value), tlen) {
		struct blobmsg_hdr *hdr = blob_data(attr);

		switch (blob_id(attr)) {
		case BLOBMSG_TYPE_STRING:
			snprintf(value, MAX_DM_VALUE, "%s", blobmsg_get_string(attr));
			break;
		case BLOBMSG_TYPE_INT8:
			snprintf(value, MAX_DM_VALUE, "%d", blobmsg_get_u8(attr));
			break;
		case BLOBMSG_TYPE_INT16:
			snprintf(value, MAX_DM_VALUE, "%d", blobmsg_get_u16(attr));
			break;
		case BLOBMSG_TYPE_INT32:
			snprintf(value, MAX_DM_VALUE, "%u", blobmsg_get_u32(attr));
			break;
		case BLOBMSG_TYPE_INT64:
			snprintf(value, MAX_DM_VALUE, "%"PRIu64"", blobmsg_get_u64(attr));
			break;
		default:
			INFO("Unhandled set request type|%x|", blob_id(attr));
			bbf_cleanup(&bbf_ctx);
			free_path_list(&resolved_paths);
			return USP_FAULT_INVALID_ARGUMENT;
		}

		list_for_each_entry(p, &resolved_paths, list) {
			snprintf(path, MAX_DM_PATH, "%s%s", p->path, (char *)hdr->name);
			add_pv_node(path, value, NULL, pv_list);
		}
	}

	bbf_cleanup(&bbf_ctx);
	free_path_list(&resolved_paths);

	return fault;
}

int fill_pvlist_from_tuple(struct blob_attr *blob, struct list_head *pv_list)
{
	size_t rem;
	struct blob_attr *cur;

	blobmsg_for_each_attr(cur, blob, rem) {
		struct blob_attr *tb[__DM_SET_V_MAX];
		char *path, *value, *key;

		key = NULL;
		blobmsg_parse(dm_setm_value_policy, __DM_SET_V_MAX, tb,
			      blobmsg_data(cur), blobmsg_len(cur));

		// ignore the tuples which does not have path and values
		if (!tb[DM_SET_V_PATH] || !tb[DM_SET_V_VALUE])
			continue;

		path = blobmsg_get_string(tb[DM_SET_V_PATH]);
		value = blobmsg_get_string(tb[DM_SET_V_VALUE]);

		add_pv_node(path, value, key, pv_list);
	}

	return 0;
}

int fill_pvlist_from_path(char *path, struct blob_attr *val_blob, struct list_head *pv_list, int instance)
{
	int fault = USP_ERR_OK;
	size_t plen;
	char *val = NULL;
	struct dmctx bbf_ctx;

	LIST_HEAD(resolved_paths);

	if (!val_blob)
		return 0;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	bbf_init(&bbf_ctx, instance);

	plen = DM_STRLEN(path);
	if (plen == 0)
		fault = USP_FAULT_INVALID_PATH;

	if (fault == USP_ERR_OK) {
		if (path[plen - 1] == '.')
			fault = USP_FAULT_INVALID_PATH;
	}

	if (fault == USP_ERR_OK)
		fault = get_resolved_paths(&bbf_ctx, path, &resolved_paths);

	if (fault == USP_ERR_OK) {
		struct pathNode *p;

		list_for_each_entry(p, &resolved_paths, list) {
			val = blobmsg_get_string(val_blob);
			add_pv_node(p->path, val, NULL, pv_list);
		}
	}

	free_path_list(&resolved_paths);
	bbf_cleanup(&bbf_ctx);

	return fault;
}
