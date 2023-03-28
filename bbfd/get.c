/*
 * get.c: Get handler for uspd
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

#include "get.h"
#include "get_helper.h"
#include "pretty_print.h"
#include "ipc.h"
#include <libubus.h>
#include <libbbfdm/dmbbfcommon.h>

void init_dmmap(void)
{
	struct dmctx bbf_ctx;
	LIST_HEAD(resolved_list);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	get_resolved_paths(&bbf_ctx, ROOT_NODE, &resolved_list);

	// Commit dmmap
	bbf_uci_commit_bbfdm();

	free_path_list(&resolved_list);
	bbf_cleanup(&bbf_ctx);
}

void usp_get_value_async(usp_data_t *data, void *output)
{
	struct blob_buf bb;
	int fault = USP_ERR_OK;
	struct dmctx bbf_ctx;

	LIST_HEAD(resolved_list);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);
	// Fill the blob_buf for sharing the result
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);
	INFO("Preparing result for(%s)", data->qpath);

	fault = get_resolved_paths(&bbf_ctx, data->qpath, &resolved_list);
	if (fault) {
		fill_err_code(&bb, fault);
	} else {
		if (data->is_raw)
			prepare_result_raw(&bb, &bbf_ctx, &resolved_list);
		else
			prepare_pretty_result(data->depth, data->qpath, &bb, &bbf_ctx, &resolved_list);
	}

	if (!validate_msglen(&bb)) {
		ERR("IPC failed for path(%s)", data->qpath);
	}

	memcpy(output, bb.head, blob_pad_len(bb.head));

	// free
	blob_buf_free(&bb);
	free_path_list(&resolved_list);
	bbf_cleanup(&bbf_ctx);
}

void usp_get_value(usp_data_t *data)
{
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	struct blob_buf bb;
	int fault = USP_ERR_OK;
	char *qpath;
	bool raw;
	uint8_t depth;
	struct dmctx bbf_ctx;

	ctx = data->ctx;
	req = data->req;
	qpath = data->qpath;
	raw = data->is_raw;
	depth = data->depth;

	LIST_HEAD(resolved_list);

	// Fill the blob_buf for sharing the result
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);
	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);

	fault = get_resolved_paths(&bbf_ctx, qpath, &resolved_list);

	INFO("Preparing result for(%s), fault(%d)", qpath, fault);
	if (fault) {
		fill_err_code(&bb, fault);
	} else {
		if (raw)
			prepare_result_raw(&bb, &bbf_ctx, &resolved_list);
		else
			prepare_pretty_result(depth, qpath, &bb, &bbf_ctx, &resolved_list);
	}

	if (!validate_msglen(&bb)) {
		ERR("IPC failed for path(%s)", data->qpath);
	}

	ubus_send_reply(ctx, req, bb.head);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		bbf_uci_commit_bbfdm();

	// free
	blob_buf_free(&bb);
	free_path_list(&resolved_list);
	bbf_cleanup(&bbf_ctx);
}

void usp_validate_path(usp_data_t *data)
{
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	struct blob_buf bb;
	int fault = USP_ERR_OK;
	char *qpath;
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);

	ctx = data->ctx;
	req = data->req;
	qpath = data->qpath;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	fault = bbf_dm_get_names(&bbf_ctx, qpath, data->next_level);
	if (!list_empty(&bbf_ctx.list_parameter)) {
		size_t len = DM_STRLEN(qpath);

		if (len > 0) {
			if (qpath[len - 1] == '.')
				qpath[len - 1] = '\0';
			blobmsg_add_string(&bb, "parameter", qpath);
		}
	}

	if (fault)
		fill_err_code(&bb, fault);

	ubus_send_reply(ctx, req, bb.head);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		bbf_uci_commit_bbfdm();

	// free
	blob_buf_free(&bb);
	bbf_cleanup(&bbf_ctx);
}

void usp_get_instance(usp_data_t *data)
{
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	struct blob_buf bb;
	int fault = USP_ERR_OK;
	char *qpath;
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);

	ctx = data->ctx;
	req = data->req;
	qpath = data->qpath;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	fault = bbf_dm_get_instances(&bbf_ctx, qpath, data->next_level);

	if (fault) {
		fill_err_code(&bb, fault);
	} else {
		struct dm_parameter *n;
		void *array;

		array = blobmsg_open_array(&bb, "parameters");
		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			void *table = blobmsg_open_table(&bb, NULL);

			blobmsg_add_string(&bb, "parameter", n->name);
			blobmsg_close_table(&bb, table);
		}
		blobmsg_close_array(&bb, array);
	}

	ubus_send_reply(ctx, req, bb.head);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		bbf_uci_commit_bbfdm();

	// free
	blob_buf_free(&bb);
	bbf_cleanup(&bbf_ctx);
}

void usp_get_name(usp_data_t *data)
{
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	struct blob_buf bb;
	int fault;
	char *qpath;
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);

	ctx = data->ctx;
	req = data->req;
	qpath = data->qpath;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	fault = bbf_dm_get_names(&bbf_ctx, qpath, data->next_level);
	if (fault) {
		fill_err_code(&bb, fault);
	} else {
		void *array;
		struct dm_parameter *n;

		array = blobmsg_open_array(&bb, "parameters");
		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			void *table = blobmsg_open_table(&bb, NULL);

			blobmsg_add_string(&bb, "parameter", n->name);
			blobmsg_add_string(&bb, "writable", n->data);
			blobmsg_add_string(&bb, "type", n->type);
			blobmsg_close_table(&bb, table);
		}
		blobmsg_close_array(&bb, array);
	}

	ubus_send_reply(ctx, req, bb.head);

	// Commit all bbfdm changes if transaction is not in progress
	if (is_transaction_running() == false)
		bbf_uci_commit_bbfdm();

	// free
	blob_buf_free(&bb);
	bbf_cleanup(&bbf_ctx);
}

void get_mpath(usp_data_t *data)
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (data->is_raw) {
		void *array = blobmsg_open_array(&bb, "parameters");
		bbf_get_raw(data, &bb);
		blobmsg_close_array(&bb, array);
	} else {
		bbf_get_blob(data, &bb);
	}

	ubus_send_reply(data->ctx, data->req, bb.head);
	blob_buf_free(&bb);
}

