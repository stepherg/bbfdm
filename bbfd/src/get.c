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

void usp_get_value_async(struct dmctx *bbf_ctx, usp_data_t *data, void *output)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;
	struct blob_buf bb;
	void *array = NULL;

	memset(&bb, 0, sizeof(struct blob_buf));

	bbf_init(bbf_ctx);
	blob_buf_init(&bb, 0);

	if (data->is_raw)
		array = blobmsg_open_array(&bb, "parameters");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(bbf_ctx);
		bbf_ctx->in_param = pn->path;
		fault = usp_dm_exec(bbf_ctx, BBF_GET_VALUE);
		if (fault) {
			blob_buf_free(&bb);
			blob_buf_init(&bb, 0);
			fill_err_code(&bb, bbf_ctx->dm_type, fault);
			break;
		} else {
			INFO("Preparing result for(%s)", bbf_ctx->in_param);

			if (data->is_raw)
				prepare_result_raw(&bb, bbf_ctx);
			else
				prepare_pretty_result(data->depth, &bb, bbf_ctx);
		}
		bbf_sub_cleanup(bbf_ctx);
	}

	if (data->is_raw)
		blobmsg_close_array(&bb, array);

	if (!validate_msglen(&bb, bbf_ctx->dm_type)) {
		ERR("IPC failed for path(%s)", bbf_ctx->in_param);
	}

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	memcpy(output, bb.head, blob_pad_len(bb.head));

	// free
	blob_buf_free(&bb);
	bbf_cleanup(bbf_ctx);
}

void usp_get_value(struct dmctx *bbf_ctx, usp_data_t *data)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;
	void *array = NULL;
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));

	bbf_init(bbf_ctx);
	blob_buf_init(&bb, 0);

	if (data->is_raw)
		array = blobmsg_open_array(&bb, "parameters");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(bbf_ctx);
		bbf_ctx->in_param = pn->path;
		fault = usp_dm_exec(bbf_ctx, BBF_GET_VALUE);
		if (fault) {
			blob_buf_free(&bb);
			blob_buf_init(&bb, 0);
			fill_err_code(&bb, bbf_ctx->dm_type, fault);
			break;
		} else {
			INFO("Preparing result for(%s)", bbf_ctx->in_param);

			if (data->is_raw)
				prepare_result_raw(&bb, bbf_ctx);
			else
				prepare_pretty_result(data->depth, &bb, bbf_ctx);
		}

		bbf_sub_cleanup(bbf_ctx);
	}

	if (data->is_raw)
		blobmsg_close_array(&bb, array);

	if (!validate_msglen(&bb, bbf_ctx->dm_type)) {
		ERR("IPC failed");
	}

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	ubus_send_reply(data->ctx, data->req, bb.head);

	// free
	blob_buf_free(&bb);
	bbf_cleanup(bbf_ctx);
}

void usp_get_names(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;
	void *array = NULL;

	bbf_init(bbf_ctx);

	array = blobmsg_open_array(bb, "parameters");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(bbf_ctx);
		bbf_ctx->in_param = pn->path;
		fault = usp_dm_exec(bbf_ctx, BBF_GET_NAME);
		if (fault) {
			void *table = blobmsg_open_table(bb,NULL);
			blobmsg_add_string(bb, "parameter", bbf_ctx->in_param);
			fill_err_code(bb, bbf_ctx->dm_type, fault);
			blobmsg_close_table(bb, table);
		} else {
			struct dm_parameter *n;

			list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
				void *table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "parameter", n->name);
				blobmsg_add_string(bb, "writable", n->data);
				blobmsg_add_string(bb, "type", n->type);
				blobmsg_close_table(bb, table);
			}
		}

		bbf_sub_cleanup(bbf_ctx);
	}

	blobmsg_close_array(bb, array);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	bbf_cleanup(bbf_ctx);
}

void usp_get_instances(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;
	void *array = NULL;

	bbf_init(bbf_ctx);

	array = blobmsg_open_array(bb, "parameters");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(bbf_ctx);
		bbf_ctx->in_param = pn->path;
		fault = usp_dm_exec(bbf_ctx, BBF_GET_INSTANCES);
		if (fault) {
			void *table = blobmsg_open_table(bb,NULL);
			blobmsg_add_string(bb, "parameter", bbf_ctx->in_param);
			fill_err_code(bb, bbf_ctx->dm_type, fault);
			blobmsg_close_table(bb, table);
		} else {
			struct dm_parameter *n;

			list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
				void *table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "parameter", n->name);
				blobmsg_close_table(bb, table);
			}
		}

		bbf_sub_cleanup(bbf_ctx);
	}

	blobmsg_close_array(bb, array);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	bbf_cleanup(bbf_ctx);
}

static void fill_operate_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter", param->name);
	blobmsg_add_string(bb, "type", param->type);
	blobmsg_add_string(bb, "cmd_type", param->additional_data);

	if (param->data) {
		void *array;
		const char **in, **out;
		operation_args *args;
		int i;

		args = (operation_args *) param->data;
		in = args->in;
		if (in) {
			array = blobmsg_open_array(bb, "in");
			for (i = 0; in[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, in[i]);

			blobmsg_close_array(bb, array);
		}

		out = args->out;
		if (out) {
			array = blobmsg_open_array(bb, "out");
			for (i = 0; out[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, out[i]);

			blobmsg_close_array(bb, array);
		}
	}
}

static void fill_event_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter",param->name);
	blobmsg_add_string(bb,"type",param->type);

	if (param->data) {
		event_args *ev;

		ev = (event_args *)param->data;

		if (ev->param) {
			const char **in = ev->param;
			void *key = blobmsg_open_array(bb, "in");

			for (int i = 0; in[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, in[i]);
			blobmsg_close_array(bb, key);
		}
	}
}

static void fill_param_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter", param->name);
	blobmsg_add_string(bb, "writable", param->data ? param->data : "0");
	blobmsg_add_string(bb, "type", param->type);

	if (param->additional_data) {
		const char **uniq_keys = (const char **)param->additional_data;
		void *key = blobmsg_open_array(bb, "unique_keys");

		for (int i = 0; uniq_keys[i] != NULL; i++)
			blobmsg_add_string(bb, NULL, uniq_keys[i]);

		blobmsg_close_array(bb, key);
	}
}

int bbf_dm_get_supported_dm(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	struct dm_parameter *param;
	struct pathNode *pn;
	int fault = USP_ERR_OK;

	bbf_init(bbf_ctx);

	void *array = blobmsg_open_array(bb, "parameters");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(bbf_ctx);
		bbf_ctx->in_param = pn->path;
		fault = usp_dm_exec(bbf_ctx, BBF_GET_SUPPORTED_DM);
		if (fault) {
			void *table = blobmsg_open_table(bb,NULL);
			blobmsg_add_string(bb, "parameter", bbf_ctx->in_param);
			blobmsg_add_u32(bb, "fault", fault);
			blobmsg_close_table(bb, table);
		} else {
			INFO("Preparing result for(%s)", bbf_ctx->in_param);

			list_for_each_entry(param, &bbf_ctx->list_parameter, list) {
				int cmd = bbf_get_dm_type(param->type);

				void *table = blobmsg_open_table(bb,NULL);
				if (cmd == DMT_COMMAND) {
					fill_operate_schema(bb, param);
				} else if (cmd == DMT_EVENT) {
					fill_event_schema(bb, param);
				} else {
					fill_param_schema(bb, param);
				}

				blobmsg_close_table(bb, table);
			}
		}
		bbf_sub_cleanup(bbf_ctx);
	}

	blobmsg_close_array(bb, array);

	bbf_cleanup(bbf_ctx);

	return fault;
}
