/*
 * get.c: Get handler for uspd
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

#include "get.h"
#include "get_helper.h"
#include "pretty_print.h"
#include "ipc.h"
#include "libbbf_api/dmentry.h"

#include <libubus.h>

void usp_get_value_async(usp_data_t *data, void *output)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;
	void *array = NULL;

	bbf_init(&data->bbf_ctx);
	blob_buf_init(&data->bb, 0);

	if (data->is_raw)
		array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = usp_dm_exec(&data->bbf_ctx, BBF_GET_VALUE);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			INFO("Preparing result for(%s)", data->bbf_ctx.in_param);

			if (data->is_raw) {
				struct dm_parameter *n = NULL;

				list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
					void *table = blobmsg_open_table(&data->bb, NULL);
					bb_add_string(&data->bb, "path", n->name);
					bb_add_string(&data->bb, "data", n->data);
					bb_add_string(&data->bb, "type", n->type);
					blobmsg_close_table(&data->bb, table);
				}
			} else {
				prepare_pretty_result(data->depth, &data->bb, &data->bbf_ctx);
			}
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	if (data->is_raw)
		blobmsg_close_array(&data->bb, array);

	if (!validate_msglen(data)) {
		ERR("IPC failed for path(%s)", data->bbf_ctx.in_param);
	}

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	memcpy(output, data->bb.head, blob_pad_len(data->bb.head));

	// free
	blob_buf_free(&data->bb);
	bbf_cleanup(&data->bbf_ctx);
}

void usp_get_value(usp_data_t *data)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;
	void *array = NULL;

	memset(&data->bb, 0, sizeof(struct blob_buf));

	bbf_init(&data->bbf_ctx);
	blob_buf_init(&data->bb, 0);

	if (data->is_raw)
		array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = usp_dm_exec(&data->bbf_ctx, BBF_GET_VALUE);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			INFO("Preparing result for(%s)", data->bbf_ctx.in_param);

			if (data->is_raw) {
				struct dm_parameter *n = NULL;
				void *table = NULL;

				list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
					table = blobmsg_open_table(&data->bb, NULL);
					bb_add_string(&data->bb, "path", n->name);
					bb_add_string(&data->bb, "data", n->data);
					bb_add_string(&data->bb, "type", n->type);
					blobmsg_close_table(&data->bb, table);
				}
			} else {
				prepare_pretty_result(data->depth, &data->bb, &data->bbf_ctx);
			}
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	if (data->is_raw)
		blobmsg_close_array(&data->bb, array);

	if (!validate_msglen(data)) {
		ERR("IPC failed");
	}

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	ubus_send_reply(data->ctx, data->req, data->bb.head);

	// free
	blob_buf_free(&data->bb);
	bbf_cleanup(&data->bbf_ctx);
}

void usp_get_names(usp_data_t *data)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = usp_dm_exec(&data->bbf_ctx, BBF_GET_NAME);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			struct dm_parameter *n = NULL;
			void *table = NULL;

			list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
				table = blobmsg_open_table(&data->bb, NULL);
				blobmsg_add_string(&data->bb, "path", n->name);
				blobmsg_add_string(&data->bb, "data", n->data);
				blobmsg_add_string(&data->bb, "type", n->type);
				blobmsg_close_table(&data->bb, table);
			}
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bb, array);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	bbf_cleanup(&data->bbf_ctx);
}

void usp_get_instances(usp_data_t *data)
{
	int fault = USP_ERR_OK;
	struct pathNode *pn;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = usp_dm_exec(&data->bbf_ctx, BBF_GET_INSTANCES);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			struct dm_parameter *n;


			list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
				void *table = blobmsg_open_table(&data->bb, NULL);
				blobmsg_add_string(&data->bb, "path", n->name);
				blobmsg_close_table(&data->bb, table);
			}
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bb, array);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	bbf_cleanup(&data->bbf_ctx);
}

static void fill_operate_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "path", param->name);
	blobmsg_add_string(bb, "type", param->type);
	blobmsg_add_string(bb, "data", param->additional_data);

	if (param->data) {
		void *array, *table;
		const char **in, **out;
		operation_args *args;
		int i;

		args = (operation_args *) param->data;
		in = args->in;
		if (in) {
			array = blobmsg_open_array(bb, "input");

			for (i = 0; in[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", in[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, array);
		}

		out = args->out;
		if (out) {
			array = blobmsg_open_array(bb, "output");

			for (i = 0; out[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", out[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, array);
		}
	}
}

static void fill_event_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "path", param->name);
	blobmsg_add_string(bb, "type", param->type);

	if (param->data) {
		event_args *ev;
		void *table;

		ev = (event_args *)param->data;

		if (ev->param) {
			const char **in = ev->param;
			void *key = blobmsg_open_array(bb, "input");

			for (int i = 0; in[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", in[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, key);
		}
	}
}

static void fill_param_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "path", param->name);
	blobmsg_add_string(bb, "data", param->data ? param->data : "0");
	blobmsg_add_string(bb, "type", param->type);

	if (param->additional_data) {
		const char **uniq_keys = (const char **)param->additional_data;
		void *key = blobmsg_open_array(bb, "input");
		void *table = NULL;

		for (int i = 0; uniq_keys[i] != NULL; i++) {
			table = blobmsg_open_table(bb, NULL);
			blobmsg_add_string(bb, "path", uniq_keys[i]);
			blobmsg_close_table(bb, table);
		}

		blobmsg_close_array(bb, key);
	}
}

int bbf_dm_get_supported_dm(usp_data_t *data)
{
	struct dm_parameter *param;
	struct pathNode *pn;
	int fault = USP_ERR_OK;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = usp_dm_exec(&data->bbf_ctx, BBF_GET_SUPPORTED_DM);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			INFO("Preparing result for(%s)", data->bbf_ctx.in_param);

			list_for_each_entry(param, &data->bbf_ctx.list_parameter, list) {
				int cmd = bbf_get_dm_type(param->type);

				void *table = blobmsg_open_table(&data->bb, NULL);
				if (cmd == DMT_COMMAND) {
					fill_operate_schema(&data->bb, param);
				} else if (cmd == DMT_EVENT) {
					fill_event_schema(&data->bb, param);
				} else {
					fill_param_schema(&data->bb, param);
				}
				blobmsg_close_table(&data->bb, table);
			}
		}
		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bb, array);

	bbf_cleanup(&data->bbf_ctx);

	return fault;
}
