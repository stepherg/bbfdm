/*
 * operate.c: Operate handler for uspd
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

#include "common.h"
#include "operate.h"
#include "get_helper.h"
#include "pretty_print.h"
#include "ipc.h"

#include <libubus.h>

static int usp_dm_operate(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	int fault = 0, ret = 0;
	void *table, *array;

	bbf_init(bbf_ctx);

	ret = usp_dm_exec(bbf_ctx, BBF_OPERATE);
	// This switch should be removed in the future and will be treated internally
	// but lets do that after removing old libbbfdm and uspd
	switch (ret) {
	case CMD_NOT_FOUND:
		fault = USP_FAULT_INVALID_PATH;
		break;
	case CMD_INVALID_ARGUMENTS:
		fault = USP_FAULT_INVALID_ARGUMENT;
		break;
	case CMD_FAIL:
		fault = USP_FAULT_COMMAND_FAILURE;
		break;
	case CMD_SUCCESS:
		fault = USP_ERR_OK;
		DEBUG("command executed successfully");
		break;
	default:
		WARNING("Case(%d) not defined", fault);
		fault = USP_FAULT_INVALID_PATH;
		break;
	}

	if (ret == CMD_SUCCESS) {
		struct dm_parameter *n;

		if (data->is_raw) {
			array = blobmsg_open_array(bb, "parameters");
			list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
				table = blobmsg_open_table(bb, NULL);
				bb_add_string(bb, "parameter", n->name);
				bb_add_string(bb, "value", n->data);
				bb_add_string(bb, "type", n->type);
				blobmsg_close_table(bb, table);
			}
			blobmsg_close_array(bb, array);
		} else {
			LIST_HEAD(pv_local);

			list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
				add_pv_list(n->name, n->data, n->type, &pv_local);
			}

			array = blobmsg_open_array(bb, "result");
			table = blobmsg_open_table(bb, NULL);
			prepare_result_blob(bb, &pv_local);
			blobmsg_close_table(bb, table);
			blobmsg_close_array(bb, array);

			free_pv_list(&pv_local);
		}
	} else {
		fill_err_code(bb, fault);
	}

	bbf_cleanup(bbf_ctx);

	if (fault != USP_ERR_OK) {
		WARNING("Fault(%d) path(%s) input(%s)", fault, bbf_ctx->in_param, bbf_ctx->in_value);
		return fault;
	}

	return USP_ERR_OK;
}

static void usp_operate_cmd(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	void *array = blobmsg_open_array(bb, "Results");

	void *table = blobmsg_open_table(bb, NULL);
	blobmsg_add_string(bb, "command", bbf_ctx->in_param);
	blobmsg_add_string(bb, "command_key", bbf_ctx->linker);
	usp_dm_operate(bbf_ctx, data, bb);
	blobmsg_close_table(bb, table);

	blobmsg_close_array(bb, array);
}

void usp_operate_cmd_async(struct dmctx *bbf_ctx, usp_data_t *data, void *output)
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	usp_operate_cmd(bbf_ctx, data, &bb);

	if (!validate_msglen(&bb)) {
		ERR("IPC failed for path(%s)", bbf_ctx->in_param);
	}

	memcpy(output, bb.head, blob_pad_len(bb.head));

	// free
	blob_buf_free(&bb);
}

void usp_operate_cmd_sync(struct dmctx *bbf_ctx, usp_data_t *data)
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	usp_operate_cmd(bbf_ctx, data, &bb);

	if (!validate_msglen(&bb)) {
		ERR("IPC failed for path(%s)", bbf_ctx->in_param);
	}

	ubus_send_reply(data->ctx, data->req, bb.head);

	// free
	blob_buf_free(&bb);
}
