/*
 * operate.c: Operate handler for uspd
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
#include "operate.h"
#include "get_helper.h"
#include "pretty_print.h"
#include "ipc.h"

#include <libubus.h>

static int usp_dm_operate(usp_data_t *data)
{
	int fault = 0, ret = 0;
	void *table, *array;

	bbf_init(&data->bbf_ctx);

	ret = usp_dm_exec(&data->bbf_ctx, BBF_OPERATE);
	// This switch should be removed in the future and will be treated internally
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

	void *global_table = blobmsg_open_table(&data->bb, NULL);
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_string(&data->bb, "data", data->bbf_ctx.linker);

	if (ret == CMD_SUCCESS) {
		struct dm_parameter *n;

		if (data->is_raw) {
			array = blobmsg_open_array(&data->bb, "output");
			list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
				table = blobmsg_open_table(&data->bb, NULL);
				bb_add_string(&data->bb, "path", n->name);
				bb_add_string(&data->bb, "data", n->data);
				bb_add_string(&data->bb, "type", n->type);
				blobmsg_close_table(&data->bb, table);
			}
			blobmsg_close_array(&data->bb, array);
		} else {
			LIST_HEAD(pv_local);

			list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
				add_pv_list(n->name, n->data, n->type, &pv_local);
			}

			array = blobmsg_open_array(&data->bb, "output");
			table = blobmsg_open_table(&data->bb, NULL);
			prepare_result_blob(&data->bb, &pv_local);
			blobmsg_close_table(&data->bb, table);
			blobmsg_close_array(&data->bb, array);

			free_pv_list(&pv_local);
		}
	} else {
		blobmsg_add_u32(&data->bb, "fault", fault);
		bb_add_string(&data->bb, "fault_msg", "");
	}

	blobmsg_close_table(&data->bb, global_table);

	bbf_cleanup(&data->bbf_ctx);

	if (fault != USP_ERR_OK) {
		WARNING("Fault(%d) path(%s) input(%s)", fault, data->bbf_ctx.in_param, data->bbf_ctx.in_value);
		return fault;
	}

	return USP_ERR_OK;
}

static void usp_operate_cmd(usp_data_t *data)
{
	void *array = blobmsg_open_array(&data->bb, "results");
	usp_dm_operate(data);
	blobmsg_close_array(&data->bb, array);
}

void usp_operate_cmd_async(usp_data_t *data, void *output)
{
	blob_buf_init(&data->bb, 0);

	usp_operate_cmd(data);

	memcpy(output, data->bb.head, blob_pad_len(data->bb.head));
	blob_buf_free(&data->bb);
}

void usp_operate_cmd_sync(usp_data_t *data)
{
	blob_buf_init(&data->bb, 0);

	usp_operate_cmd(data);

	ubus_send_reply(data->ctx, data->req, data->bb.head);
	blob_buf_free(&data->bb);
}
