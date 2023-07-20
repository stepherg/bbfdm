/*
 * operate.c: Operate handler for bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "common.h"
#include "operate.h"
#include "get_helper.h"
#include "pretty_print.h"

#include <libubus.h>

static int bbfdm_dm_operate(bbfdm_data_t *data)
{
	int fault = 0;
	void *table, *array;

	bbf_init(&data->bbf_ctx);

	void *global_table = blobmsg_open_table(&data->bb, NULL);
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_string(&data->bb, "data", data->bbf_ctx.linker);

	fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_OPERATE);
	if (fault == 0) {
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

	return fault;
}

static void bbfdm_operate_cmd(bbfdm_data_t *data)
{
	void *array = blobmsg_open_array(&data->bb, "results");
	bbfdm_dm_operate(data);
	blobmsg_close_array(&data->bb, array);
}

void bbfdm_operate_cmd_async(bbfdm_data_t *data, void *output)
{
	blob_buf_init(&data->bb, 0);

	bbfdm_operate_cmd(data);

	memcpy(output, data->bb.head, blob_pad_len(data->bb.head));
	blob_buf_free(&data->bb);
}

void bbfdm_operate_cmd_sync(bbfdm_data_t *data)
{
	blob_buf_init(&data->bb, 0);

	bbfdm_operate_cmd(data);

	ubus_send_reply(data->ctx, data->req, data->bb.head);
	blob_buf_free(&data->bb);
}
