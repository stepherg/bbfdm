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
#include "get_helper.h"

#include <libubus.h>

void bbfdm_operate_cmd(bbfdm_data_t *data, void *output)
{
	int fault = 0;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bbf_ctx.bb, "results");

	void *table = blobmsg_open_table(&data->bbf_ctx.bb, NULL);
	bb_add_string(&data->bbf_ctx.bb, "path", data->bbf_ctx.in_param);
	bb_add_string(&data->bbf_ctx.bb, "data", data->bbf_ctx.linker);
	void *output_array = blobmsg_open_array(&data->bbf_ctx.bb, "output");

	fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_OPERATE);
	if (fault) {
		void *fault_table = blobmsg_open_table(&data->bbf_ctx.bb, NULL);
		blobmsg_add_u32(&data->bbf_ctx.bb, "fault", fault);
		bb_add_string(&data->bbf_ctx.bb, "fault_msg", data->bbf_ctx.fault_msg);
		blobmsg_close_table(&data->bbf_ctx.bb, fault_table);
	}

	blobmsg_close_array(&data->bbf_ctx.bb, output_array);
	blobmsg_close_table(&data->bbf_ctx.bb, table);

	blobmsg_close_array(&data->bbf_ctx.bb, array);

	if (output) {
		memcpy(output, data->bbf_ctx.bb.head, blob_pad_len(data->bbf_ctx.bb.head));
	} else if (data->ctx && data->req) {
		ubus_send_reply(data->ctx, data->req, data->bbf_ctx.bb.head);
	}

	/* Commit or Revert changes in uci files */
	if (data->bbf_ctx.modified_uci_head != NULL &&
		!list_empty(data->bbf_ctx.modified_uci_head)) {
		struct dm_modified_uci *m;
		struct blob_buf bb = {0};

		blob_buf_init(&bb, 0);
		void *array = blobmsg_open_array(&bb, "services");

		list_for_each_entry(m, data->bbf_ctx.modified_uci_head, list) {
			blobmsg_add_string(&bb, NULL, m->uci_file);
		}

		blobmsg_close_array(&bb, array);

		blobmsg_add_string(&bb, "proto", (data->bbf_ctx.dm_type == BBFDM_USP) ? "usp" : "both");
		blobmsg_add_u8(&bb, "reload", (fault == 0) ? true : false);

		dmubus_call_blob_msg_timeout("bbf.config", (fault == 0) ? "commit" : "revert", &bb, 10000);

		blob_buf_free(&bb);
	}

	bbf_cleanup(&data->bbf_ctx);
}
