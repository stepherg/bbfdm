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
		blobmsg_add_u32(&data->bbf_ctx.bb, "fault", fault);
		bb_add_string(&data->bbf_ctx.bb, "fault_msg", data->bbf_ctx.fault_msg);
	}

	blobmsg_close_array(&data->bbf_ctx.bb, output_array);
	blobmsg_close_table(&data->bbf_ctx.bb, table);

	blobmsg_close_array(&data->bbf_ctx.bb, array);

	if (output) {
		memcpy(output, data->bbf_ctx.bb.head, blob_pad_len(data->bbf_ctx.bb.head));
	} else if (data->ctx && data->req) {
		ubus_send_reply(data->ctx, data->req, data->bbf_ctx.bb.head);
	}

	bbf_cleanup(&data->bbf_ctx);
}
