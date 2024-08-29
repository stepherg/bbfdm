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

void bbfdm_operate_cmd(bbfdm_data_t *data, void *output)
{
	int fault = 0;

	memset(&data->bb, 0, sizeof(struct blob_buf));

	bbf_init(&data->bbf_ctx);
	blob_buf_init(&data->bb, 0);

	void *global_array = blobmsg_open_array(&data->bb, "results");

	void *global_table = blobmsg_open_table(&data->bb, NULL);
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_string(&data->bb, "data", data->bbf_ctx.linker);

	fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_OPERATE);
	if (fault == 0) {
		void *table = NULL, *array = NULL;
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		if (data->is_raw) {
			array = blobmsg_open_array(&data->bb, "output");
			blobmsg_for_each_attr(cur, data->bbf_ctx.bb.head, rem) {
				blobmsg_add_blob(&data->bb, cur);
			}
			blobmsg_close_array(&data->bb, array);
		} else {
			LIST_HEAD(pv_local);

			blobmsg_for_each_attr(cur, data->bbf_ctx.bb.head, rem) {
				struct blob_attr *tb[3] = {0};
				const struct blobmsg_policy p[3] = {
						{ "path", BLOBMSG_TYPE_STRING },
						{ "data", BLOBMSG_TYPE_STRING },
						{ "type", BLOBMSG_TYPE_STRING }
				};

				blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

				char *op_name = (tb[0]) ? blobmsg_get_string(tb[0]) : "";
				char *op_data = (tb[1]) ? blobmsg_get_string(tb[1]) : "";
				char *op_type = (tb[2]) ? blobmsg_get_string(tb[2]) : "";

				add_pv_list(op_name, op_data, op_type, &pv_local);
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
		bb_add_string(&data->bb, "fault_msg", data->bbf_ctx.fault_msg);
	}

	blobmsg_close_table(&data->bb, global_table);

	blobmsg_close_array(&data->bb, global_array);

	if (output)
		memcpy(output, data->bb.head, blob_pad_len(data->bb.head));
	else
		ubus_send_reply(data->ctx, data->req, data->bb.head);

	blob_buf_free(&data->bb);
	bbf_cleanup(&data->bbf_ctx);
}
