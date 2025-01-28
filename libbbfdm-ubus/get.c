/*
 * get.c: Get handler for bbfdmd
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

void bbfdm_get(bbfdm_data_t *data, int method)
{
	struct pathNode *pn = NULL;
	int fault = 0;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bbf_ctx.bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = bbfdm_cmd_exec(&data->bbf_ctx, method);
		if (fault) {
			void *table = blobmsg_open_table(&data->bbf_ctx.bb, NULL);
			bb_add_string(&data->bbf_ctx.bb, "path", data->bbf_ctx.in_param);
			blobmsg_add_u32(&data->bbf_ctx.bb, "fault", bbf_fault_map(&data->bbf_ctx, fault));
			bb_add_string(&data->bbf_ctx.bb, "fault_msg", data->bbf_ctx.fault_msg);
			blobmsg_close_table(&data->bbf_ctx.bb, table);
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bbf_ctx.bb, array);

	if (!validate_msglen(data)) {
		BBF_ERR("IPC failed for path(%s)", data->bbf_ctx.in_param);
	}

	if (data->ctx && data->req) {
		ubus_send_reply(data->ctx, data->req, data->bbf_ctx.bb.head);
	}

	// Apply all bbfdm changes
	dmuci_commit_bbfdm();

	bbf_cleanup(&data->bbf_ctx);
}
