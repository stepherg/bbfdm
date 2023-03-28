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
#include "libbbf_api/dmentry.h"
#include <libubus.h>

static void usp_operate_cmd(usp_data_t *data, struct blob_buf *bb)
{
	struct dmctx bbf_ctx;
	int fault;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);
	bbf_init(&bbf_ctx, data->instance);

	LIST_HEAD(resolved_paths);

	fault = get_resolved_paths(&bbf_ctx, data->qpath, &resolved_paths);
	bbf_cleanup(&bbf_ctx);
	if (fault) {
		fill_err_code(bb, fault);
	} else {
		void *array;
		struct pathNode *rv;

		array = blobmsg_open_array(bb, "Results");
		list_for_each_entry(rv, &resolved_paths, list) {
			char path[MAX_DM_PATH] = {0};
			snprintf(path, MAX_DM_PATH, "%s%s", rv->path, data->op_action);

			void *table = blobmsg_open_table(bb, NULL);
			blobmsg_add_string(bb, "path", path);
			usp_dm_operate(bb, path, data->op_input, data->is_raw, data->instance);
			blobmsg_close_table(bb, table);
		}
		blobmsg_close_array(bb, array);
	}

	free_path_list(&resolved_paths);
}

void list_operate_schema(struct blob_buf *bb)
{
	struct dm_parameter *n;
	void *array;
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(BBFDM_USP);
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	bbf_dm_list_operate(&bbf_ctx);

	array = blobmsg_open_array(bb, "parameters");
	list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
		void *table = blobmsg_open_table(bb, NULL);

		bb_add_string(bb, "parameter", n->name);
		bb_add_string(bb, "type", n->additional_data);

		DEBUG("Operate node|%s|, type(%s)", n->name, n->type);

		// filling in and out parameter
		if (n->data) {
			int i;
			void *array_arg;
			operation_args *args = (operation_args *) n->data;
			const char **ap = args->in;

			if (ap) {
				array_arg = blobmsg_open_array(bb, "in");
				for (i = 0; ap[i] != NULL; i++)
					blobmsg_add_string(bb, NULL, ap[i]);

				blobmsg_close_array(bb, array_arg);
			}

			ap = args->out;
			if (ap) {
				array_arg = blobmsg_open_array(bb, "out");
				for (i = 0; ap[i] != NULL; i++)
					blobmsg_add_string(bb, NULL, ap[i]);

				blobmsg_close_array(bb, array_arg);
			}
		}
		blobmsg_close_table(bb, table);
	}

	blobmsg_close_array(bb, array);
	bbf_cleanup(&bbf_ctx);
}

void usp_operate_cmd_async(usp_data_t *data, void *output)
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	usp_operate_cmd(data, &bb);

	if (!validate_msglen(&bb)) {
		ERR("IPC failed for path(%s)", data->qpath);
	}

	memcpy(output, bb.head, blob_pad_len(bb.head));

	// free
	blob_buf_free(&bb);
}

void usp_operate_cmd_sync(usp_data_t *data)
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	usp_operate_cmd(data, &bb);

	if (!validate_msglen(&bb)) {
		ERR("IPC failed for path(%s)", data->qpath);
	}

	ubus_send_reply(data->ctx, data->req, bb.head);

	// free
	blob_buf_free(&bb);
}
