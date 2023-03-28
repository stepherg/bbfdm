/*
 * add_delete.c: Add/Delete handler for uspd
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
#include "add_delete.h"
#include "get_helper.h"
#include "libbbf_api/dmentry.h"

typedef int (*ADD_DEL_CB_T)(struct dmctx *bbf_ctx, struct blob_buf *bb, char *path, const char *pkey);

static int handle_add_del_req(usp_data_t *data, struct blob_buf *bb, ADD_DEL_CB_T req_cb)
{
	int fault = 0;
	struct dmctx bbf_ctx;
	LIST_HEAD(resolved_paths);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	set_bbfdatamodel_type(data->proto);

	bbf_init(&bbf_ctx, data->instance);

	fault = get_resolved_paths(&bbf_ctx, data->qpath, &resolved_paths);
	if (fault) {
		fill_resolve_err(bb, data->qpath, fault);
	} else {
		struct pathNode *p;
		void *array;

		array = blobmsg_open_array(bb, "parameters");
		list_for_each_entry(p, &resolved_paths, list) {
			void *table = blobmsg_open_table(bb, NULL);
			int op_fault;

			op_fault = req_cb(&bbf_ctx, bb, p->path, data->set_key);
			blobmsg_close_table(bb, table);
			// Preserve the first error
			if (fault == USP_ERR_OK && op_fault != USP_ERR_OK)
				fault = op_fault;
		}
		blobmsg_close_array(bb, array);
	}

	// Free
	bbf_cleanup(&bbf_ctx);
	free_path_list(&resolved_paths);

	return fault;
}

int create_add_response(usp_data_t *data, struct blob_buf *bb)
{
	return handle_add_del_req(data, bb, &usp_add_object);
}

int create_del_response(usp_data_t *data, struct blob_buf *bb)
{
	return handle_add_del_req(data, bb, &usp_del_object);
}
