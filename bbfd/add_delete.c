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

typedef int (*ADD_DEL_CB_T)(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);

static int usp_add_object(struct dmctx *bbf_ctx, usp_data_t *data __attribute__((unused)), struct blob_buf *bb)
{
	int fault = 0;

	INFO("Req to add object |%s|", bbf_ctx->in_param);

	fault = usp_dm_exec(bbf_ctx, BBF_ADD_OBJECT);

	void *table = blobmsg_open_table(bb, NULL);
	bb_add_string(bb, "path", bbf_ctx->in_param);
	if (fault) {
		blobmsg_add_u32(bb, "fault", fault);
		blobmsg_add_u8(bb, "status", 0);
	} else {
		if (bbf_ctx->addobj_instance) {
			blobmsg_add_u8(bb, "status", 1);
			bb_add_string(bb, "instance", bbf_ctx->addobj_instance);
		} else {
			blobmsg_add_u8(bb, "status", 0);
		}
	}
	blobmsg_close_table(bb, table);

	return fault;
}

static int usp_del_object(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	struct pathNode *pn;
	int fault = 0;

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(bbf_ctx);
		bbf_ctx->in_param = pn->path;

		INFO("Req to delete object |%s|", bbf_ctx->in_param);
		fault = usp_dm_exec(bbf_ctx, BBF_DEL_OBJECT);

		void *table = blobmsg_open_table(bb, NULL);
		bb_add_string(bb, "path", bbf_ctx->in_param);
		if (fault) {
			blobmsg_add_u8(bb, "status", 0);
			blobmsg_add_u32(bb, "fault", fault);
		} else {
			blobmsg_add_u8(bb, "status", 1);
		}
		blobmsg_close_table(bb, table);

		bbf_sub_cleanup(bbf_ctx);
	}

	return fault;
}

static int handle_add_del_req(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb, ADD_DEL_CB_T req_cb)
{
	void *array = NULL;
	int fault = 0;

	array = blobmsg_open_array(bb, "objects");
	fault = req_cb(bbf_ctx, data, bb);
	blobmsg_close_array(bb, array);

	return fault;
}

int create_add_response(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	return handle_add_del_req(bbf_ctx, data, bb, &usp_add_object);
}

int create_del_response(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	return handle_add_del_req(bbf_ctx, data, bb, &usp_del_object);
}
