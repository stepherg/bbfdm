/*
 * set.c: Set handler for uspd
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

#include "set.h"
#include "get_helper.h"

#include <libubus.h>

int usp_set_value(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb)
{
	struct pvNode *pv = NULL;
	void *array = NULL;
	int fault = USP_ERR_OK;

	array = blobmsg_open_array(bb, "parameters");

	list_for_each_entry(pv, data->pv_list, list) {
		bbf_ctx->in_param = pv->param;
		bbf_ctx->in_value = pv->val;

		fault = usp_dm_exec(bbf_ctx, BBF_SET_VALUE);

		void *table = blobmsg_open_table(bb, NULL);
		bb_add_string(bb, "path", bbf_ctx->in_param);
		blobmsg_add_u8(bb, "status", fault ? false : true);
		if (fault) blobmsg_add_u32(bb, "fault", fault);
		blobmsg_close_table(bb, table);
	}

	blobmsg_close_array(bb, array);

	return fault;
}

int fill_pvlist_set(struct dmctx *bbf_ctx, struct blob_attr *blob_table, struct list_head *pv_list)
{
	struct blob_attr *attr;
	struct blobmsg_hdr *hdr;
	char path[MAX_DM_PATH], value[MAX_DM_VALUE];

	size_t plen = DM_STRLEN(bbf_ctx->in_param);
	if (plen == 0)
		return USP_FAULT_INVALID_PATH;

	if (!bbf_ctx->in_value)
		goto blob__table;

	if (bbf_ctx->in_param[plen - 1] == '.')
		return USP_FAULT_INVALID_PATH;

	add_pv_list(bbf_ctx->in_param, bbf_ctx->in_value, NULL, pv_list);

	return USP_ERR_OK;

blob__table:

	if (!blob_table)
		return USP_ERR_OK;

	size_t tlen = (size_t)blobmsg_data_len(blob_table);

	__blob_for_each_attr(attr, blobmsg_data(blob_table), tlen) {
		hdr = blob_data(attr);

		switch (blob_id(attr)) {
		case BLOBMSG_TYPE_STRING:
			snprintf(value, MAX_DM_VALUE, "%s", blobmsg_get_string(attr));
			break;
		case BLOBMSG_TYPE_INT8:
			snprintf(value, MAX_DM_VALUE, "%d", blobmsg_get_u8(attr));
			break;
		case BLOBMSG_TYPE_INT16:
			snprintf(value, MAX_DM_VALUE, "%d", blobmsg_get_u16(attr));
			break;
		case BLOBMSG_TYPE_INT32:
			snprintf(value, MAX_DM_VALUE, "%u", blobmsg_get_u32(attr));
			break;
		case BLOBMSG_TYPE_INT64:
			snprintf(value, MAX_DM_VALUE, "%"PRIu64"", blobmsg_get_u64(attr));
			break;
		default:
			INFO("Unhandled set request type|%x|", blob_id(attr));
			return USP_FAULT_INVALID_ARGUMENT;
		}

		snprintf(path, MAX_DM_PATH, "%s%s", bbf_ctx->in_param, (char *)hdr->name);
		add_pv_list(path, value, NULL, pv_list);
	}

	return USP_ERR_OK;
}
