/*
 * set.c: Set handler for bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "set.h"
#include "get_helper.h"

#include <libubus.h>

int bbfdm_set_value(bbfdm_data_t *data)
{
	struct pvNode *pv = NULL;
	void *array = NULL;
	int fault = 0;

	array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pv, data->plist, list) {
		data->bbf_ctx.in_param = pv->param;
		data->bbf_ctx.in_value = pv->val;

		fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_SET_VALUE);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			void *table = blobmsg_open_table(&data->bb, NULL);
			bb_add_string(&data->bb, "path", data->bbf_ctx.in_param);
			bb_add_string(&data->bb, "data", "1");
			blobmsg_close_table(&data->bb, table);
		}
	}

	blobmsg_close_array(&data->bb, array);

	return fault;
}

static int set_resolved_paths(unsigned int dm_type, char *path, char *value, struct list_head *pv_list)
{
	int fault = 0;
	struct dmctx bbf_ctx = {
			.dm_type = dm_type
	};

	if (!path || !value || !pv_list)
		return -1;

	LIST_HEAD(resolved_paths);
	bbf_sub_init(&bbf_ctx);

	fault = get_resolved_paths(&bbf_ctx, path, &resolved_paths);
	if (!fault) {
		struct pathNode *p;

		list_for_each_entry(p, &resolved_paths, list) {
			add_pv_list(p->path, value, NULL, pv_list);
		}
	}

	bbf_sub_cleanup(&bbf_ctx);
	free_path_list(&resolved_paths);

	return fault;
}

int fill_pvlist_set(bbfdm_data_t *data, char *param_name, char *param_value, struct blob_attr *blob_table, struct list_head *pv_list)
{
	struct blob_attr *attr;
	struct blobmsg_hdr *hdr;
	char path[MAX_DM_PATH], value[MAX_DM_VALUE];
	int fault = 0;

	size_t plen = DM_STRLEN(param_name);
	if (plen == 0)
		return USP_FAULT_INVALID_PATH;

	if (!param_value)
		goto blob__table;

	if (param_name[plen - 1] == '.')
		return USP_FAULT_INVALID_PATH;

	fault = set_resolved_paths(data->bbf_ctx.dm_type, param_name, param_value, pv_list);
	if (fault)
		return fault;

blob__table:

	if (!blob_table)
		return 0;

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

		snprintf(path, MAX_DM_PATH, "%s%s", param_name, (char *)hdr->name);
		fault = set_resolved_paths(data->bbf_ctx.dm_type, path, value, pv_list);
		if (fault)
			return fault;
	}

	return 0;
}
