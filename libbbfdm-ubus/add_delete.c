/*
 * add_delete.c: Add/Delete handler for bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "common.h"
#include "add_delete.h"
#include "get_helper.h"

typedef int (*ADD_DEL_CB_T)(bbfdm_data_t *data);

static int bbfdm_add_object(bbfdm_data_t *data)
{
	int fault = 0;

	BBF_INFO("Req to add object |%s|", data->bbf_ctx.in_param);

	void *array = blobmsg_open_array(&data->bb, "results");

	fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_ADD_OBJECT);
	if (fault) {
		fill_err_code_table(data, fault);
	} else {
		void *table = blobmsg_open_table(&data->bb, NULL);
		bb_add_string(&data->bb, "path", data->bbf_ctx.in_param);
		bb_add_string(&data->bb, "data", data->bbf_ctx.addobj_instance);
		blobmsg_close_table(&data->bb, table);
	}

	blobmsg_close_array(&data->bb, array);

	return fault;
}

static int bbfdm_del_object(bbfdm_data_t *data)
{
	struct pathNode *pn;
	int fault = 0;

	void *array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		BBF_INFO("Req to delete object |%s|", data->bbf_ctx.in_param);

		fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_DEL_OBJECT);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			void *table = blobmsg_open_table(&data->bb, NULL);
			bb_add_string(&data->bb, "path", data->bbf_ctx.in_param);
			bb_add_string(&data->bb, "data", "1");
			blobmsg_close_table(&data->bb, table);
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bb, array);

	return fault;
}

static int handle_add_del_req(bbfdm_data_t *data, ADD_DEL_CB_T req_cb)
{
	int fault = 0;

	fault = req_cb(data);

	return fault;
}

int create_add_response(bbfdm_data_t *data)
{
	return handle_add_del_req(data, &bbfdm_add_object);
}

int create_del_response(bbfdm_data_t *data)
{
	return handle_add_del_req(data, &bbfdm_del_object);
}
