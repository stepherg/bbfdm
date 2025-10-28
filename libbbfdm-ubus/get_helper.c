/*
 * get_helper.c: Get Fast handler for bbfdmd
 *
 * Copyright (C) 2019-2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#define _XOPEN_SOURCE
#define _DEFAULT_SOURCE

#include <time.h>
#include <setjmp.h>

#include "get_helper.h"
#include "common.h"

DMOBJ *DEAMON_DM_ROOT_OBJ = NULL;
DM_MAP_OBJ *INTERNAL_ROOT_TREE = NULL;

int bbfdm_cmd_exec(struct dmctx *bbf_ctx, int cmd)
{
	int fault = 0;

	if (bbf_ctx->in_param == NULL)
		return USP_FAULT_INTERNAL_ERROR;

	fault = bbf_entry_method(bbf_ctx, cmd);
	if (fault)
		BBF_WARNING("Fault [%d => %d => %s]", fault, cmd, bbf_ctx->in_param);

	return fault;
}

void bb_add_string(struct blob_buf *bb, const char *name, const char *value)
{
	blobmsg_add_string(bb, name, value ? value : "");
}

void bbf_init(struct dmctx *dm_ctx)
{
	bbf_ctx_init(dm_ctx, DEAMON_DM_ROOT_OBJ);
}

void bbf_cleanup(struct dmctx *dm_ctx)
{
	bbf_ctx_clean(dm_ctx);
}

void bbf_sub_init(struct dmctx *dm_ctx)
{
	bbf_ctx_init_sub(dm_ctx, DEAMON_DM_ROOT_OBJ);
}

void bbf_sub_cleanup(struct dmctx *dm_ctx)
{
	bbf_ctx_clean_sub(dm_ctx);
}

bool match_with_path_list(struct list_head *plist, char *entry)
{
	struct pathNode *node;

	list_for_each_entry(node, plist, list) {
		if (strncmp(node->path, entry, strlen(node->path)) == 0)
			return true;
	}

	return false;
}

bool present_in_path_list(struct list_head *plist, char *entry)
{
	struct pathNode *node;

	list_for_each_entry(node, plist, list) {
		if (!strcmp(node->path, entry))
			return true;
	}

	return false;
}

bool present_in_pv_list(struct list_head *pv_list, char *entry)
{
	struct pvNode *node = NULL;

	list_for_each_entry(node, pv_list, list) {
		if (!strcmp(node->param, entry))
			return true;
	}

	return false;
}

void add_pv_list(const char *para, const char *val, const char *type, struct list_head *pv_list)
{
	struct pvNode *node = NULL;

	node = (struct pvNode *)calloc(1, sizeof(*node));

	if (!node) {
		BBF_ERR("Out of memory!");
		return;
	}

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, pv_list);

	node->param = (para) ? strdup(para) : strdup("");
	node->val = (val) ? strdup(val) : strdup("");
	node->type = (type) ? strdup(type) : strdup("");
}

void free_pv_list(struct list_head *pv_list)
{
	struct pvNode *iter, *node;

	list_for_each_entry_safe(iter, node, pv_list, list) {
		free(iter->param);
		free(iter->val);
		free(iter->type);

		list_del(&iter->list);
		free(iter);
	}
}

void add_path_list(const char *param, struct list_head *plist)
{
	struct pathNode *node = NULL;
	size_t len;

	node = (struct pathNode *)calloc(1, sizeof(*node));

	if (!node) {
		BBF_ERR("Out of memory!");
		return;
	}

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, plist);

	len = DM_STRLEN(param);
	strncpyt(node->path, param, len + 1);
}

void free_path_list(struct list_head *plist)
{
	struct pathNode *iter, *node;

	list_for_each_entry_safe(iter, node, plist, list) {
		list_del(&iter->list);
		free(iter);
	}
	INIT_LIST_HEAD(plist);
}

void fill_err_code_table(bbfdm_data_t *data, int fault)
{
	void *table = blobmsg_open_table(&data->bb, NULL);
	bb_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_u32(&data->bb, "fault", bbf_fault_map(&data->bbf_ctx, fault));
	bb_add_string(&data->bb, "fault_msg", data->bbf_ctx.fault_msg);
	blobmsg_close_table(&data->bb, table);
}

void fill_err_code_array(bbfdm_data_t *data, int fault)
{
	void *array = blobmsg_open_array(&data->bb, "results");
	void *table = blobmsg_open_table(&data->bb, NULL);
	bb_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_u32(&data->bb, "fault", bbf_fault_map(&data->bbf_ctx, fault));
	bb_add_string(&data->bb, "fault_msg", data->bbf_ctx.fault_msg);
	blobmsg_close_table(&data->bb, table);
	blobmsg_close_array(&data->bb, array);
}
