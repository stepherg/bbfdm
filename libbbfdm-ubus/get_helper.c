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
#include "pretty_print.h"

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

bool present_in_path_list(struct list_head *plist, char *entry)
{
	struct pathNode *pos;

	list_for_each_entry(pos, plist, list) {
		if (!strcmp(pos->path, entry))
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
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param ? data->bbf_ctx.in_param : "");
	blobmsg_add_u32(&data->bb, "fault", bbf_fault_map(&data->bbf_ctx, fault));
	bb_add_string(&data->bb, "fault_msg", data->bbf_ctx.fault_msg);
	blobmsg_close_table(&data->bb, table);
}

void fill_err_code_array(bbfdm_data_t *data, int fault)
{
	void *array = blobmsg_open_array(&data->bb, "results");
	void *table = blobmsg_open_table(&data->bb, NULL);
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_u32(&data->bb, "fault", bbf_fault_map(&data->bbf_ctx, fault));
	bb_add_string(&data->bb, "fault_msg", data->bbf_ctx.fault_msg);
	blobmsg_close_table(&data->bb, table);
	blobmsg_close_array(&data->bb, array);
}

static int CountConsecutiveDigits(char *p)
{
    char c;
    int num_digits;

    num_digits = 0;
    c = *p++;
    while ((c >= '0') && (c <= 9))
    {
        num_digits++;
        c = *p++;
    }

    return num_digits;
}

static int compare_path(const void *arg1, const void *arg2)
{
	const struct pvNode *pv1 = (const struct pvNode *)arg1;
	const struct pvNode *pv2 = (const struct pvNode *)arg2;

	char *s1 = pv1->param;
	char *s2 = pv2->param;

	char c1, c2;
	int num_digits_s1;
	int num_digits_s2;
	int delta;

	// Skip all characters which are the same
	while (true) {
		c1 = *s1;
		c2 = *s2;

		// Exit if reached the end of either string
		if ((c1 == '\0') || (c2 == '\0')) {
			// NOTE: The following comparision puts s1 before s2, if s1 terminates before s2 (and vice versa)
			return (int)c1 - (int)c2;
		}

		// Exit if the characters do not match
		if (c1 != c2) {
			break;
		}

		// As characters match, move to next characters
		s1++;
		s2++;
	}

	// If the code gets here, then we have reached a character which is different
	// Determine the number of digits in the rest of the string (this may be 0 if the first character is not a digit)
	num_digits_s1 = CountConsecutiveDigits(s1);
	num_digits_s2 = CountConsecutiveDigits(s2);

	// Determine if the number of digits in s1 is greater than in s2 (if so, s1 comes after s2)
	delta = num_digits_s1 - num_digits_s2;
	if (delta != 0) {
		return delta;
	}

	// If the code gets here, then the strings contain either no digits, or the same number of digits,
	// so just compare the characters (this also works if the characters are digits)
	return (int)c1 - (int)c2;
}

// Returns a pointer to the sorted array of PVs, memory need to be freed by caller
struct pvNode *sort_pv_path(struct list_head *pv_list, size_t pv_count)
{
	if (!pv_list)
		return NULL;

	if (list_empty(pv_list) || pv_count == 0)
		return NULL;

	struct pvNode *arr = (struct pvNode *)calloc(pv_count, sizeof(struct pvNode));
	if (arr == NULL)
		return NULL;

	struct pvNode *pv = NULL;
	size_t i = 0;

	list_for_each_entry(pv, pv_list, list) {
		if (i == pv_count)
			break;

		memcpy(&arr[i], pv, sizeof(struct pvNode));
		i++;
	}

	qsort(arr, pv_count, sizeof(struct pvNode), compare_path);

	return arr;
}
