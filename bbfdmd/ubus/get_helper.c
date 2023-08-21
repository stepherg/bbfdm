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

#include "libbbfdm-api/dmentry.h"

DMOBJ *DEAMON_DM_ROOT_OBJ = NULL;
DM_MAP_VENDOR *DEAMON_DM_VENDOR_EXTENSION[2] = {0};
DM_MAP_VENDOR_EXCLUDE *DEAMON_DM_VENDOR_EXTENSION_EXCLUDE = NULL;

// uloop.h does not have versions, below line is to use
// deprecated uloop_timeout_remaining for the time being
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static struct {
	int trans_id;
	struct uloop_timeout trans_timeout;
	int timeout_ms;
	char app[32];
} g_current_trans = {.trans_id=0, .timeout_ms=10000};

static jmp_buf gs_jump_location;
static bool gs_jump_called_by_bbf = false;

void handle_pending_signal(int sig)
{
	if (gs_jump_called_by_bbf) {
		siglongjmp(gs_jump_location, 1);
	}

	ERR("Exception [%d] not cause by bbf dm, exit with error", sig);
	exit(1);
}

int bbfdm_cmd_exec(struct dmctx *bbf_ctx, int cmd)
{
	int fault = 0;

	if (bbf_ctx->in_param == NULL)
		return USP_FAULT_INTERNAL_ERROR;

	if (sigsetjmp(gs_jump_location, 1) == 0) {
		gs_jump_called_by_bbf = true;
		fault = bbf_entry_method(bbf_ctx, cmd);
	} else {
		ERR("PID [%ld]::Exception on [%d => %s]", getpid(), cmd, bbf_ctx->in_param);
		fault = USP_FAULT_INTERNAL_ERROR;
	}

	gs_jump_called_by_bbf = false;

	if (fault)
		WARNING("Fault [%d => %d => %s]", fault, cmd, bbf_ctx->in_param);

	return fault;
}

void bb_add_string(struct blob_buf *bb, const char *name, const char *value)
{
	blobmsg_add_string(bb, name, value ? value : "");
}

void bbf_init(struct dmctx *dm_ctx)
{
	bbf_ctx_init(dm_ctx, DEAMON_DM_ROOT_OBJ, DEAMON_DM_VENDOR_EXTENSION, DEAMON_DM_VENDOR_EXTENSION_EXCLUDE);
}

void bbf_cleanup(struct dmctx *dm_ctx)
{
	bbf_ctx_clean(dm_ctx);
}

void bbf_sub_init(struct dmctx *dm_ctx)
{
	bbf_ctx_init_sub(dm_ctx, DEAMON_DM_ROOT_OBJ, DEAMON_DM_VENDOR_EXTENSION, DEAMON_DM_VENDOR_EXTENSION_EXCLUDE);
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

void add_pv_list(char *para, char *val, char *type, struct list_head *pv_list)
{
	struct pvNode *node = NULL;

	node = (struct pvNode *) malloc(sizeof(*node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	node->param = (para) ? strdup(para) : strdup("");
	node->val = (val) ? strdup(val) : strdup("");
	node->type = (type) ? strdup(type) : strdup("");

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, pv_list);
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

void add_path_list(char *param, struct list_head *plist)
{
	struct pathNode *node = NULL;
	size_t len;

	node = (struct pathNode *)calloc(1, sizeof(*node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	len = DM_STRLEN(param);
	strncpyt(node->path, param, len + 1);

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, plist);
}

void free_path_list(struct list_head *plist)
{
	struct pathNode *iter, *node;

	list_for_each_entry_safe(iter, node, plist, list) {
		list_del(&iter->list);
		free(iter);
	}
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

static void transaction_timeout_handler(struct uloop_timeout *t __attribute__((unused)))
{
	INFO("Transaction timeout called, aborting tid %d", g_current_trans.trans_id);
	transaction_abort(g_current_trans.trans_id, NULL);
}

static int get_random_id(void)
{
	int ret;

	srand(time(0));
	ret = rand();
	if (!ret)
		ret = 1;

	return ret;
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
	struct pvNode *pv1 = (struct pvNode *)arg1;
	struct pvNode *pv2 = (struct pvNode *)arg2;

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

// Returns transaction id if successful, otherwise 0
int transaction_start(char *app, uint32_t max_timeout)
{
	int ret = 0;
	uint32_t timeout;

	if (g_current_trans.trans_id) {
		WARNING("%s Transaction locked by %s", app, g_current_trans.app);
		return 0;
	}

	if (max_timeout > 0) {
		timeout = max_timeout;
	} else {
		timeout = g_current_trans.timeout_ms;
	}

	ret = get_random_id();
	strncpyt(g_current_trans.app, app, 32);

	g_current_trans.trans_id = ret;
	g_current_trans.trans_timeout.cb = transaction_timeout_handler;
	uloop_timeout_set(&g_current_trans.trans_timeout, timeout);
	INFO("Transaction created by [%s] id %d, timeout %zd", g_current_trans.app, g_current_trans.trans_id, timeout);

	return ret;
}

int transaction_status(struct blob_buf *bb)
{
	if (g_current_trans.trans_id) {
		int64_t rem = uloop_timeout_remaining(&g_current_trans.trans_timeout);
		blobmsg_add_string(bb, "app", g_current_trans.app);
		blobmsg_add_string(bb, "tstatus", "running");
		blobmsg_add_u64(bb, "remaining_time", rem / 1000);
	} else {
		blobmsg_add_string(bb, "tstatus", "Idle");
	}

	return 0;
}

bool is_transaction_running(void)
{
	return (g_current_trans.trans_id == 0 ? false : true);
}

bool is_transaction_valid(int trans_id)
{
	if (trans_id == 0)
		return false;

	return (trans_id == g_current_trans.trans_id);
}

int transaction_commit(int trans_id, struct blob_buf *bb, bool is_service_restart)
{
	int ret = -1;

	if (is_transaction_valid(trans_id)) {
		INFO("Commit on-going transaction by %s", g_current_trans.app);
		uloop_timeout_cancel(&g_current_trans.trans_timeout);
		g_current_trans.trans_id = 0;
		g_current_trans.app[0] = '\0';

		bbf_entry_restart_services(bb, is_service_restart);

		ret = 0;
	} else {
		WARNING("Transaction id mismatch(%d)", trans_id);
	}

	return ret;
}

int transaction_abort(int trans_id, struct blob_buf *bb)
{
	int ret = -1;

	if (is_transaction_valid(trans_id)) {
		INFO("Abort on-going transaction by %s", g_current_trans.app);
		uloop_timeout_cancel(&g_current_trans.trans_timeout);
		g_current_trans.trans_id = 0;
		g_current_trans.app[0] = '\0';

		bbf_entry_revert_changes(bb);

		ret = 0;
	} else {
		WARNING("Transaction id mismatch(%d)", trans_id);
	}

	return ret;
}

int configure_transaction_timeout(int timeout)
{
	if (timeout <= 0)
		return -1;

	g_current_trans.timeout_ms = timeout * 1000;

	return 0;
}

// Returns a pointer to the sorted array of PVs, memory need to be freed by caller
struct pvNode *sort_pv_path(struct list_head *pv_list, size_t pv_count)
{
	if (!pv_list)
		return NULL;

	if (list_empty(pv_list) || pv_count == 0)
		return NULL;

	struct pvNode *arr = malloc(sizeof(struct pvNode) * pv_count);
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
