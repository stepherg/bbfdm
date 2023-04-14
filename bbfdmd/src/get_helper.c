/*
 * get_helper.c: Get Fast handler for uspd
 *
 * Copyright (C) 2019 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Shubham Sharma <shubham.sharma@iopsys.eu>
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

#define _XOPEN_SOURCE
#define _DEFAULT_SOURCE

#include <time.h>
#include <setjmp.h>

#include "get_helper.h"
#include "common.h"
#include "pretty_print.h"

#include "libbbf_api/dmentry.h"
#include "libbbf_dm/dmtree/tr181/device.h"
#include "libbbf_dm/dmtree/vendor/vendor.h"

DMOBJ *DM_ROOT_OBJ = tEntry181Obj;
DM_MAP_VENDOR *DM_VENDOR_EXTENSION[2] = {
		tVendorExtension,
		tVendorExtensionOverwrite
};
DM_MAP_VENDOR_EXCLUDE *DM_VENDOR_EXTENSION_EXCLUDE = tVendorExtensionExclude;

// uloop.h does not have versions, below line is to use
// deprecated uloop_timeout_remaining for the time being
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static struct {
	int trans_id;
	struct uloop_timeout trans_timeout;
	int timeout_ms;
} g_current_trans = {.trans_id=0, .timeout_ms=10000};

static jmp_buf gs_jump_location;
static bool gs_jump_called_by_bbf = false;

void print_last_dm_object(void)
{
	char buff[MAX_DM_PATH];

	bbf_debug_browse_path(buff, MAX_DM_PATH);
	ERR("# PID[%ld] Last DM path [%s] #", getpid(), buff);
}

void handle_pending_signal(int sig)
{
	if (gs_jump_called_by_bbf) {
		siglongjmp(gs_jump_location, 1);
	}

	ERR("Exception [%d] not cause by bbf dm, exit with error", sig);
	exit(1);
}

void bb_add_string(struct blob_buf *bb, const char *name, const char *value)
{
	blobmsg_add_string(bb, name, value ? value : "");
}

void bbf_init(struct dmctx *dm_ctx)
{
	bbf_ctx_init(dm_ctx, DM_ROOT_OBJ, DM_VENDOR_EXTENSION, DM_VENDOR_EXTENSION_EXCLUDE);
}

void bbf_cleanup(struct dmctx *dm_ctx)
{
	bbf_ctx_clean(dm_ctx);
}

void bbf_sub_init(struct dmctx *dm_ctx)
{
	bbf_ctx_init_sub(dm_ctx, DM_ROOT_OBJ, DM_VENDOR_EXTENSION, DM_VENDOR_EXTENSION_EXCLUDE);
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

int usp_dm_exec(struct dmctx *bbf_ctx, int cmd)
{
	int fault = 0;

	if (bbf_ctx->in_param == NULL)
		return USP_FAULT_INTERNAL_ERROR;

	if (sigsetjmp(gs_jump_location, 1) == 0) {
		gs_jump_called_by_bbf = true;
		fault = bbf_entry_method(bbf_ctx, cmd);
	} else {
		ERR("PID [%ld]::Exception on [%d => %s]", getpid(), cmd, bbf_ctx->in_param);
		print_last_dm_object();
		fault = USP_FAULT_INTERNAL_ERROR;
	}

	gs_jump_called_by_bbf = false;

	if (fault)
		WARNING("Fault [%d => %d => %s]", fault, cmd, bbf_ctx->in_param);

	return fault;
}

void fill_err_code_table(usp_data_t *data, int fault)
{
	void *table = blobmsg_open_table(&data->bb, NULL);
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_u32(&data->bb, "fault", bbf_fault_map(data->bbf_ctx.dm_type, fault));
	bb_add_string(&data->bb, "fault_msg", "");
	blobmsg_close_table(&data->bb, table);
}

void fill_err_code_array(usp_data_t *data, int fault)
{
	void *array = blobmsg_open_array(&data->bb, "results");
	void *table = blobmsg_open_table(&data->bb, NULL);
	blobmsg_add_string(&data->bb, "path", data->bbf_ctx.in_param);
	blobmsg_add_u32(&data->bb, "fault", bbf_fault_map(data->bbf_ctx.dm_type, fault));
	bb_add_string(&data->bb, "fault_msg", "");
	blobmsg_close_table(&data->bb, table);
	blobmsg_close_array(&data->bb, array);
}

static void transaction_timeout_handler(struct uloop_timeout *t __attribute__((unused)))
{
	INFO("Transaction timeout called");
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

// Returns transaction id if successful, otherwise 0
int transaction_start(uint32_t max_timeout)
{
	int ret = 0;
	uint32_t timeout;

	if (g_current_trans.trans_id) {
		WARNING("Transaction already in-process");
		return 0;
	}

	if (max_timeout > 0) {
		timeout = max_timeout * 1000;
	} else {
		timeout = g_current_trans.timeout_ms;
	}
	ret = get_random_id();
	g_current_trans.trans_id = ret;
	g_current_trans.trans_timeout.cb = transaction_timeout_handler;
	uloop_timeout_set(&g_current_trans.trans_timeout, timeout);
	INFO("Transaction started with id %d, timeout %zd", g_current_trans.trans_id, timeout);

	return ret;
}

int transaction_status(struct blob_buf *bb, int trans_id)
{
	if (g_current_trans.trans_id == trans_id) {
		int rem = uloop_timeout_remaining(&g_current_trans.trans_timeout);
		blobmsg_add_string(bb, "status", "on-going");
		blobmsg_add_u32(bb, "remaining_time", rem / 1000);
	} else {
		blobmsg_add_string(bb, "status", "not-exists");
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
		INFO("Commit on-going transaction");
		uloop_timeout_cancel(&g_current_trans.trans_timeout);
		g_current_trans.trans_id = 0;

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
		INFO("Abort on-going transaction");
		uloop_timeout_cancel(&g_current_trans.trans_timeout);
		g_current_trans.trans_id = 0;

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
