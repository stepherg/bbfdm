#ifndef GET_HELPER_H
#define GET_HELPER_H

#include "common.h"

#include <libubus.h>

struct pvNode {
	char *param;
	char *val;
	char *type;
	struct list_head list;
};

struct pathNode {
	struct list_head list;
	char path[MAX_DM_PATH];
};

int bbfdm_cmd_exec(struct dmctx *bbf_ctx, int cmd);

void bbf_init(struct dmctx *dm_ctx);
void bbf_cleanup(struct dmctx *dm_ctx);
void bbf_sub_init(struct dmctx *dm_ctx);
void bbf_sub_cleanup(struct dmctx *dm_ctx);

bool present_in_path_list(struct list_head *plist, char *entry);

void add_pv_list(const char *para, const char *val, const char *type, struct list_head *pv_list);
void free_pv_list(struct list_head *pv_list);

void add_path_list(const char *param, struct list_head *plist);
void free_path_list(struct list_head *plist);

void fill_err_code_table(bbfdm_data_t *data, int fault);
void fill_err_code_array(bbfdm_data_t *data, int fault);

void bb_add_string(struct blob_buf *bb, const char *name, const char *value);

struct pvNode *sort_pv_path(struct list_head *pv_list, size_t pv_count);

#endif /* GET_HELPER_H */
