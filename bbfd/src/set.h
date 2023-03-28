#ifndef SET_H
#define SET_H

#include "bbfd.h"
#include "common.h"

#include "libbbf_api/dmbbf.h"

enum {
	DM_SET_PATH,
	DM_SET_VALUE,
	DM_SET_OBJ_PATH,
	DM_SET_OPTIONAL,
	__DM_SET_MAX,
};

int fill_pvlist_set(struct dmctx *bbf_ctx, struct blob_attr *blob_table, struct list_head *pv_list);
int usp_set_value(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);

#endif /* SET_H */

