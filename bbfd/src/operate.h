#ifndef OPERATE_H
#define OPERATE_H

#include "usp.h"
#include "common.h"

enum {
	DM_OPERATE_PATH,
	DM_OPERATE_ACTION,
	DM_OPERATE_INPUT,
	DM_OPERATE_PROTO,
	DM_OPERATE_INSTANCE,
	__DM_OPERATE_MAX,
};

void list_operate_schema(struct blob_buf *bb);
void usp_operate_cmd_async(usp_data_t *data, void *output);
void usp_operate_cmd_sync(usp_data_t *data);
#endif /* OPERATE_H */
