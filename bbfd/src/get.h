#ifndef GET_H
#define GET_H

#include "bbfd.h"
#include "common.h"

#include "libbbf_api/src/dmbbf.h"

enum {
	DM_GET_PATH,
	DM_GET_PATHS,
	DM_GET_MAXDEPTH,
	DM_GET_OPTIONAL,
	__DM_GET_MAX
};

enum {
	DM_GET_INSTANCES_PATH,
	DM_GET_INSTANCES_PATHS,
	DM_GET_INSTANCES_FIRST_LEVEL,
	DM_GET_INSTANCES_OPTIONAL,
	__DM_GET_INSTANCES_MAX
};

enum {
	DM_SUPPORTED_PATH,
	DM_SUPPORTED_PATHS,
	DM_SUPPORTED_FIRST_LEVEL,
	DM_SUPPORTED_COMMANDS,
	DM_SUPPORTED_EVENTS,
	DM_SUPPORTED_PARAMS,
	DM_SUPPORTED_OPTIONAL,
	__DM_SUPPORTED_MAX
};

void usp_get_value(struct dmctx *bbf_ctx, usp_data_t *data);
void usp_get_value_async(struct dmctx *bbf_ctx, usp_data_t *data, void *output);

void usp_get_names(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);

void usp_get_instances(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);

int bbf_dm_get_supported_dm(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);

#endif /* GET_H */
