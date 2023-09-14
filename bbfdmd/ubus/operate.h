#ifndef OPERATE_H
#define OPERATE_H

#include "bbfdmd.h"
#include "common.h"

enum {
	DM_OPERATE_COMMAND,
	DM_OPERATE_COMMAND_KEY,
	DM_OPERATE_INPUT,
	DM_OPERATE_OPTIONAL,
	__DM_OPERATE_MAX,
};

void bbfdm_operate_cmd_async(bbfdm_data_t *data, void *output);
void bbfdm_operate_cmd_sync(bbfdm_data_t *data);

#endif /* OPERATE_H */
