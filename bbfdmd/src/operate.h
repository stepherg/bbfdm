#ifndef OPERATE_H
#define OPERATE_H

#include "bbfdmd.h"
#include "common.h"

#include "libbbf_api/dmbbf.h"

enum {
	DM_OPERATE_COMMAND,
	DM_OPERATE_COMMAND_KEY,
	DM_OPERATE_INPUT,
	DM_OPERATE_OPTIONAL,
	__DM_OPERATE_MAX,
};

void usp_operate_cmd_async(usp_data_t *data, void *output);
void usp_operate_cmd_sync(usp_data_t *data);

#endif /* OPERATE_H */
