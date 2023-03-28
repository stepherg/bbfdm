#ifndef GET_H
#define GET_H

#include "bbfd.h"
#include "common.h"

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

void usp_get_value(usp_data_t *data);
void usp_get_value_async(usp_data_t *data, void *output);

void usp_get_names(usp_data_t *data);

void usp_get_instances(usp_data_t *data);

int bbf_dm_get_supported_dm(usp_data_t *data);

#endif /* GET_H */
