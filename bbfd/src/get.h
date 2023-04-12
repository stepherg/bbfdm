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
	DM_INSTANCES_PATH,
	DM_INSTANCES_PATHS,
	DM_INSTANCES_FIRST_LEVEL,
	DM_INSTANCES_OPTIONAL,
	__DM_INSTANCES_MAX
};

enum {
	DM_SCHEMA_PATH,
	DM_SCHEMA_PATHS,
	DM_SCHEMA_FIRST_LEVEL,
	DM_SCHEMA_COMMANDS,
	DM_SCHEMA_EVENTS,
	DM_SCHEMA_PARAMS,
	DM_SCHEMA_OPTIONAL,
	__DM_SCHEMA_MAX
};

void usp_get_value(usp_data_t *data);
void usp_get_value_async(usp_data_t *data, void *output);

void usp_get_names(usp_data_t *data);

void usp_get_instances(usp_data_t *data);

int bbf_dm_get_supported_dm(usp_data_t *data);

#endif /* GET_H */
