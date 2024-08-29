#ifndef OPERATE_H
#define OPERATE_H

enum {
	DM_OPERATE_COMMAND,
	DM_OPERATE_COMMAND_KEY,
	DM_OPERATE_INPUT,
	DM_OPERATE_OPTIONAL,
	__DM_OPERATE_MAX,
};

void bbfdm_operate_cmd(bbfdm_data_t *data, void *output);

#endif /* OPERATE_H */
