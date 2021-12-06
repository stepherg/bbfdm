#include <stdio.h>

#include <libubus.h>
#include <libbbfdm/dmentry.h>
#include <libbbfdm/dmbbfcommon.h>

#ifndef CMD_GET_INFO
#define CMD_GET_INFO (CMD_EXTERNAL_COMMAND + 1)
#endif
static int g_proto = BBFDM_USP;

typedef struct {
	int id;
	char *str;
} cmd_t;


cmd_t CMD[] = {
	{ CMD_GET_VALUE, "get"},
	{ CMD_GET_NAME, "get_name"},
	//{ CMD_SET_VALUE, "set"},
	//{ CMD_ADD_OBJECT, "add"},
	//{ CMD_DEL_OBJECT, "del"},
	//{ CMD_USP_OPERATE, "operate"},
	{ CMD_USP_LIST_OPERATE, "list_operate"},
	{ CMD_USP_LIST_EVENT, "list_event"},
	{ CMD_GET_SCHEMA, "get_schema"},
	{ CMD_GET_INSTANCES, "instances"},
	{ CMD_GET_INFO, "get_info"}
};

int get_cmd_from_str(char *str)
{
	int i, cmd = CMD_GET_VALUE;

	for (i = 0; i < ARRAY_SIZE(CMD); i++) {
		if (strcmp(CMD[i].str, str) == 0) {
			cmd = CMD[i].id;
			break;
		}
	}

	return cmd;
}

void print_help(char *prog)
{
	printf("Valid commands:\n");
	printf("%s -c => Run with cwmp proto\n", prog);
	printf("%s -u => Run with usp proto\n", prog);
	exit(0);
}

int usp_dm_exec(int cmd, char *path, char *arg1, char *arg2)
{
	int fault = 0;
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	printf("cmd[%d], path[%s]\n", cmd, path);
	set_bbfdatamodel_type(g_proto);

	dm_ctx_init(&bbf_ctx, 0);

	if (arg2 && *arg2) {
		bbf_ctx.dm_version = arg2;
		printf("config version %s\n", bbf_ctx.dm_version);
	}

	if (cmd == CMD_GET_INFO){
		fault = dm_get_supported_dm(&bbf_ctx, path, false, atoi(arg1));
	} else {
		fault = dm_entry_param_method(&bbf_ctx, cmd, path, arg1, arg2);
	}

	if (!fault) {
		struct dm_parameter *n;

		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			printf(" %s::%s::%s\n", n->name, n->data, n->type);
		}
	} else {
		printf("Fault %d\n", fault);
	}

	dm_ctx_clean(&bbf_ctx);
	return fault;
}

int main(int argc, char *argv[])
{
	static struct ubus_context *ubus_ctx = NULL;
	char *param = "", *value = "", *version = "";
	int cmd;

	if (argc < 3) {
		print_help(argv[0]);
	}

	ubus_ctx = ubus_connect(NULL);
	if (ubus_ctx == NULL) {
		fprintf(stderr, "Failed to connect with ubus\n");
		return -1;
	}

	dm_config_ubus(ubus_ctx);

	if (strcmp(argv[1], "-c") == 0)
		g_proto = BBFDM_CWMP;

	cmd = get_cmd_from_str(argv[2]);

	if (argc > 3 && strlen(argv[3]))
		param = argv[3];

	if (argc > 4 && strlen(argv[4]))
		value = argv[4];

	if (argc > 5 && strlen(argv[5]))
		version = argv[5];
	
	usp_dm_exec(cmd, param, value, version);
	bbf_dm_cleanup();
	ubus_free(ubus_ctx);
}
