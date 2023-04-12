#include <stdio.h>

#include <libbbf_api/dmapi.h>
#include <libbbf_api/dmentry.h>
#include <libbbf_dm/device.h>
#include <libbbf_dm/vendor.h>

static DMOBJ *TR181_ROOT_TREE = tEntry181Obj;
static DM_MAP_VENDOR *TR181_VENDOR_EXTENSION[2] = {
		tVendorExtension,
		tVendorExtensionOverwrite
};
static DM_MAP_VENDOR_EXCLUDE *TR181_VENDOR_EXTENSION_EXCLUDE = tVendorExtensionExclude;

typedef struct {
	int id;
	char *str;
} cmd_t;


cmd_t CMD[] = {
	{ BBF_GET_VALUE, "get"},
	{ BBF_SCHEMA, "schema"},
	{ BBF_INSTANCES, "instances"},
	//{ BBF_SET_VALUE, "set"},
	//{ BBF_ADD_OBJECT, "add"},
	//{ BBF_DEL_OBJECT, "del"},
	//{ BBF_USP_OPERATE, "operate"},
};

static int get_cmd_from_str(char *str)
{
	int i, cmd = BBF_GET_VALUE;

	for (i = 0; i < ARRAY_SIZE(CMD); i++) {
		if (DM_STRCMP(CMD[i].str, str) == 0) {
			cmd = CMD[i].id;
			break;
		}
	}

	return cmd;
}

static void print_help(char *prog)
{
	printf("Valid commands:\n");
	printf("%s -c => Run with cwmp proto\n", prog);
	printf("%s -u => Run with usp proto\n", prog);
	exit(0);
}

int bbf_dm_exec(int argc, char *argv[])
{
	struct dmctx bbf_ctx;
	int fault = 0;
	int cmd = 0;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	cmd = get_cmd_from_str(argv[2]);

	bbf_ctx.instance_mode = INSTANCE_MODE_NUMBER;

	if (DM_STRCMP(argv[1], "-c") == 0)
		bbf_ctx.dm_type = BBFDM_CWMP;
	else
		bbf_ctx.dm_type = BBFDM_USP;

	if (argc > 3 && DM_STRLEN(argv[3]))
		bbf_ctx.in_param = argv[3];

	if (cmd == 1) {
		bbf_ctx.nextlevel = false;
		bbf_ctx.iscommand = true;
		bbf_ctx.isevent = true;
		bbf_ctx.isinfo = true;
	}

	if (cmd == 2) {
		bbf_ctx.nextlevel = false;
	}

	if (cmd == 3 && argc > 4 && DM_STRLEN(argv[4]))
		bbf_ctx.in_value = argv[4];

	bbf_ctx_init(&bbf_ctx, TR181_ROOT_TREE, TR181_VENDOR_EXTENSION, TR181_VENDOR_EXTENSION_EXCLUDE);

	fault = bbf_entry_method(&bbf_ctx, cmd);
	if (!fault) {
		struct dm_parameter *n;

		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			printf(" %s::%s::%s\n", n->name, n->data, n->type);
		}
	} else {
		printf("Fault %d\n", fault);
	}

	bbf_ctx_clean(&bbf_ctx);
	return fault;
}

int main(int argc, char *argv[])
{
	if (argc < 3)
		print_help(argv[0]);

	bbf_dm_exec(argc, argv);

	bbf_global_clean(TR181_ROOT_TREE);
}
