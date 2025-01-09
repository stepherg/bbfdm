#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libubox/blobmsg.h>

#include <libbbfdm-api/dmapi.h>
#include <libbbfdm-ubus/bbfdm-ubus.h>
#include <libbbfdm-api/dmentry.h>

#include "../../libbbfdm-ubus/plugin.h"
#include "../../libbbfdm/device.h"

static int cli_exec_schema(struct dmctx *bbfdm_ctx, char *in_path)
{
	int err = 0;

	bbfdm_ctx->in_param = in_path;
	bbfdm_ctx->nextlevel = false;
	bbfdm_ctx->iscommand = true;
	bbfdm_ctx->isevent = true;
	bbfdm_ctx->isinfo = true;

	err = bbf_entry_method(bbfdm_ctx, BBF_SCHEMA);
	if (!err) {
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		blobmsg_for_each_attr(cur, bbfdm_ctx->bb.head, rem) {
			struct blob_attr *tb[3] = {0};
			const struct blobmsg_policy p[3] = {
					{ "path", BLOBMSG_TYPE_STRING },
					{ "data", BLOBMSG_TYPE_STRING },
					{ "type", BLOBMSG_TYPE_STRING }
			};

			blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

			char *name = (tb[0]) ? blobmsg_get_string(tb[0]) : "";
			char *data = (tb[1]) ? blobmsg_get_string(tb[1]) : "";
			char *type = (tb[2]) ? blobmsg_get_string(tb[2]) : "";

			printf("%s %s %s\n", name, type, strlen(data) ? data : "0"); // Added a data check to handle events with empty or missing data
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, bbfdm_ctx->in_param);
		err = -1;
	}

	return err;
}

int main(int argc, char **argv)
{
	DMOBJ *CLI_DM_ROOT_OBJ = NULL;
	void *cli_lib_handle = NULL;
	struct dmctx bbfdm_ctx = {0};
	bbfdm_config_t bbfdm_config = {0};
	char *plugin_path = NULL, *plugin_dir = NULL, *dm_path = NULL;
	unsigned int proto = BBFDM_BOTH;
	int err = 0, ch;

	memset(&bbfdm_ctx, 0, sizeof(struct dmctx));

	while ((ch = getopt(argc, argv, "hc:u:l:p:")) != -1) {
		switch (ch) {
		case 'c':
			bbfdm_ctx.dm_type = BBFDM_CWMP;
			dm_path = argv[optind - 1];
			break;
		case 'u':
			bbfdm_ctx.dm_type = BBFDM_USP;
			dm_path = argv[optind - 1];
			break;
		case 'l':
			plugin_path = optarg;
			break;
		case 'p':
			plugin_dir = optarg;
			break;
		default:
			break;
		}
	}

	if (plugin_path == NULL) {
		err = bbfdm_load_internal_plugin(NULL, tDynamicObj, &bbfdm_config, &CLI_DM_ROOT_OBJ);
	} else {
		err = bbfdm_load_dotso_plugin(NULL, &cli_lib_handle, plugin_path, &bbfdm_config, &CLI_DM_ROOT_OBJ);
	}

	if (err || !CLI_DM_ROOT_OBJ) {
		printf("ERROR: Failed to load plugin\n");
		return -1;
	}

	if (!dm_path) {
		printf("ERROR: Data Model path should be defined\n");
		return -1;
	}

	// Initialize global context
	bbf_global_init(CLI_DM_ROOT_OBJ, plugin_dir);

	// Initialize the bbfdm context
	bbf_ctx_init(&bbfdm_ctx, CLI_DM_ROOT_OBJ);

	err = cli_exec_schema(&bbfdm_ctx, dm_path);

	// Clean up the context and global resources
	bbf_ctx_clean(&bbfdm_ctx);
	bbf_global_clean(CLI_DM_ROOT_OBJ);

	// Free plugin handle
	bbfdm_free_dotso_plugin(NULL, &cli_lib_handle);

	return err;
}
