/*
 * cli.c: Cli command for bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <stdlib.h>
#include <stdio.h>

#include "common.h"
#include "plugin.h"

extern struct list_head loaded_json_files;
extern struct list_head json_list;
extern struct list_head json_memhead;

#define UNUSED  __attribute__((unused))

static DMOBJ *CLI_DM_ROOT_OBJ = NULL;

static void *cli_lib_handle = NULL;

typedef struct {
	struct dmctx bbf_ctx;
	unsigned int proto;
	char in_name[128];
	char in_plugin_dir[128];
	char in_type[32];
	char out_type[32];
	char *cmd;
	bool ubus_status;
} cli_data_t;

typedef struct {
    char *name;
    int num_args;
    int (*exec_cmd)(cli_data_t *cli_data, char *argv[]);
    char *usage;
} cli_cmd_t;

static int cli_exec_help(cli_data_t *cli_data UNUSED, char *argv[] UNUSED);
static int cli_exec_get(cli_data_t *cli_data, char *argv[]);
static int cli_exec_set(cli_data_t *cli_data, char *argv[]);
static int cli_exec_add(cli_data_t *cli_data, char *argv[]);
static int cli_exec_del(cli_data_t *cli_data, char *argv[]);
static int cli_exec_instances(cli_data_t *cli_data, char *argv[]);
static int cli_exec_schema(cli_data_t *cli_data, char *argv[]);

cli_cmd_t cli_commands[] = {
//    Name    NumArgs   Exec callback     Usage String
	{ "help",    0,		cli_exec_help,  "help" },
	{ "get",     1, 	cli_exec_get,   "get [path-expr]" },
	{ "set",     2, 	cli_exec_set,   "set [path-expr] [value]"},
	{ "add",     1, 	cli_exec_add,   "add [object]"},
	{ "del",     1, 	cli_exec_del,   "del [path-expr]"},
	{ "instances", 1, 	cli_exec_instances,   "instances [path-expr]" },
	{ "schema",    1,  	cli_exec_schema,  "schema [path-expr]"},
};

typedef void (*__ubus_cb)(struct ubus_request *req, int type, struct blob_attr *msg);

static int bbfdm_ubus_invoke(const char *obj, const char *method, struct blob_attr *msg, __ubus_cb bbfdm_ubus_callback, void *callback_arg)
{
	struct ubus_context *ctx = NULL;
	uint32_t id;
	int rc = 0;

	ctx = ubus_connect(NULL);
	if (ctx == NULL) {
		printf("Can't create ubus context\n");
		return -1;
	}

	if (!ubus_lookup_id(ctx, obj, &id))
		rc = ubus_invoke(ctx, id, method, msg, bbfdm_ubus_callback, callback_arg, 30000);
	else
		rc = -1;


	ubus_free(ctx);
	ctx = NULL;

	return rc;
}

static struct blob_attr *get_results_array(struct blob_attr *msg)
{
	struct blob_attr *tb[1] = {0};
	const struct blobmsg_policy p[1] = {
			{ "results", BLOBMSG_TYPE_ARRAY }
	};

	if (msg == NULL)
		return NULL;

	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));

	return tb[0];
}

static void __ubus_callback(struct ubus_request *req, int msgtype __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *cur = NULL;
	int rem = 0;
	const struct blobmsg_policy p[7] = {
			{ "path", BLOBMSG_TYPE_STRING },
			{ "data", BLOBMSG_TYPE_STRING },
			{ "type", BLOBMSG_TYPE_STRING },
			{ "fault", BLOBMSG_TYPE_INT32 },
			{ "input", BLOBMSG_TYPE_ARRAY },
			{ "output", BLOBMSG_TYPE_ARRAY },
			{ "fault_msg", BLOBMSG_TYPE_STRING }
	};

	if (msg == NULL || req == NULL)
		return;

	cli_data_t *cli_data = (cli_data_t *)req->priv;
	struct blob_attr *parameters = get_results_array(msg);

	if (parameters == NULL) {
		cli_data->ubus_status = false;
		return;
	}

	if (blobmsg_len(parameters) == 0) {
		cli_data->ubus_status = true;
		return;
	}

	blobmsg_for_each_attr(cur, parameters, rem) {
		struct blob_attr *tb[7] = {0};

		blobmsg_parse(p, 7, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = tb[0] ? blobmsg_get_string(tb[0]) : "";
		char *data = tb[1] ? blobmsg_get_string(tb[1]) : "";

		if (tb[3]) {
			printf("Fault %u: %s\n", blobmsg_get_u32(tb[3]), tb[6] ? blobmsg_get_string(tb[6]) : "");
			cli_data->ubus_status = false;
			return;
		}

		if (strcmp(cli_data->cmd, "get") == 0)
			printf("%s => %s\n", name, data);
		else if (strcmp(cli_data->cmd, "set") == 0) {
			printf("Set value of %s is successfully done\n", name);
		} else if (strcmp(cli_data->cmd, "add") == 0) {
			printf("Added %s%s.\n", name, data);
		} else if (strcmp(cli_data->cmd, "del") == 0) {
			printf("Deleted %s\n", name);
		} else if (strcmp(cli_data->cmd, "instances") == 0) {
			printf("%s\n", name);
		} else if (strcmp(cli_data->cmd, "schema") == 0) {
			char *type = tb[2] ? blobmsg_get_string(tb[2]) : "";
			int cmd = get_dm_type(type);

			printf("%s %s %s\n", name, type, (cmd != DMT_EVENT && cmd != DMT_COMMAND) ? data : "0");
		}

		cli_data->ubus_status = true;
	}
}

static int in_ubus_out_cli_exec_cmd(cli_data_t *cli_data, const char *path, const char *value)
{
	struct blob_buf b = {0};
	void *table = NULL;
	int err = EXIT_SUCCESS;

	memset(&b, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	if (value) blobmsg_add_string(&b, "value", value);

	table = blobmsg_open_table(&b, "optional");
	blobmsg_add_string(&b, "proto", (cli_data->proto == BBFDM_CWMP) ? "cwmp" : (cli_data->proto == BBFDM_USP) ? "usp" : "both");
	blobmsg_add_string(&b, "format", "raw");
	blobmsg_close_table(&b, table);

	int e = bbfdm_ubus_invoke(cli_data->in_name, cli_data->cmd, b.head, __ubus_callback, cli_data);

	if (e < 0) {
		printf("ERROR: ubus invoke for [object:%s method:%s] exit with error(%d)\n", cli_data->in_name, cli_data->cmd, e);
		err = EXIT_FAILURE;
	}

	if (cli_data->ubus_status == false) {
		printf("ERROR: ubus call for [object:%s method:%s] exit with error\n", cli_data->in_name, cli_data->cmd);
		err = EXIT_FAILURE;
	}

	blob_buf_free(&b);

	return err;
}

static int bbfdm_load_cli_config(bbfdm_config_t *bbf_config, cli_data_t *cli_data)
{
	char *opt_val = NULL;

	cli_data->proto = bbf_config->proto;

	opt_val = bbf_config->cli_in_type;
	if (opt_val && strlen(opt_val)) {
		snprintf(cli_data->in_type, sizeof(cli_data->in_type), "%s", opt_val);
	} else {
		printf("ERROR: [cli.input.type] not specified\n");
		return -1;
	}

	opt_val = bbf_config->cli_in_name;
	if (opt_val && strlen(opt_val)) {
		snprintf(cli_data->in_name, sizeof(cli_data->in_name), "%s", opt_val);
	} else {
		printf("ERROR: [cli.input.name] not specified\n");
		return -1;
	}

	opt_val = bbf_config->cli_in_plugin_dir;
	if (opt_val && strlen(opt_val)) {
		snprintf(cli_data->in_plugin_dir, sizeof(cli_data->in_plugin_dir), "%s", opt_val);
	}

	opt_val = bbf_config->cli_out_type;
	if (opt_val && strlen(opt_val)) {
		snprintf(cli_data->out_type, sizeof(cli_data->out_type), "%s", opt_val);
	} else {
		printf("ERROR: [cli.output.type] not specified\n");
		return -1;
	}

	return 0;
}

static int cli_exec_help(cli_data_t *cli_data UNUSED, char *argv[] UNUSED)
{
	cli_cmd_t *cli_cmd;

	printf("Valid commands:\n");

	// Print out the help usage of all commands
	for (size_t i = 0; i < ARRAY_SIZE(cli_commands); i++) {
		cli_cmd = &cli_commands[i];
		printf("   %s\n", cli_cmd->usage);
	}

	return EXIT_SUCCESS;
}

static int in_dotso_out_cli_exec_get(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	cli_data->bbf_ctx.in_param = argv[0];

	err = bbf_entry_method(&cli_data->bbf_ctx, BBF_GET_VALUE);
	if (!err) {
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		blobmsg_for_each_attr(cur, cli_data->bbf_ctx.bb.head, rem) {
			struct blob_attr *tb[2] = {0};
			const struct blobmsg_policy p[2] = {
					{ "path", BLOBMSG_TYPE_STRING },
					{ "data", BLOBMSG_TYPE_STRING }
			};

			blobmsg_parse(p, 2, tb, blobmsg_data(cur), blobmsg_len(cur));

			char *name = (tb[0]) ? blobmsg_get_string(tb[0]) : "";
			char *data = (tb[1]) ? blobmsg_get_string(tb[1]) : "";

			printf("%s => %s\n", name, data);
		}

		// Apply all bbfdm changes
		dmuci_commit_bbfdm();
	} else {
		printf("ERROR: %d retrieving %s\n", err, cli_data->bbf_ctx.in_param);
		dmuci_revert_bbfdm();
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_get(cli_data_t *cli_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(cli_data, argv[0], argv[1]);
}

static int cli_exec_get(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0)
		err = in_dotso_out_cli_exec_get(cli_data, argv);
	else if (strcasecmp(cli_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_get(cli_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_set(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	cli_data->bbf_ctx.in_param = argv[0];
	cli_data->bbf_ctx.in_value = argv[1];

	err = bbf_entry_method(&cli_data->bbf_ctx, BBF_SET_VALUE);
	if (!err) {
		printf("%s => Set value is successfully done\n", cli_data->bbf_ctx.in_param);
		bbf_entry_services(cli_data->proto, true, true);
	} else {
		printf("Fault %d: %s\n", err, cli_data->bbf_ctx.fault_msg);
		bbf_entry_services(cli_data->proto, false, true);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_set(cli_data_t *cli_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(cli_data, argv[0], argv[1]);
}

static int cli_exec_set(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0)
		err = in_dotso_out_cli_exec_set(cli_data, argv);
	else if (strcasecmp(cli_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_set(cli_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_add(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	cli_data->bbf_ctx.in_param = argv[0];

	err = bbf_entry_method(&cli_data->bbf_ctx, BBF_ADD_OBJECT);
	if (!err) {
		printf("Added %s%s.\n", cli_data->bbf_ctx.in_param, cli_data->bbf_ctx.addobj_instance);
		bbf_entry_services(cli_data->proto, true, false);
	} else {
		printf("Fault %d: %s\n", err, cli_data->bbf_ctx.fault_msg);
		bbf_entry_services(cli_data->proto, false, false);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_add(cli_data_t *cli_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(cli_data, argv[0], argv[1]);
}

static int cli_exec_add(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0)
		err = in_dotso_out_cli_exec_add(cli_data, argv);
	else if (strcasecmp(cli_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_add(cli_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_del(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	cli_data->bbf_ctx.in_param = argv[0];

	err = bbf_entry_method(&cli_data->bbf_ctx, BBF_DEL_OBJECT);
	if (!err) {
		printf("Deleted %s\n", cli_data->bbf_ctx.in_param);
		bbf_entry_services(cli_data->proto, true, true);
	} else {
		printf("Fault %d: %s\n", err, cli_data->bbf_ctx.fault_msg);
		bbf_entry_services(cli_data->proto, false, true);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_del(cli_data_t *cli_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(cli_data, argv[0], argv[1]);
}

static int cli_exec_del(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0)
		err = in_dotso_out_cli_exec_del(cli_data, argv);
	else if (strcasecmp(cli_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_del(cli_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_instances(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	cli_data->bbf_ctx.in_param = argv[0];
	cli_data->bbf_ctx.nextlevel = false;

	err = bbf_entry_method(&cli_data->bbf_ctx, BBF_INSTANCES);
	if (!err) {
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		blobmsg_for_each_attr(cur, cli_data->bbf_ctx.bb.head, rem) {
			struct blob_attr *tb[1] = {0};
			const struct blobmsg_policy p[1] = {
					{ "path", BLOBMSG_TYPE_STRING }
			};

			blobmsg_parse(p, 1, tb, blobmsg_data(cur), blobmsg_len(cur));

			printf("%s\n", (tb[0]) ? blobmsg_get_string(tb[0]) : "");
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, cli_data->bbf_ctx.in_param);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_instances(cli_data_t *cli_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(cli_data, argv[0], argv[1]);
}

static int cli_exec_instances(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0)
		err = in_dotso_out_cli_exec_instances(cli_data, argv);
	else if (strcasecmp(cli_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_instances(cli_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_schema(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	cli_data->bbf_ctx.in_param = argv[0];
	cli_data->bbf_ctx.nextlevel = false;
	cli_data->bbf_ctx.iscommand = true;
	cli_data->bbf_ctx.isevent = true;
	cli_data->bbf_ctx.isinfo = true;

	err = bbf_entry_method(&cli_data->bbf_ctx, BBF_SCHEMA);
	if (!err) {
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		blobmsg_for_each_attr(cur, cli_data->bbf_ctx.bb.head, rem) {
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

			int cmd = get_dm_type(type);
			printf("%s %s %s\n", name, type, (cmd != DMT_EVENT && cmd != DMT_COMMAND) ? data : "0");
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, cli_data->bbf_ctx.in_param);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_schema(cli_data_t *cli_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(cli_data, argv[0], argv[1]);
}

static int cli_exec_schema(cli_data_t *cli_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0)
		err = in_dotso_out_cli_exec_schema(cli_data, argv);
	else if (strcasecmp(cli_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_schema(cli_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int cli_exec_command(cli_data_t *cli_data, int argc, char *argv[])
{
	cli_cmd_t *cli_cmd = NULL;
	int err = EXIT_SUCCESS;
	bool registred_command = false;

	cli_data->cmd = argv[0];
	if (!cli_data->cmd || strlen(cli_data->cmd) == 0)
		return EXIT_FAILURE;

	if (strcasecmp(cli_data->in_type, "DotSO") == 0 || strcasecmp(cli_data->in_type, "JSON") == 0) {

		if (strcasecmp(cli_data->in_type, "DotSO") == 0) {
			if (load_dotso_plugin(&cli_lib_handle, cli_data->in_name, NULL, &CLI_DM_ROOT_OBJ) != 0) {
				err = EXIT_FAILURE;
				goto end;
			}
		} else {
			if (load_json_plugin(&loaded_json_files, &json_list, &json_memhead, cli_data->in_name, NULL, &CLI_DM_ROOT_OBJ) != 0) {
				err = EXIT_FAILURE;
				goto end;
			}
		}

		if (CLI_DM_ROOT_OBJ == NULL) {
			err = EXIT_FAILURE;
			goto end;
		}

		bbf_global_init(CLI_DM_ROOT_OBJ, cli_data->in_plugin_dir);

		bbf_ctx_init(&cli_data->bbf_ctx, CLI_DM_ROOT_OBJ);

		cli_data->bbf_ctx.dm_type = cli_data->proto;
	} else if (strcasecmp(cli_data->in_type, "UBUS") != 0) {
		return -1;
	}

	for (size_t i = 0; i < ARRAY_SIZE(cli_commands); i++) {

        cli_cmd = &cli_commands[i];
        if (strcmp(cli_data->cmd, cli_cmd->name) == 0) {

        	if (argc-1 < cli_cmd->num_args) {
        		printf("ERROR: Number of arguments for %s method is wrong(%d), it should be %d\n", cli_cmd->name, argc-1, cli_cmd->num_args);
        		cli_commands[0].exec_cmd(cli_data, NULL);
        		err = EXIT_FAILURE;
        		goto end;
        	}

        	err = cli_cmd->exec_cmd(cli_data, &argv[1]);
        	registred_command = true;
        	break;
        }
	}

	if (!registred_command) {
		printf("ERROR: Unknown command: %s\n", cli_data->cmd);
		cli_commands[0].exec_cmd(cli_data, NULL);
		err = EXIT_FAILURE;
	}

end:
	if (strcasecmp(cli_data->in_type, "DotSO") == 0) {
		if (CLI_DM_ROOT_OBJ) {
			bbf_ctx_clean(&cli_data->bbf_ctx);
			bbf_global_clean(CLI_DM_ROOT_OBJ);
		}
		free_dotso_plugin(cli_lib_handle);
		cli_lib_handle = NULL;
	} else if (strcasecmp(cli_data->in_type, "JSON") == 0) {
		if (CLI_DM_ROOT_OBJ) {
			bbf_ctx_clean(&cli_data->bbf_ctx);
			bbf_global_clean(CLI_DM_ROOT_OBJ);
		}
		free_json_plugin();
	}

	return err;
}

int bbfdm_cli_exec_command(bbfdm_config_t *bbf_config, int argc, char *argv[])
{
	cli_data_t cli_data = {0};
	int err = EXIT_SUCCESS;

	// Exit if no command specified
	if (argc < 1) {
		printf("ERROR: command name not specified\n");
		return EXIT_FAILURE;
	}

	memset(&cli_data, 0, sizeof(cli_data_t));

	err = bbfdm_load_cli_config(bbf_config, &cli_data);
	if (err) {
		printf("ERROR: required cli config missing\n");
		return EXIT_FAILURE;
	}

	err = cli_exec_command(&cli_data, argc, argv);
	return err;
}
