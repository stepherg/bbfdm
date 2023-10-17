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
extern const char *CONFIG_PLUGIN_PATH;

#define UNUSED  __attribute__((unused))

static DMOBJ *CLI_DM_ROOT_OBJ = NULL;
static DM_MAP_VENDOR *CLI_DM_VENDOR_EXTENSION[2] = {0};
static DM_MAP_VENDOR_EXCLUDE *CLI_DM_VENDOR_EXTENSION_EXCLUDE = NULL;

static void *cli_lib_handle = NULL;
static json_object *cli_json_obj = NULL;

typedef struct {
	struct dmctx bbf_ctx;
	unsigned int instance_mode;
	unsigned int proto;
	char in_name[128];
	char in_type[8];
	char out_type[8];
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

static void __ubus_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *cur = NULL;
	bool print_msg = false;
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

			if (print_msg == false) {
				printf("\nDumping %s Schema...\n\n", name);
				print_msg = true;
			}

			printf("%s\n", name);

			if (cmd == DMT_COMMAND) {
				struct blob_attr *input = tb[4];
				struct blob_attr *output = tb[5];
				struct blob_attr *in_cur = NULL, *out_cur = NULL;
				int in_rem = 0, out_rem = 0;

				if (input) {
					blobmsg_for_each_attr(in_cur, input, in_rem) {
						struct blob_attr *in_tb[7] = {0};

						blobmsg_parse(p, 7, in_tb, blobmsg_data(in_cur), blobmsg_len(in_cur));

						char *arg = in_tb[0] ? blobmsg_get_string(in_tb[0]) : "";
						printf("%s input:%s\n", name, arg);
					}
				}

				if (output) {
					blobmsg_for_each_attr(out_cur, output, out_rem) {
						struct blob_attr *out_tb[7] = {0};

						blobmsg_parse(p, 7, out_tb, blobmsg_data(out_cur), blobmsg_len(out_cur));

						char *arg = out_tb[0] ? blobmsg_get_string(out_tb[0]) : "";
						printf("%s output:%s\n", name, arg);
					}
				}
			} else if (cmd == DMT_EVENT) {
				struct blob_attr *input = tb[4];
				struct blob_attr *in_cur = NULL;
				int in_rem = 0;

				if (input) {
					blobmsg_for_each_attr(in_cur, input, in_rem) {
						struct blob_attr *in_tb[7] = {0};

						blobmsg_parse(p, 7, in_tb, blobmsg_data(in_cur), blobmsg_len(in_cur));

						char *arg = in_tb[0] ? blobmsg_get_string(in_tb[0]) : "";
						printf("%s event_arg:%s\n", name, arg);
					}
				}
			}
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
	blobmsg_add_string(&b, "proto", (cli_data->proto == BBFDM_CWMP) ? "cwmp" : "usp");
	blobmsg_add_string(&b, "format", "raw");
	blobmsg_add_u32(&b, "instance_mode", cli_data->instance_mode);
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

static int bbfdm_load_cli_config(const char *json_path, cli_data_t *cli_data)
{
	char *opt_val = NULL;

	if (!json_path || !strlen(json_path)) {
		printf("ERROR: json file not specified\n");
		return -1;
	}

	cli_json_obj = json_object_from_file(json_path);
	if (!cli_json_obj) {
		printf("ERROR: not possible to load json file (%s)\n", json_path);
		return -1;
	}

	opt_val = dmjson_get_value(cli_json_obj, 3, "cli", "config", "proto");
	if (opt_val && strlen(opt_val)) {
		cli_data->proto = get_proto_type(opt_val);
	} else {
		cli_data->proto = BBFDM_BOTH;
	}

	opt_val = dmjson_get_value(cli_json_obj, 3, "cli", "config", "instance_mode");
	if (opt_val && strlen(opt_val)) {
		int inst_mode = (int) strtol(opt_val, NULL, 10);
		cli_data->instance_mode = get_instance_mode(inst_mode);
	} else {
		cli_data->instance_mode = INSTANCE_MODE_NUMBER;
	}

	opt_val = dmjson_get_value(cli_json_obj, 3, "cli", "input", "type");
	if (opt_val && strlen(opt_val)) {
		snprintf(cli_data->in_type, sizeof(cli_data->in_type), "%s", opt_val);
	} else {
		printf("ERROR: [cli.input.type] not specified\n");
		return -1;
	}

	opt_val = dmjson_get_value(cli_json_obj, 3, "cli", "input", "name");
	if (opt_val && strlen(opt_val)) {
		snprintf(cli_data->in_name, sizeof(cli_data->in_name), "%s", opt_val);
	} else {
		printf("ERROR: [cli.input.name] not specified\n");
		return -1;
	}

	opt_val = dmjson_get_value(cli_json_obj, 3, "cli", "output", "type");
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
		struct dm_parameter *n;

		list_for_each_entry(n, &cli_data->bbf_ctx.list_parameter, list) {
			printf("%s => %s\n", n->name, n->data);
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, cli_data->bbf_ctx.in_param);
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
		bbf_entry_restart_services(NULL, true);
	} else {
		printf("Fault %d: %s\n", err, cli_data->bbf_ctx.fault_msg);
		bbf_entry_revert_changes(NULL);
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
		bbf_entry_restart_services(NULL, true);
	} else {
		printf("Fault %d: %s\n", err, cli_data->bbf_ctx.fault_msg);
		bbf_entry_revert_changes(NULL);
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
		bbf_entry_restart_services(NULL, true);
	} else {
		printf("Fault %d: %s\n", err, cli_data->bbf_ctx.fault_msg);
		bbf_entry_revert_changes(NULL);
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
		struct dm_parameter *n;

		list_for_each_entry(n, &cli_data->bbf_ctx.list_parameter, list) {
			printf("%s\n", n->name);
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
		struct dm_parameter *n;

	    printf("\nDumping %s Schema...\n\n", cli_data->bbf_ctx.in_param);

		list_for_each_entry(n, &cli_data->bbf_ctx.list_parameter, list) {
			int cmd = get_dm_type(n->type);

			printf("%s\n", n->name);

			if (cmd == DMT_COMMAND) {
				if (n->data) {
					const char **in, **out;
					operation_args *args;
					int i;

					args = (operation_args *) n->data;
					in = args->in;
					if (in) {
						for (i = 0; in[i] != NULL; i++)
							printf("%s input:%s\n", n->name, in[i]);
					}

					out = args->out;
					if (out) {
						for (i = 0; out[i] != NULL; i++)
							printf("%s output:%s\n", n->name, out[i]);
					}
				}
			} else if (cmd == DMT_EVENT) {
				if (n->data) {
					event_args *ev;

					ev = (event_args *)n->data;

					if (ev->param) {
						const char **in = ev->param;

						for (int i = 0; in[i] != NULL; i++)
							printf("%s event_arg:%s\n", n->name, in[i]);
					}
				}
			}
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
			if (load_dotso_plugin(&cli_lib_handle, cli_data->in_name,
					&CLI_DM_ROOT_OBJ,
					CLI_DM_VENDOR_EXTENSION,
					&CLI_DM_VENDOR_EXTENSION_EXCLUDE) != 0) {
				err = EXIT_FAILURE;
				goto end;
			}
		} else {
			if (load_json_plugin(&loaded_json_files, &json_list, &json_memhead, cli_data->in_name,
					&CLI_DM_ROOT_OBJ) != 0) {
				err = EXIT_FAILURE;
				goto end;
			}
		}

		if (CLI_DM_ROOT_OBJ == NULL) {
			err = EXIT_FAILURE;
			goto end;
		}

		bbf_global_init(CLI_DM_ROOT_OBJ, CLI_DM_VENDOR_EXTENSION, CLI_DM_VENDOR_EXTENSION_EXCLUDE, CONFIG_PLUGIN_PATH);

		bbf_ctx_init(&cli_data->bbf_ctx, CLI_DM_ROOT_OBJ, CLI_DM_VENDOR_EXTENSION, CLI_DM_VENDOR_EXTENSION_EXCLUDE);

		cli_data->bbf_ctx.dm_type = cli_data->proto;
		cli_data->bbf_ctx.instance_mode = cli_data->instance_mode;
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
	} else if (strcasecmp(cli_data->in_type, "JSON") == 0) {
		if (CLI_DM_ROOT_OBJ) {
			bbf_ctx_clean(&cli_data->bbf_ctx);
			bbf_global_clean(CLI_DM_ROOT_OBJ);
		}
		free_json_plugin();
	}

	return err;
}

int bbfdm_cli_exec_command(const char *input, int argc, char *argv[])
{
	cli_data_t cli_data = {0};
	int err = EXIT_SUCCESS;
	const char *json_input = (input) ? input : BBF_JSON_INPUT;

	memset(&cli_data, 0, sizeof(cli_data_t));

	err = bbfdm_load_cli_config(json_input, &cli_data);
	if (err)
		return EXIT_FAILURE;

	// Exit if no command specified
	if (argc < 1) {
		printf("ERROR: command name not specified\n");
		return EXIT_FAILURE;
	}

	err = cli_exec_command(&cli_data, argc, argv);

	if (cli_json_obj) {
		json_object_put(cli_json_obj);
		cli_json_obj = NULL;
	}
	return err;
}
