/*
 * cli.c: Cli command for bbfdmd
 *
 * Copyright (C) 2023 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdlib.h>
#include <stdio.h>

#include "common.h"
#include "libbbfdm-api/dmapi.h"
#include "libbbfdm-api/dmjson.h"
#include "libbbfdm-api/dmentry.h"

#define UNUSED  __attribute__((unused))

typedef struct {
	struct dmctx bbf_ctx;
	unsigned int instance_mode;
	unsigned int proto;
	char in_type[128];
	char in_name[128];
	char out_type[128];
	char *cmd;
	bool ubus_status;
} client_data_t;

typedef struct {
    char *name;
    int num_args;
    int (*exec_cmd)(client_data_t *client_data, char *argv[]);
    char *usage;
} cli_cmd_t;

static int cli_exec_help(client_data_t *client_data UNUSED, char *argv[] UNUSED);
static int cli_exec_get(client_data_t *client_data, char *argv[]);
static int cli_exec_set(client_data_t *client_data, char *argv[]);
static int cli_exec_add(client_data_t *client_data, char *argv[]);
static int cli_exec_del(client_data_t *client_data, char *argv[]);
static int cli_exec_instances(client_data_t *client_data, char *argv[]);
static int cli_exec_schema(client_data_t *client_data, char *argv[]);

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
		rc = ubus_invoke(ctx, id, method, msg, bbfdm_ubus_callback, callback_arg, 20000);
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
	const struct blobmsg_policy p[6] = {
			{ "path", BLOBMSG_TYPE_STRING },
			{ "data", BLOBMSG_TYPE_STRING },
			{ "type", BLOBMSG_TYPE_STRING },
			{ "fault", BLOBMSG_TYPE_INT32 },
			{ "input", BLOBMSG_TYPE_ARRAY },
			{ "output", BLOBMSG_TYPE_ARRAY },
	};

	if (msg == NULL || req == NULL)
		return;

	client_data_t *client_data = (client_data_t *)req->priv;
	struct blob_attr *parameters = get_results_array(msg);

	if (parameters == NULL) {
		client_data->ubus_status = false;
		return;
	}

	blobmsg_for_each_attr(cur, parameters, rem) {
		struct blob_attr *tb[6] = {0};

		blobmsg_parse(p, 6, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = tb[0] ? blobmsg_get_string(tb[0]) : "";
		char *data = tb[1] ? blobmsg_get_string(tb[1]) : "";

		if (tb[3]) {
			printf("ERROR: %u retrieving %s\n", blobmsg_get_u32(tb[3]), name);
			client_data->ubus_status = false;
			return;
		}

		if (strcmp(client_data->cmd, "get") == 0)
			printf("%s => %s\n", name, data);
		else if (strcmp(client_data->cmd, "set") == 0) {
			printf("%s => Set value is successfully done\n", name);
		} else if (strcmp(client_data->cmd, "add") == 0) {
			printf("Added %s%s.\n", name, data);
		} else if (strcmp(client_data->cmd, "del") == 0) {
			printf("Deleted %s\n", name);
		} else if (strcmp(client_data->cmd, "instances") == 0) {
			printf("%s\n", name);
		} else if (strcmp(client_data->cmd, "schema") == 0) {
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
						struct blob_attr *in_tb[6] = {0};

						blobmsg_parse(p, 6, in_tb, blobmsg_data(in_cur), blobmsg_len(in_cur));

						char *arg = in_tb[0] ? blobmsg_get_string(in_tb[0]) : "";
						printf("%s input:%s\n", name, arg);
					}
				}

				if (output) {
					blobmsg_for_each_attr(out_cur, output, out_rem) {
						struct blob_attr *out_tb[6] = {0};

						blobmsg_parse(p, 6, out_tb, blobmsg_data(out_cur), blobmsg_len(out_cur));

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
						struct blob_attr *in_tb[6] = {0};

						blobmsg_parse(p, 6, in_tb, blobmsg_data(in_cur), blobmsg_len(in_cur));

						char *arg = in_tb[0] ? blobmsg_get_string(in_tb[0]) : "";
						printf("%s event_arg:%s\n", name, arg);
					}
				}
			}
		}

		client_data->ubus_status = true;
	}
}

static int in_ubus_out_cli_exec_cmd(client_data_t *client_data, const char *path, const char *value)
{
	struct blob_buf b = {0};
	void *table = NULL;
	int err = EXIT_SUCCESS;

	memset(&b, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	if (value) blobmsg_add_string(&b, "value", value);

	table = blobmsg_open_table(&b, "optional");
	blobmsg_add_string(&b, "proto", (client_data->proto == BBFDM_CWMP) ? "cwmp" : "usp");
	blobmsg_add_string(&b, "format", "raw");
	blobmsg_add_u32(&b, "instance_mode", client_data->instance_mode);
	blobmsg_close_table(&b, table);

	int e = bbfdm_ubus_invoke(client_data->in_name, client_data->cmd, b.head, __ubus_callback, client_data);

	if (e < 0) {
		printf("ERROR: ubus invoke for [object:%s method:%s] exit with error(%d)\n", client_data->in_name, client_data->cmd, e);
		err = EXIT_FAILURE;
	}

	if (client_data->ubus_status == false) {
		printf("ERROR: ubus call for [object:%s method:%s] exit with error\n", client_data->in_name, client_data->cmd);
		err = EXIT_FAILURE;
	}

	blob_buf_free(&b);

	return err;
}

static int bbfdm_load_client_config(const char *json_path, client_data_t *client_data)
{
	json_object *json_obj = NULL;
	char *opt_val = NULL;

	if (!json_path || !strlen(json_path)) {
		printf("ERROR: json file not specified\n");
		return -1;
	}

	json_obj = json_object_from_file(json_path);
	if (!json_obj) {
		printf("ERROR: not possible to load json file (%s)\n", json_path);
		return -1;
	}

	opt_val = dmjson_get_value(json_obj, 3, "client", "config", "proto");
	if (opt_val && strlen(opt_val)) {
		client_data->proto = get_proto_type(opt_val);
	} else {
		client_data->proto = BBFDM_BOTH;
	}

	opt_val = dmjson_get_value(json_obj, 3, "client", "config", "instance_mode");
	if (opt_val && strlen(opt_val)) {
		int inst_mode = (int) strtol(opt_val, NULL, 10);
		client_data->instance_mode = get_instance_mode(inst_mode);
	} else {
		client_data->instance_mode = INSTANCE_MODE_NUMBER;
	}

	opt_val = dmjson_get_value(json_obj, 3, "client", "input", "type");
	if (opt_val && strlen(opt_val)) {
		snprintf(client_data->in_type, sizeof(client_data->in_type), "%s", opt_val);
	} else {
		printf("ERROR: [client.input.type] not specified\n");
		return -1;
	}

	opt_val = dmjson_get_value(json_obj, 3, "client", "input", "name");
	if (opt_val && strlen(opt_val)) {
		snprintf(client_data->in_name, sizeof(client_data->in_name), "%s", opt_val);
	} else {
		printf("ERROR: [client.input.name] not specified\n");
		return -1;
	}

	opt_val = dmjson_get_value(json_obj, 3, "client", "output", "type");
	if (opt_val && strlen(opt_val)) {
		snprintf(client_data->out_type, sizeof(client_data->out_type), "%s", opt_val);
	} else {
		printf("ERROR: [client.output.type] not specified\n");
		return -1;
	}

	json_object_put(json_obj);
	return 0;
}

static int cli_exec_help(client_data_t *client_data UNUSED, char *argv[] UNUSED)
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

static int in_dotso_out_cli_exec_get(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	client_data->bbf_ctx.in_param = argv[0];

	err = bbf_entry_method(&client_data->bbf_ctx, BBF_GET_VALUE);
	if (!err) {
		struct dm_parameter *n;

		list_for_each_entry(n, &client_data->bbf_ctx.list_parameter, list) {
			printf("%s => %s\n", n->name, n->data);
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, client_data->bbf_ctx.in_param);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_get(client_data_t *client_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(client_data, argv[0], argv[1]);
}

static int cli_exec_get(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(client_data->in_type, "DotSO") == 0)
		err = in_dotso_out_cli_exec_get(client_data, argv);
	else if (strcasecmp(client_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_get(client_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_set(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	client_data->bbf_ctx.in_param = argv[0];
	client_data->bbf_ctx.in_value = argv[1];

	err = bbf_entry_method(&client_data->bbf_ctx, BBF_SET_VALUE);
	if (!err) {
		printf("%s => Set value is successfully done\n", client_data->bbf_ctx.in_param);
		bbf_entry_restart_services(NULL, true);
	} else {
		printf("ERROR: %d retrieving %s => %s\n", err, client_data->bbf_ctx.in_param, client_data->bbf_ctx.in_value);
		bbf_entry_revert_changes(NULL);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_set(client_data_t *client_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(client_data, argv[0], argv[1]);
}

static int cli_exec_set(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(client_data->in_type, "DotSO") == 0)
		err = in_dotso_out_cli_exec_set(client_data, argv);
	else if (strcasecmp(client_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_set(client_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_add(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	client_data->bbf_ctx.in_param = argv[0];

	err = bbf_entry_method(&client_data->bbf_ctx, BBF_ADD_OBJECT);
	if (!err) {
		printf("Added %s%s.\n", client_data->bbf_ctx.in_param, client_data->bbf_ctx.addobj_instance);
		bbf_entry_restart_services(NULL, true);
	} else {
		printf("ERROR: %d retrieving %s\n", err, client_data->bbf_ctx.in_param);
		bbf_entry_revert_changes(NULL);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_add(client_data_t *client_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(client_data, argv[0], argv[1]);
}

static int cli_exec_add(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(client_data->in_type, "DotSO") == 0)
		err = in_dotso_out_cli_exec_add(client_data, argv);
	else if (strcasecmp(client_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_add(client_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_del(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	client_data->bbf_ctx.in_param = argv[0];

	err = bbf_entry_method(&client_data->bbf_ctx, BBF_DEL_OBJECT);
	if (!err) {
		printf("Deleted %s\n", client_data->bbf_ctx.in_param);
		bbf_entry_restart_services(NULL, true);
	} else {
		printf("ERROR: %d retrieving %s\n", err, client_data->bbf_ctx.in_param);
		bbf_entry_revert_changes(NULL);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_del(client_data_t *client_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(client_data, argv[0], argv[1]);
}

static int cli_exec_del(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(client_data->in_type, "DotSO") == 0)
		err = in_dotso_out_cli_exec_del(client_data, argv);
	else if (strcasecmp(client_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_del(client_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_instances(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	client_data->bbf_ctx.in_param = argv[0];
	client_data->bbf_ctx.nextlevel = false;

	err = bbf_entry_method(&client_data->bbf_ctx, BBF_INSTANCES);
	if (!err) {
		struct dm_parameter *n;

		list_for_each_entry(n, &client_data->bbf_ctx.list_parameter, list) {
			printf("%s\n", n->name);
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, client_data->bbf_ctx.in_param);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_instances(client_data_t *client_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(client_data, argv[0], argv[1]);
}

static int cli_exec_instances(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(client_data->in_type, "DotSO") == 0)
		err = in_dotso_out_cli_exec_instances(client_data, argv);
	else if (strcasecmp(client_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_instances(client_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int in_dotso_out_cli_exec_schema(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	client_data->bbf_ctx.in_param = argv[0];
	client_data->bbf_ctx.nextlevel = false;
	client_data->bbf_ctx.iscommand = true;
	client_data->bbf_ctx.isevent = true;
	client_data->bbf_ctx.isinfo = true;

	err = bbf_entry_method(&client_data->bbf_ctx, BBF_SCHEMA);
	if (!err) {
		struct dm_parameter *n;

	    printf("\nDumping %s Schema...\n\n", client_data->bbf_ctx.in_param);

		list_for_each_entry(n, &client_data->bbf_ctx.list_parameter, list) {
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
		printf("ERROR: %d retrieving %s\n", err, client_data->bbf_ctx.in_param);
		err = EXIT_FAILURE;
	}

	return err;
}

static int in_ubus_out_cli_exec_schema(client_data_t *client_data, char *argv[])
{
	return in_ubus_out_cli_exec_cmd(client_data, argv[0], argv[1]);
}

static int cli_exec_schema(client_data_t *client_data, char *argv[])
{
	int err = EXIT_SUCCESS;

	if (strcasecmp(client_data->in_type, "DotSO") == 0)
		err = in_dotso_out_cli_exec_schema(client_data, argv);
	else if (strcasecmp(client_data->in_type, "UBUS") == 0)
		err = in_ubus_out_cli_exec_schema(client_data, argv);
	else
		err = EXIT_FAILURE;

	return err;
}

static int cli_exec_command(client_data_t *client_data, int argc, char *argv[])
{
	cli_cmd_t *cli_cmd = NULL;
	int err = EXIT_SUCCESS;
	bool registred_command = false;

	client_data->cmd = argv[0];
	if (!client_data->cmd || strlen(client_data->cmd) == 0)
		return EXIT_FAILURE;

	if (strcasecmp(client_data->in_type, "DotSO") == 0) {

		bbf_ctx_init(&client_data->bbf_ctx, DM_ROOT_OBJ, DM_VENDOR_EXTENSION, DM_VENDOR_EXTENSION_EXCLUDE);

		client_data->bbf_ctx.dm_type = client_data->proto;
		client_data->bbf_ctx.instance_mode = client_data->instance_mode;
	}

	for (size_t i = 0; i < ARRAY_SIZE(cli_commands); i++) {

        cli_cmd = &cli_commands[i];
        if (strcmp(client_data->cmd, cli_cmd->name)==0) {

        	if (argc-1 < cli_cmd->num_args) {
        		printf("ERROR: Number of arguments for %s method is wrong(%d), it should be %d\n", cli_cmd->name, argc-1, cli_cmd->num_args);
        		cli_commands[0].exec_cmd(client_data, NULL);
        		err = EXIT_FAILURE;
        		goto end;
        	}

        	err = cli_cmd->exec_cmd(client_data, &argv[1]);
        	registred_command = true;
        	break;
        }
	}

	if (!registred_command) {
		printf("ERROR: Unknown command: %s\n", client_data->cmd);
		cli_commands[0].exec_cmd(client_data, NULL);
		return EXIT_FAILURE;
	}

end:
	if (strcasecmp(client_data->in_type, "DotSO") == 0) {
		bbf_ctx_clean(&client_data->bbf_ctx);
		bbf_global_clean(DM_ROOT_OBJ);
	}

	return err;
}

int bbfdm_cli_exec_command(const char *json_path, int argc, char *argv[])
{
	client_data_t client_data = {0};
	int err = EXIT_SUCCESS;

	memset(&client_data, 0, sizeof(client_data_t));

	err = bbfdm_load_client_config(json_path, &client_data);
	if (err)
		return EXIT_FAILURE;

	// Exit if no command specified
	if (argc < 1) {
		printf("ERROR: command name not specified\n");
		return EXIT_FAILURE;
	}

	return cli_exec_command(&client_data, argc, argv);
}
