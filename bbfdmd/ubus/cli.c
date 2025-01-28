/*
 * Copyright (C) 2023-2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <libubus.h>

#include "common.h"

typedef struct {
	char *cmd;
	bool ubus_status;
} cli_data_t;

typedef struct {
    char *name;
    int num_args;
    int (*exec_cmd)(cli_data_t *cli_data, const char *path, const char *value);
    char *usage;
} cli_cmd_t;

static int cli_exec_help(cli_data_t *cli_data __attribute__((unused)), const char *path __attribute__((unused)), const char *value __attribute__((unused)));
static int cli_exec_cmd(cli_data_t *cli_data, const char *path, const char *value);

cli_cmd_t cli_commands[] = {
//    Name    NumArgs   Exec callback     Usage String
	{ "help",    0,		cli_exec_help,  "help" },
	{ "get",     1, 	cli_exec_cmd,   "get [path-expr]" },
	{ "set",     2, 	cli_exec_cmd,   "set [path-expr] [value]"},
	{ "add",     1, 	cli_exec_cmd,   "add [object]"},
	{ "del",     1, 	cli_exec_cmd,   "del [path-expr]"},
	{ "instances", 1, 	cli_exec_cmd,   "instances [path-expr]" },
	{ "schema",    1,  	cli_exec_cmd,  "schema [path-expr]"},
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
			//char *type = tb[2] ? blobmsg_get_string(tb[2]) : "";
			//int cmd = get_dm_type(type);

			//printf("%s %s %s\n", name, type, (cmd != DMT_EVENT && cmd != DMT_COMMAND) ? data : "0"); //TODO
		}

		cli_data->ubus_status = true;
	}
}

static int cli_exec_cmd(cli_data_t *cli_data, const char *path, const char *value)
{
	struct blob_buf b = {0};
	int err = EXIT_SUCCESS;

	memset(&b, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "value", value ? value : "");

	int e = bbfdm_ubus_invoke(BBFDM_UBUS_OBJECT, cli_data->cmd, b.head, __ubus_callback, cli_data);

	if (e < 0) {
		printf("ERROR: ubus invoke for [object:%s method:%s] exit with error(%d)\n", BBFDM_UBUS_OBJECT, cli_data->cmd, e);
		err = EXIT_FAILURE;
	}

	if (cli_data->ubus_status == false) {
		printf("ERROR: ubus call for [object:%s method:%s] exit with error\n", BBFDM_UBUS_OBJECT, cli_data->cmd);
		err = EXIT_FAILURE;
	}

	blob_buf_free(&b);

	return err;
}

static int cli_exec_help(cli_data_t *cli_data __attribute__((unused)), const char *path __attribute__((unused)), const char *value __attribute__((unused)))
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

static int cli_exec_command(cli_data_t *cli_data, int argc, char *argv[])
{
	cli_cmd_t *cli_cmd = NULL;
	int err = EXIT_SUCCESS;
	bool registred_command = false;

	cli_data->cmd = argv[0];
	if (!cli_data->cmd || strlen(cli_data->cmd) == 0)
		return EXIT_FAILURE;

	for (size_t i = 0; i < ARRAY_SIZE(cli_commands); i++) {

        cli_cmd = &cli_commands[i];
        if (strcmp(cli_data->cmd, cli_cmd->name) == 0) {

        	if (argc-1 < cli_cmd->num_args) {
        		printf("ERROR: Number of arguments for %s method is wrong(%d), it should be %d\n", cli_cmd->name, argc-1, cli_cmd->num_args);
        		cli_commands[0].exec_cmd(cli_data, NULL, NULL);
        		err = EXIT_FAILURE;
        		goto end;
        	}

        	err = cli_cmd->exec_cmd(cli_data, argv[1], argv[2]);
        	registred_command = true;
        	break;
        }
	}

	if (!registred_command) {
		printf("ERROR: Unknown command: %s\n", cli_data->cmd);
		cli_commands[0].exec_cmd(cli_data, NULL, NULL);
		err = EXIT_FAILURE;
	}

end:

	return err;
}

int bbfdmd_cli_exec_command(int argc, char *argv[])
{
	cli_data_t cli_data = {0};

	// Exit if no command specified
	if (argc < 1) {
		printf("ERROR: command name not specified\n");
		return EXIT_FAILURE;
	}

	memset(&cli_data, 0, sizeof(cli_data_t));

	return cli_exec_command(&cli_data, argc, argv);
}
