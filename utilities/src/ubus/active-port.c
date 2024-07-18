/*
 * active_port.c: active-port daemon that provides active-port ubus object
 * 		  and a dump method which read from netstat output and
 * 		  returns local and remote IP and port and connections state.
 * 		  This is done for Device.IP.ActivePort object, whose json
 * 		  maps to this ubus call.
 *
 * Copyright (C) 2024 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Mohd Husaam Mehdi <husaam.mehdi@genexis.eu>
 *
 * See LICENSE file for license related information.
 */

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#define MAX_LINE_LEN 256

static int parse_ip_port(char *str, char **ip, char **port)
{
	char *colon = NULL;

	// get the last colon in string
	colon = strrchr(str, ':');
	if (!colon) {
		syslog(LOG_ERR, "active-port(%s,%u): ERROR (ip port not separated by ':')\n", __func__, __LINE__);
		return 1;
	}

	*colon = '\0';
	*ip = str;
	*port = colon + 1;

	return 0;
}

static const struct blobmsg_policy active_port_policy[] = {};

static int parse_line(char *line, struct blob_buf *b)
{
	char *local_ip = NULL;
	char *local_port = NULL;
	char *remote_ip = NULL;
	char *remote_port = NULL;
	bool established = false;

	char *token = NULL, *end = NULL;
	// split the columns
	token = strtok_r(line, " ", &end);
	int i = 0;
	while (token != NULL) {
		switch (i) {
			// first column
			case 0:
				if (parse_ip_port(token, &local_ip, &local_port) != 0)
					return 1;

				i++;
				break;
				// second column
			case 1:

				if (parse_ip_port(token, &remote_ip, &remote_port) != 0)
					return 1;

				i++;
				break;
			case 2:
				// if established is found strncmp would be 0 and established would be 1
				established = !strncmp(token, "ESTABLISHED", strlen("ESTABLISHED"));
				i++;
				break;

			default:
				syslog(LOG_ERR, "active-port(%s,%u): ERROR (extra column in netstat)\n", __func__, __LINE__);
				return 1;
		}

		token = strtok_r(NULL, " ", &end);
	}

	if (!local_ip || !local_port || !remote_ip || !remote_port) {
		syslog(LOG_ERR, "active-port(%s,%u): ERROR (missing data in netstat)\n", __func__, __LINE__);
		return 1;
	}

	void *dd = NULL;

	dd = blobmsg_open_table(b, "");

	blobmsg_add_string(b, "local_ip", local_ip);
	blobmsg_add_string(b, "local_port", local_port);
	blobmsg_add_string(b, "remote_ip", remote_ip);
	blobmsg_add_string(b, "remote_port", remote_port);
	blobmsg_add_string(b, "status", established ? "ESTABLISHED" : "LISTEN");

	blobmsg_close_table(b, dd);

	return 0;
}

static int active_port_dump_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_buf b = {0};

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	FILE *pp = NULL;
	char cmd[64] = {0};
	// get the output of netstat (do not resolve ip addresses, get tcp connections, all kinds of states)
	// skip the first two rows(headers) and print the 4th, 5th and 6th column separated by single space
	snprintf(cmd, sizeof(cmd), "netstat -nta 2>/dev/null | awk \'NR>2 {print $4, $5, $6}\'");

	pp = popen(cmd, "r");
	if (pp != NULL) {
		void *d = NULL;
		d = blobmsg_open_array(&b, "connections");

		char line[MAX_LINE_LEN] = {0};

		while (fgets(line, MAX_LINE_LEN, pp) != NULL) {
			// remove_new_line
			line[strcspn(line, "\n")] = 0;
			// stop parsing if there is a problem in one of the lines
			if (parse_line(line, &b) != 0)
				break;
		}

		pclose(pp);
		blobmsg_close_array(&b, d);
	} else {
		blobmsg_add_string(&b, "error", "Could not run netstat");
		goto end;
	}

end:
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}


static const struct ubus_method active_port_methods[] = {
	UBUS_METHOD("dump", active_port_dump_handler, active_port_policy),
};

static struct ubus_object_type active_port_object_type = UBUS_OBJECT_TYPE("active-port", active_port_methods);

static struct ubus_object active_port_object = {
	.name = "active-port",
	.type = &active_port_object_type,
	.methods = active_port_methods,
	.n_methods = ARRAY_SIZE(active_port_methods),
};

int main(int argc, char **argv)
{
	struct ubus_context *uctx;

	openlog("active-port", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	uctx = ubus_connect(NULL);
	if (uctx == NULL) {
		printf("Can't create UBUS context");
		return -1;
	}

	uloop_init();
	ubus_add_uloop(uctx);

	if (ubus_add_object(uctx, &active_port_object))
		goto exit;

	uloop_run();

exit:
	uloop_done();
	ubus_free(uctx);
	closelog();

	return 0;
}
