/*
 * Copyright (C) 2024 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Mohd Husaam Mehdi <husaam.mehdi@genexis.eu>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "activeport.h"

#define STATUS_SIZE 16

typedef struct {
	char local_ip[INET6_ADDRSTRLEN];
	uint16_t local_port;
	char remote_ip[INET6_ADDRSTRLEN];
	uint16_t remote_port;
	unsigned int state;
} ActivePort;

/*************************************************************
 * UTILITY METHODS
 **************************************************************/
void format_ipv6_address(const char *hex_str_ip, char *ipv6_addr)
{
	struct in6_addr addr = {};

	sscanf(hex_str_ip, "%08X%08X%08X%08X",
			&addr.s6_addr32[0], &addr.s6_addr32[1],
			&addr.s6_addr32[2], &addr.s6_addr32[3]);

	// Convert the address to the standard IPv6 format
	inet_ntop(AF_INET6, &addr, ipv6_addr, INET6_ADDRSTRLEN);
}

void parse_tcp_line(const char* line, int is_ipv6, ActivePort* port)
{
	unsigned int local_port, remote_port;
	unsigned int state;
	char local_ip[INET6_ADDRSTRLEN] = {0};
	char remote_ip[INET6_ADDRSTRLEN] = {0};

	if (is_ipv6) {
		char local_ip6[33] = {0}, remote_ip6[33] = {0};
		sscanf(line, "%*d: %32s:%4X %32s:%4X %2X", local_ip6, &local_port, remote_ip6, &remote_port, &state);
		format_ipv6_address(local_ip6, local_ip);
		format_ipv6_address(remote_ip6, remote_ip);
	} else {
		unsigned int local_ip_num, remote_ip_num;
		sscanf(line, "%*d: %8X:%4X %8X:%4X %2X", &local_ip_num, &local_port, &remote_ip_num, &remote_port, &state);

		struct in_addr local_addr = { local_ip_num };
		struct in_addr remote_addr = { remote_ip_num };

		inet_ntop(AF_INET, &local_addr, local_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &remote_addr, remote_ip, INET_ADDRSTRLEN);
	}

	DM_STRNCPY(port->local_ip, local_ip, INET6_ADDRSTRLEN);
	port->local_port = local_port;
	DM_STRNCPY(port->remote_ip, remote_ip, INET6_ADDRSTRLEN);
	port->remote_port = remote_port;
	port->state = state;
}

/*************************************************************
 * ENTRY METHOD
 **************************************************************/
static void browse_ip_port(struct dmctx *dmctx, DMNODE *parent_node, bool is_ipv6, const char *proc_path, int *id, char *inst)
{
	if (proc_path == NULL || DM_STRLEN(proc_path) == 0)
		return;

	FILE* fp = fopen(proc_path, "r");
	if (fp == NULL) {
		return;
	}

	char line[256] = {0};
	fgets(line, sizeof(line), fp); // Skip header line

	while (fgets(line, sizeof(line), fp)) {
		struct dm_data curr_data = {0};

		ActivePort port;
		memset(&port, 0, sizeof(port));
		parse_tcp_line(line, is_ipv6, &port);

		// only display LISTEN or ESTABLISHED
		if (port.state != 1 && port.state != 10)
			continue;

		curr_data.additional_data = (void *)(&port);
		inst = handle_instance_without_section(dmctx, parent_node, ++(*id));

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}

	fclose(fp);
}

int browseIPActivePortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	int id = 0;

	browse_ip_port(dmctx, parent_node, 0, "/proc/net/tcp", &id, inst);
	browse_ip_port(dmctx, parent_node, 1, "/proc/net/tcp6", &id, inst);

	return 0;
}

/*************************************************************
 * GET & SET PARAM
 **************************************************************/
static int get_IP_ActivePort_LocalIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((ActivePort *)((struct dm_data *)data)->additional_data)->local_ip);
	return 0;
}

static int get_IP_ActivePort_LocalPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%u", ((ActivePort *)((struct dm_data *)data)->additional_data)->local_port);
	return 0;
}

static int get_IP_ActivePort_RemoteIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((ActivePort *)((struct dm_data *)data)->additional_data)->remote_ip);
	return 0;
}

static int get_IP_ActivePort_RemotePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%u", ((ActivePort *)((struct dm_data *)data)->additional_data)->remote_port);
	return 0;
}

static int get_IP_ActivePort_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned int state = (((ActivePort *)((struct dm_data *)data)->additional_data)->state);

	switch (state) {
		case 1:
			*value = "ESTABLISHED";
			break;
		case 10:
			*value = "LISTEN";
			break;
		default:
			*value = "";
			break;
	}

	return 0;
}

/**********************************************************************************************************************************
 *                                            OBJ & PARAM DEFINITION
 ***********************************************************************************************************************************/

/* *** Device.IP.ActivePort.{i}. *** */
DMLEAF tIPActivePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"LocalIPAddress", &DMREAD, DMT_STRING,  get_IP_ActivePort_LocalIPAddress, NULL, BBFDM_BOTH},
{"LocalPort", &DMREAD, DMT_UNINT, get_IP_ActivePort_LocalPort, NULL, BBFDM_BOTH},
{"RemoteIPAddress", &DMREAD, DMT_STRING,  get_IP_ActivePort_RemoteIPAddress, NULL, BBFDM_BOTH},
{"RemotePort", &DMREAD, DMT_UNINT,  get_IP_ActivePort_RemotePort, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING,  get_IP_ActivePort_Status, NULL, BBFDM_BOTH},
{0}
};

