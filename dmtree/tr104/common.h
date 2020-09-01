/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include <stdio.h>
#include <libbbf_api/dmcommon.h>

#define ENABLE_TR104_DEBUG 0

#define TR104_UCI_PACKAGE "asterisk"
#define DEFAULT_SIP_PORT_STR "5060"
#define DEFAULT_SIP_REGISTER_EXPIRY_STR "300"

#if ENABLE_TR104_DEBUG
#define TR104_DEBUG(fmt, ...) do { \
	FILE *fp = fopen("/tmp/bbf_tr104.log", "a"); \
	if (fp) { \
		fprintf(fp, "%s@%s:%d: " fmt, __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
		fclose(fp); \
	} \
} while(0)
#else
#define TR104_DEBUG(fmt, ...)
#endif

struct codec_info {
	char uci_name[16]; // Codec name used in UCI, i.e. alaw
	char codec[16]; // Codec name, i.e. G.711ALaw
	unsigned int bit_rate;
	char packetization_period[160]; // e.g. "20", "5-10,20,30"
	unsigned int ptime_default;
};

struct call_log_entry {
	struct list_head list;

	char calling_num[20], called_num[20];
	char source[20], destination[20];
	char used_line[16];
	char direction[16];
	char start_time[32];
	char duration[8];
	char termination_cause[32];
};

#define MAX_SUPPORTED_CODECS 8
extern struct codec_info supported_codecs[MAX_SUPPORTED_CODECS];
extern int codecs_num;

extern struct list_head call_log_list;
extern int call_log_count;

extern char *RFPowerControl[];
extern char *ProxyServerTransport[];
extern char *RegistrarServerTransport[];
extern char *DTMFMethod[];
extern char *JitterBufferType[];

int init_supported_codecs();
int init_call_log();
