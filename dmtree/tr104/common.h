/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include <libbbf_api/dmcommon.h>

#define TR104_UCI_PACKAGE "asterisk"
#define DEFAULT_SIP_PORT_STR "5060"
#define DEFAULT_SIP_REGISTER_EXPIRY_STR "300"

struct codec_info {
	char uci_name[16]; // Codec name used in UCI, i.e. alaw
	char codec[16]; // Codec name, i.e. G.711ALaw
	unsigned int bit_rate;
	char packetization_period[160]; // e.g. "20", "5-10,20,30"
	unsigned int ptime_default;
};

struct call_log_entry {
	struct list_head list;

	char calling_num[256], called_num[256];
	char source[256], destination[256], used_line[256];
	char direction[16];
	char start_time[32];
	char duration[8];
	char termination_cause[32];
	char sessionId[20];
	char sipIpAddress[40];
	char farEndIPAddress[40];
	char sipResponseCode[20];
	char codec[40];
	char localBurstDensity[20];
	char remoteBurstDensity[20];
	char localBurstDuration[20];
	char remoteBurstDuration[20];
	char localGapDensity[20];
	char remoteGapDensity[20];
	char localGapDuration[20];
	char remoteGapDuration[20];
	char localJbRate[20];
	char remoteJbRate[20];
	char localJbMax[20];
	char remoteJbMax[20];
	char localJbNominal[20];
	char remoteJbNominal[20];
	char localJbAbsMax[20];
	char remoteJbAbsMax[20];
	char jbAvg[20];
	char uLossRate[20];
	char discarded[20];
	char lost[20];
	char rxpkts[20];
	char txpkts[20];
	char jitter[20];
	char maxJitter[20];
	char averageRoundTripDelay[20];
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
extern char *KeyingMethods[];

int init_supported_codecs(void);
int init_call_log(void);
const char *get_codec_uci_name(const char *codec);
const char *get_codec_name(const char *codec_profile);
int get_Alias_value_by_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value, char *service_name, char* service_inst);
int set_Alias_value_by_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action, char *service_name, char* service_inst);
int get_Alias_value_by_inst(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value, char *alias_inst);
int set_Alias_value_by_inst(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action, char *alias_inst);
