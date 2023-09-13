/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "common.h"

char *RFPowerControl[] = {"Normal", "Reduced", NULL};
char *ProxyServerTransport[] = {"UDP", "TCP", "TLS", "SCTP", NULL};
char *RegistrarServerTransport[] = {"UDP", "TCP", "TLS", "SCTP", NULL};
char *DTMFMethod[] = {"InBand", "RFC4733", "SIPInfo", NULL};
char *JitterBufferType[] = {"Static", "Dynamic", NULL};
char *KeyingMethods[] = {"Null", "Static", "SDP", "IKE", NULL};
char *FacilityAction[] = {"AA_REGISTER", "AA_ERASE", "AA_INTERROGATE", "CA_ACTIVATE", "CCBS_ACTIVATE", "CCBS_DEACTIVATE", "CCBS_INTERROGATE", "CCNR_ACTIVATE", "CCNR_DEACTIVATE", "CCNR_INTERROGATE", "CFB_REGISTER", "CFB_ACTIVATE", "CFB_DEACTIVATE", "CFB_ERASE", "CFB_INTERROGATE", "CFNR_REGISTER", "CFNR_ACTIVATE", "CFNR_DEACTIVATE", "CFNR_ERASE", "CFNR_INTERROGATE", "CFNR_TIMER", "CFT_ACTIVATE", "CFT_DEACTIVATE", "CFT_INTERROGATE", "CFU_REGISTER", "CFU_ACTIVATE", "CFU_DEACTIVATE", "CFU_ERASE", "CFU_INTERROGATE", "CLIR_ACTIVATE", "CLIR_DEACTIVATE", "CLIR_INTERROGATE", "CP_INVOKE", "CW_ACTIVATE", "CW_DEACTIVATE", "CW_INVOKE", "DND_ACTIVATE", "DND_DEACTIVATE", "DND_INTERROGATE", "EXT_INVOKE", "LINE_INVOKE", "MAILBOX_INVOKE", "OCB_ACTIVATE", "OCB_DEACTIVATE", "OCB_INTERROGATE", "PSO_ACTIVATE", "PW_SET", "SCF_ACTIVATE", "SCF_DEACTIVATE", "SCF_INTERROGATE", "SCREJ_ACTIVATE", "SCREJ_DEACTIVATE", "SCREJ_INTERROGATE", "SR_ACTIVATE", "SR_DEACTIVATE", "SR_INTERROGATE", NULL};
struct codec_info supported_codecs[MAX_SUPPORTED_CODECS];
int codecs_num;
extern struct list_head global_memhead;
LIST_HEAD(call_log_list);
static struct stat prev_stat = { 0 };
static int call_log_list_size = 0;
int call_log_count = 0;

int init_supported_codecs(void)
{
	json_object *res = NULL;

	dmubus_call("endpt", "codecs", UBUS_ARGS{0}, 0, &res);
	if (!res)
		return -1;

	int num = json_object_object_length(res);
	if (num <= 0)
		return -1;

	json_object_object_foreach(res, key, value) {
		if (value) {
			const char *codec = NULL;
			int min = 0, max = 0, increment = 0, ptime_default = 0;
			int size = sizeof(supported_codecs[codecs_num].packetization_period);

			DM_STRNCPY(supported_codecs[codecs_num].uci_name, key, sizeof(supported_codecs[codecs_num].uci_name) - 1);
			json_object_object_foreach(value, sub_key, sub_value) {
				if (sub_value && !strcasecmp(sub_key, "name") && (codec = json_object_get_string(sub_value)) != NULL) {
					DM_STRNCPY(supported_codecs[codecs_num].codec, codec, sizeof(supported_codecs[codecs_num].codec));
				} else if (sub_value && !strcasecmp(sub_key, "bitrate")) {
					supported_codecs[codecs_num].bit_rate = json_object_get_int(sub_value);
				} else if (sub_value && !strcasecmp(sub_key, "ptime_min")) {
					min = json_object_get_int(sub_value);
				} else if (sub_value && !strcasecmp(sub_key, "ptime_max")) {
					max = json_object_get_int(sub_value);
				} else if (sub_value && !strcasecmp(sub_key, "ptime_increment")) {
					increment = json_object_get_int(sub_value);
				} else if (sub_value && !strcasecmp(sub_key, "ptime_default")) {
					ptime_default = json_object_get_int(sub_value);
				}
			}

			// Construct packetization period
			if (min > 0 && max > min) {
				int duration = 0, total_len = 0;

				if (increment <= 0)
					increment = 10;
				for (total_len = 0, duration = min; duration <= max; duration += increment) {
					supported_codecs[codecs_num].ptime_default = (unsigned int)ptime_default;
					int len = snprintf(supported_codecs[codecs_num].packetization_period + total_len, size,
							"%s%d", (duration == min) ? "" : ",", duration);
					if (len > 0 && len < size) {
						total_len += len;
						size -= len;
					} else {
						BBF_DEBUG("supported_codecs[codecs_num].packetization_period = %s, "
								"the size is too small\n", supported_codecs[codecs_num].packetization_period);
						break;
					}
				}
			}

			++codecs_num;
			if (codecs_num >= num || codecs_num >= MAX_SUPPORTED_CODECS)
				break;
		}
	}

	return 0;
}

// Convert the format of source/destination/used_line in a call log to which is defined in TR-104
#define TEL_LINE_PREFIX "TELCHAN/"
#define SIP_ACCOUNT_PREFIX "SIP/sip"
static void convert_src_dst(char *src_or_dst, size_t buf_size)
{
	char *token;
	int inst;

	// Examples, "TELCHAN/5/2", "SIP/sip0-00000000",
	if ((token = DM_LSTRSTR(src_or_dst, TEL_LINE_PREFIX))) {
		inst = DM_STRTOL(token + strlen(TEL_LINE_PREFIX)) + 1;
		snprintf(src_or_dst, buf_size, "Device.Services.VoiceService.1.CallControl.Extension.%d", inst);
	} else if ((token = DM_LSTRSTR(src_or_dst, SIP_ACCOUNT_PREFIX))) {
		inst = DM_STRTOL(token + strlen(SIP_ACCOUNT_PREFIX)) + 1;
		snprintf(src_or_dst, buf_size, "Device.Services.VoiceService.1.SIP.Client.%d", inst);
	}
}
//  TODO Convert used line from "SIP/sip0-00000000" to sip{i} then to correspond line{i}
static void convert_sip_line(char *sip_line, size_t buf_size)
{
	char *token;
	// Examples, "SIP/sip0-00000000",
	if ((token = DM_LSTRSTR(sip_line, SIP_ACCOUNT_PREFIX))) {
		int inst = DM_STRTOL(token + strlen(SIP_ACCOUNT_PREFIX)) + 1;
		//snprintf(sip_line, buf_size, "sip%d", inst); // sip{i}
		// TODO Convert sip{i} to correspond line{i}, hard mapping at the moment (sip1->line1)
		snprintf(sip_line, buf_size, "Device.Services.VoiceService.1.CallControl.Line.%d", inst);

    }
}
#define EXTENSION_PREFIX "TELCHAN"
// convert_used_extensions
static void convert_used_extensions(char *used_extensions, size_t buf_size)
{
	char *token;
	int inst;
	char buf[512] = {0};

	// Examples, if "TELCHAN/1" else if "TELCHAN\/3&&TELCHAN\/2,,tF(hangup,h,2)" else "PJSIP/57007@sip2,,gT", 
	if ((token = DM_LSTRSTR(used_extensions, TEL_LINE_PREFIX))) {
		inst = DM_STRTOL(token + strlen(TEL_LINE_PREFIX)) + 1;
		snprintf(used_extensions, buf_size, "Device.Services.VoiceService.1.CallControl.Extension.%d", inst);
	} else {
		unsigned pos = 0;
		if ((token = DM_LSTRSTR(used_extensions, EXTENSION_PREFIX))) {
			do {
				token += strlen(EXTENSION_PREFIX);
				inst = DM_STRTOL(token+2) + 1;
				pos += snprintf(&buf[pos], sizeof(buf) - pos, "Device.Services.VoiceService.1.CallControl.Extension.%d,", inst);
			}while ((token = DM_LSTRSTR(token, EXTENSION_PREFIX)));
		}
		if (pos) {
			buf[pos - 1] = 0;
		}
		token = (buf[0] != '\0') ? dmstrdup(buf) : "";
		snprintf(used_extensions, buf_size, "%s", token);
	}

}

// return true is having successful responses 2xx
bool sip_response_checker(char *response_code) {
	int code;
	code = atoi(response_code);
	if (code>=200 && code<=299) {
		return true;
	} 
	return false;
}

#define CALL_LOG_FILE "/var/log/asterisk/cdr-csv/Master.csv"
#define SEPARATOR "\",\""
#define SEPARATOR_SIZE strlen(SEPARATOR)
int init_call_log(void)
{
#define CHECK_RESULT(cond) if (!(cond)) { \
		BBF_DEBUG("Invalid cdr [%s]\ncalling_number = [%s], called_number = [%s], " \
		"start_time = [%s], end_time = %s\n", line, \
		cdr.calling_num, cdr.called_num, cdr.start_time, end_time); \
		continue; \
}
	struct stat cur_stat;
	int res = 0, i = 0;
	struct call_log_entry *entry;
	struct list_head *pos = NULL;
	FILE *fp = NULL;
	char line[1024];

	// Check if there are any new call logs since the last time
	if (stat(CALL_LOG_FILE, &cur_stat) == 0) {
		if (memcmp(&cur_stat, &prev_stat, sizeof(cur_stat)) == 0) {
			return 0;
		} else {
			prev_stat = cur_stat;
		}
	}

	// Master.csv
	fp = fopen(CALL_LOG_FILE, "r");
	if (!fp) {
		BBF_DEBUG("Call log file %s doesn't exist\n", CALL_LOG_FILE);
		res = -1;
		goto __ret;
	}

	struct call_log_entry buf_cdr = { {NULL, NULL}, };
	DM_STRNCPY(buf_cdr.sessionId, "First", sizeof(buf_cdr.sessionId));
	bool line_record = false;
	do {
		if(fgets(line, sizeof(line), fp) != NULL) {
			line_record = true;
		} else if (!line_record) {
			// empty file, jump out without write
			continue;
		} else {
			line_record = false; // reaching the end, no new record from file.
			// last buf need to be written.
		}
		struct call_log_entry cdr = { {NULL, NULL}, };
		if ( line_record ){
			char end_time[sizeof(cdr.start_time)] = "";
			char *token, *end;
			/*
			* Parse the line for one call record. Examples of call log is below
			*
			* Tel 1 --> Tel 2, busy
			* "","8001","8002","sip0","""8001"" <8001>","TELCHAN/5/22","SIP/sip0-00000013","Dial","SIP/8002@sip0,,gT", \
			* "2020-08-27 11:02:40",,"2020-08-27 11:02:40",0,0,"BUSY","DOCUMENTATION","1598518960.99",""
			*
			* Tel 1 --> Tel 2
			* "","8001","8002","sip0","""8001"" <8001>","TELCHAN/5/19","SIP/sip0-00000011","Dial","SIP/8002@sip0,,gT", \
			* "2020-08-27 11:02:16","2020-08-27 11:02:20","2020-08-27 11:02:25",8,5,"ANSWERED","DOCUMENTATION", \
			* "1598518936.86",""
			*
			* External --> Tel 1
			* "","7001","8001","call_line",""""" <7001>","SIP/sip0-00000015","TELCHAN/5/25","Dial", \
			* "TELCHAN\/5,,tF(hangup,h,2)","2020-08-27 11:09:40","2020-08-27 11:09:45","2020-08-27 11:20:40", \
			* 660,654,"ANSWERED","DOCUMENTATION","1598519380.114",""
			*
			* Tel 1 --> External
			* "","8001","7001","sip0","""8001"" <8001>","TELCHAN/5/1","SIP/sip0-00000001","Dial","SIP/7001@sip0,,gT", \
			* "2020-08-25 16:11:41","2020-08-25 16:11:50","2020-08-25 16:12:02",21,11,"ANSWERED","DOCUMENTATION", \
			* "1598364701.4",""
			*/
			// calling number
			token = DM_LSTRSTR(line, SEPARATOR);
			CHECK_RESULT(token);
			token += SEPARATOR_SIZE;
			end = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.calling_num, token, end - token + 1);
			// called number
			token = end + SEPARATOR_SIZE;
			end = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.called_num, token, end - token + 1);
			// source
			token = end + SEPARATOR_SIZE; // sip0 in the last example
			token = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(token);
			token += SEPARATOR_SIZE; // ""8001"" <8001> in the last example
			token = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(token);
			token += SEPARATOR_SIZE; // TELCHAN/5/1 in the last example
			end = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.source, token, end - token + 1);
			// destination
			token = end + SEPARATOR_SIZE; // SIP/sip0-00000001 in the last example
			end = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.destination, token, end - token + 1);
			// start time and end time
			token = end + SEPARATOR_SIZE; // Dial in the last example
			token = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(token);
			token += SEPARATOR_SIZE; // SIP/7001@sip0,,gT in the last example
			end = DM_LSTRSTR(token, SEPARATOR);
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.used_extensions, token, end - token + 1);
			token = end + SEPARATOR_SIZE; // The first date
			end = DM_LSTRSTR(token, "\",,\"");
			if (end) {
				// Not answered, e.g. "2020-08-27 11:02:40",,"2020-08-27 11:02:40",21,11,
				DM_STRNCPY(cdr.start_time, token, end - token + 1);
				token = end + 4;
			} else {
				// Answered, e.g. "2020-08-25 16:11:41","2020-08-25 16:11:50","2020-08-25 16:12:02",21,11,
				end = DM_LSTRSTR(token, SEPARATOR);
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.start_time, token, end - token + 1);
				token = DM_LSTRSTR(end + SEPARATOR_SIZE, SEPARATOR); // Skip the middle date and come to the last date
				CHECK_RESULT(token);
				token += SEPARATOR_SIZE;
			}
			end = DM_LSTRSTR(token, "\",");
			CHECK_RESULT(end);
			DM_STRNCPY(end_time, token, end - token + 1);
			// termination cause
			token = DM_LSTRSTR(end + 2, ",\""); // ANSWERED in the last example
			CHECK_RESULT(token);
			token += 2;
			end = DM_LSTRSTR(token, "\",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.termination_cause, token, end - token + 1);

			// session id
			token = DM_LSTRSTR(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = DM_LSTRSTR(token, ",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.sessionId, token, end - token + 1);

			// SIP Session Id
			token = DM_LSTRSTR(token, ",\"");
			CHECK_RESULT(token);
			token += 2;
			end = DM_LSTRSTR(token, "\",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.SIPSessionId, token, end - token + 1);

			// SIP IP Address
			token = DM_LSTRSTR(token, ",\"");
			CHECK_RESULT(token);
			token += 2;
			end = DM_LSTRSTR(token, "\",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.sipIpAddress, token, end - token + 1);

			// Far End IP Address
			token = DM_LSTRSTR(token, ",\"");
			CHECK_RESULT(token);
			token += 2;
			end = DM_LSTRSTR(token, "\",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.farEndIPAddress, token, end - token + 1);

			// Sip Response Code
			token = DM_LSTRSTR(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = DM_LSTRSTR(token, ",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.sipResponseCode, token, end - token + 1);

			// Codec
			token = DM_LSTRSTR(token, ",\"");
			CHECK_RESULT(token);
			token += 2;
			end = DM_LSTRSTR(token, "\",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.codec, token, end - token + 1);

			// RTP statistic values
			token = DM_LSTRSTR(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = DM_LSTRSTR(token, ",");
			CHECK_RESULT(end);
			DM_STRNCPY(cdr.localBurstDensity, token, end - token + 1);
			// for incoming unanswered call cdr does not contain RTP stats
			if (strcasecmp(cdr.localBurstDensity, "\"DOCUMENTATION\"") == 0) {
				cdr.localBurstDensity[0] = '\0';
			} else {
				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteBurstDensity, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localBurstDuration, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteBurstDuration, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localGapDensity, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteGapDensity, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localGapDuration, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteGapDuration, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localJbRate, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteJbRate, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localJbMax, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteJbMax, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localJbNominal, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteJbNominal, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.localJbAbsMax, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.remoteJbAbsMax, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.jbAvg, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.uLossRate, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.discarded, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.lost, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.rxpkts, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.txpkts, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.jitter, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.maxJitter, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.averageRoundTripDelay, token, end - token + 1);

				token = DM_LSTRSTR(token, ",");
				CHECK_RESULT(token);
				token += 1;
				end = DM_LSTRSTR(token, ",");
				CHECK_RESULT(end);
				DM_STRNCPY(cdr.averageFarEndInterarrivalJitter, token, end - token + 1);
			}
			// Skip invalid call logs
			if (cdr.called_num[0] == '\0' || cdr.start_time[0] == '\0' || end_time[0] == '\0') {
				BBF_DEBUG("Invalid CDR: [%s]\ncalled_number = [%s], start_time = [%s], end_time = [%s]\n",
					line, cdr.called_num, cdr.start_time, end_time);
				continue;
			} else if (cdr.destination[0] == '\0' && strcasecmp(cdr.called_num, "h") == 0) {
				BBF_DEBUG("Invalid CDR: [%s]\ncalled_number = [%s], destination = [%s]\n", line,
					cdr.called_num, cdr.destination);
				continue;
			}

			// Calculate the call duration
			struct tm tm_start, tm_end;
			char *r1 = strptime(cdr.start_time, "%Y-%m-%d %H:%M:%S", &tm_start);
			char *r2 = strptime(end_time, "%Y-%m-%d %H:%M:%S", &tm_end);

			if (r1 && *r1 == '\0' && r2 && *r2 == '\0') {
				time_t time_start, time_end;
				time_start = timegm(&tm_start);
				time_end = timegm(&tm_end);
				snprintf(cdr.duration, sizeof(cdr.duration), "%u", (unsigned int)(time_end - time_start));
				// Convert start time to ISO 8601 date-time format as per TR-181 data model
				strftime(cdr.start_time, sizeof(cdr.start_time), "%Y-%m-%dT%H:%M:%SZ", &tm_start);
			} else {
				BBF_DEBUG("Invalid CDR: [%s]\nWrong start time and/or end time, [%s], [%s]\n",
					line, cdr.start_time, end_time);
				continue;
			}
			// Determine the call direction and used line
			char *used_line = NULL;
			if ((used_line = strcasestr(cdr.source, "TELCHAN")) != NULL) {
				DM_STRNCPY(cdr.direction, "Outgoing", sizeof(cdr.direction));
				used_line = strcasestr(cdr.destination, "SIP/sip");
				DM_STRNCPY(cdr.used_extensions, cdr.source, sizeof(cdr.used_extensions));
			} else if ((used_line = strcasestr(cdr.destination, "TELCHAN")) != NULL) {
				DM_STRNCPY(cdr.direction, "Incoming", sizeof(cdr.direction));
				used_line = strcasestr(cdr.source, "SIP/sip");
			} else if ( ((used_line = strcasestr(cdr.source, "SIP/sip")) != NULL) && ((used_line = strcasestr(cdr.destination, "SIP/sip")) != NULL) ) {
				DM_STRNCPY(cdr.direction, "", sizeof(cdr.direction)); //TODO fix this section for 3-way, call forward
			} else {
				BBF_DEBUG("Invalid CDR: [%s]\ndirection = [%s]\n", line, cdr.direction);
				continue;
			}
			if (used_line == NULL){
				// for internal call with extension number 0000/1111/2222/333
				DM_STRNCPY(cdr.used_line, "", sizeof(cdr.used_line));
			} else {
				DM_STRNCPY(cdr.used_line, used_line, sizeof(cdr.used_line)); // "SIP/sip0-00000000"
			}
			/*
			* Convert the termination cause to a value specified in TR-104.
			*
			* Note that some of the current causes provided by call log (CDR) can not be well mapped to those
			* specified in TR-104.
			*
			* TODO: Asterisk needs to be changed in order to provide more TR-104 compliant call termination causes.
			*/
			if (strcasecmp(cdr.termination_cause, "NO ANSWER") == 0)
				DM_STRNCPY(cdr.termination_cause, "LocalTimeout", sizeof(cdr.termination_cause));
			else if (strcasecmp(cdr.termination_cause, "FAILED") == 0)
				DM_STRNCPY(cdr.termination_cause, "LocalInternalError", sizeof(cdr.termination_cause));
			else if (strcasecmp(cdr.termination_cause, "BUSY") == 0)
				DM_STRNCPY(cdr.termination_cause, "RemoteBusy", sizeof(cdr.termination_cause));
			else if (strcasecmp(cdr.termination_cause, "ANSWERED") == 0)
				DM_STRNCPY(cdr.termination_cause, "RemoteDisconnect", sizeof(cdr.termination_cause));
			else if (strcasecmp(cdr.termination_cause, "CONGESTION") == 0)
				DM_STRNCPY(cdr.termination_cause, "RemoteNetworkFailure", sizeof(cdr.termination_cause));
			else
				DM_STRNCPY(cdr.termination_cause, "LocalInternalError", sizeof(cdr.termination_cause));
			// Convert source and destination
			convert_src_dst(cdr.source, sizeof(cdr.source)); // CallControl.Extension.{i} or SIP.Client.{i}
			convert_src_dst(cdr.destination, sizeof(cdr.destination)); // CallControl.Extension.{i} or SIP.Client.{i}
			// Convert used line to line{i}
			// TODO correspond CallControl.Line.{i}
			convert_sip_line(cdr.used_line, sizeof(cdr.used_line));
			convert_used_extensions(cdr.used_extensions, sizeof(cdr.used_extensions));

			// check session id with the record in buf
			// skip for the first record, and put into buf
			if (strcmp(buf_cdr.sessionId, "First")==0) {
				buf_cdr = cdr; // first record to buf
				continue;
			}
			// if having the same session id and the same starting time and the same direction, then skip writing and modify the buf
			if ( (strcmp(cdr.sessionId, buf_cdr.sessionId)==0) &&
				 (strcmp(cdr.start_time, buf_cdr.start_time)==0) &&
				 (strcmp(cdr.direction, buf_cdr.direction)==0) ) {
				if ( (!sip_response_checker(buf_cdr.sipResponseCode)) && ( sip_response_checker(cdr.sipResponseCode) || strcmp(cdr.sipResponseCode, buf_cdr.sipResponseCode)>0) ) {
					buf_cdr = cdr; // drop the previous record as same session id and the current response code has a higher priority
				}
				continue; // continue for next record, and see if still having the same seesion id.
			} // if having a different session id, then writing the buf to entry, and move the current to buf.
		
		} // if only last buf left. write directly.
		// Find out an existing call log entry or create a new one
		if (i < call_log_list_size) {
			if (i > 0) {
				pos = pos->next;
				entry = list_entry(pos, struct call_log_entry, list);
			} else {
				entry = list_first_entry(&call_log_list, struct call_log_entry, list);
				pos = &entry->list;
			}
		} else {
			entry = dm_dynamic_malloc(&global_memhead, sizeof(struct call_log_entry));
			if (!entry)
				return -1;

			list_add_tail(&entry->list, &call_log_list);
			call_log_list_size++;
		}

		// Fill out the entry with the record in buf
		struct list_head tmp = entry->list;
		memcpy(entry, &buf_cdr, sizeof(*entry));
		entry->list = tmp;
		// Increase the call log count
		i++;
		// put current record to buf
		buf_cdr = cdr;
	} while (line_record);

	// The total number of call logs could be less than the list size in case that old call logs have been removed
	call_log_count = i;

__ret:
	if (res != 0)
		call_log_count = 0;
	if (fp)
		fclose(fp);
	return res;
#undef CHECK_RESULT
}

// Get the UCI section name of a codec, e.g. G.711ALaw --> alaw
const char *get_codec_uci_name(const char *codec)
{
	if (codec && *codec) {

		// Initialize supported codecs if it has not been done
		if (codecs_num <= 0)
			init_supported_codecs();

		for (int i = 0; i < codecs_num; i++) {
			if (!strcasecmp(supported_codecs[i].codec, codec))
				return supported_codecs[i].uci_name;
		}
	}

	return NULL;
}

// Get the codec name in TR-104 from UCI section name, e.g. alaw --> G.711ALaw
const char *get_codec_name(const char *codec_profile)
{
	if (codec_profile && *codec_profile) {

		// Initialize supported codecs if it has not been done
		if (codecs_num <= 0)
			init_supported_codecs();

		for (int i = 0; i < codecs_num; i++) {
			if (!strcasecmp(supported_codecs[i].uci_name, codec_profile))
				return supported_codecs[i].codec;
		}
	}

	return NULL;
}

/*Get the Alias parameter value by section*/
int get_Alias_value_by_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value, char *service_name, char* service_inst)
{
    struct uci_section *s = NULL;

    uci_path_foreach_option_eq(bbfdm, "dmmap", service_name, service_inst, instance, s) {
        dmuci_get_value_by_section_string(s, "alias", value);
        break;
    }
    if ((*value)[0] == '\0')
        dmasprintf(value, "cpe-%s", instance);
    return 0;
}

/*Set the Alias paramter value by section*/
int set_Alias_value_by_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action, char *service_name, char* service_inst)
{

    struct uci_section *s = NULL, *dmmap = NULL;

    switch (action) {
        case VALUECHECK:
            if (dm_validate_string(value, -1, 64, NULL, NULL))
                return FAULT_9007;
            break;
        case VALUESET:
            uci_path_foreach_option_eq(bbfdm, "dmmap", service_name, service_inst, instance, s) {
                dmuci_set_value_by_section_bbfdm(s, "alias", value);
                return 0;
            }
            dmuci_add_section_bbfdm("dmmap", service_name, &dmmap);
            dmuci_set_value_by_section(dmmap, service_inst, instance);
            dmuci_set_value_by_section(dmmap, "alias", value);
            break;
    }
    return 0;
}


/*Get Alias parameter value by section string*/
int get_Alias_value_by_inst(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value, char *alias_inst)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, alias_inst, value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

/*Set Alias parameter value by section string*/
int set_Alias_value_by_inst(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action, char *alias_inst)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 64, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, alias_inst, value);
		break;
	}
	return 0;
}
