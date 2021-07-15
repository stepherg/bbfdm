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

char *RFPowerControl[] = {"Normal", "Reduced"};
char *ProxyServerTransport[] = {"UDP", "TCP", "TLS", "SCTP"};
char *RegistrarServerTransport[] = {"UDP", "TCP", "TLS", "SCTP"};
char *DTMFMethod[] = {"InBand", "RFC4733", "SIPInfo"};
char *JitterBufferType[] = {"Static", "Dynamic"};
char *KeyingMethods[] = {"Null", "Static", "SDP", "IKE"};

struct codec_info supported_codecs[MAX_SUPPORTED_CODECS];
int codecs_num;

LIST_HEAD(call_log_list);
static int call_log_list_size = 0;
int call_log_count = 0;

int init_supported_codecs()
{
	json_object *res = NULL;

	dmubus_call("voice.asterisk", "codecs", UBUS_ARGS{}, 0, &res);
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
	if ((token = strstr(src_or_dst, TEL_LINE_PREFIX))) {
		inst = atoi(token + strlen(TEL_LINE_PREFIX)) + 1;
		snprintf(src_or_dst, buf_size, "Device.Services.VoiceService.1.CallControl.Line.%d", inst);
	} else if ((token = strstr(src_or_dst, SIP_ACCOUNT_PREFIX))) {
		inst = atoi(token + strlen(SIP_ACCOUNT_PREFIX)) + 1;
		snprintf(src_or_dst, buf_size, "Device.Services.VoiceService.1.SIP.Client.%d", inst);
	}
}

#define CALL_LOG_FILE "/var/log/asterisk/cdr-csv/Master.csv"
#define SEPARATOR "\",\""
#define SEPARATOR_SIZE strlen(SEPARATOR)
int init_call_log()
{
#define CHECK_RESULT(cond) if (!(cond)) { \
		BBF_DEBUG("Invalid cdr [%s]\ncalling_number = [%s], called_number = [%s], " \
		"start_time = [%s], end_time = %s\n", line, \
		cdr.calling_num, cdr.called_num, cdr.start_time, end_time); \
		continue; \
}
	static struct stat prev_stat = { 0 };
	struct stat cur_stat;
	int res = 0, i = 0;
	struct call_log_entry *entry;
	struct list_head *pos = NULL;
	FILE *fp = NULL;
	char line[320];

	// Check if there are any new call logs since the last time
	if (stat(CALL_LOG_FILE, &cur_stat) == 0) {
		if (memcmp(&cur_stat, &prev_stat, sizeof(cur_stat)) == 0) {
			return 0;
		} else {
			prev_stat = cur_stat;
		}
	}

	fp = fopen(CALL_LOG_FILE, "r");
	if (!fp) {
		BBF_DEBUG("Call log file %s doesn't exist\n", CALL_LOG_FILE);
		res = -1;
		goto __ret;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		struct call_log_entry cdr = { {NULL, NULL}, };
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
		token = strstr(line, SEPARATOR);
		CHECK_RESULT(token);
		token += SEPARATOR_SIZE;
		end = strstr(token, SEPARATOR);
		CHECK_RESULT(end);
		strncpy(cdr.calling_num, token, end - token);
		// called number
		token = end + SEPARATOR_SIZE;
		end = strstr(token, SEPARATOR);
		CHECK_RESULT(end);
		strncpy(cdr.called_num, token, end - token);
		// source
		token = end + SEPARATOR_SIZE; // sip0 in the last example
		token = strstr(token, SEPARATOR);
		CHECK_RESULT(token);
		token += SEPARATOR_SIZE; // ""8001"" <8001> in the last example
		token = strstr(token, SEPARATOR);
		CHECK_RESULT(token);
		token += SEPARATOR_SIZE; // TELCHAN/5/1 in the last example
		end = strstr(token, SEPARATOR);
		CHECK_RESULT(end);
		strncpy(cdr.source, token, end - token);
		// destination
		token = end + SEPARATOR_SIZE; // SIP/sip0-00000001 in the last example
		end = strstr(token, SEPARATOR);
		CHECK_RESULT(end);
		strncpy(cdr.destination, token, end - token);
		// start time and end time
		token = end + SEPARATOR_SIZE; // Dial in the last example
		token = strstr(token, SEPARATOR);
		CHECK_RESULT(token);
		token += SEPARATOR_SIZE; // SIP/7001@sip0,,gT in the last example
		token = strstr(token, SEPARATOR);
		CHECK_RESULT(token);
		token += SEPARATOR_SIZE; // The first date
		end = strstr(token, "\",,\"");
		if (end) {
			// Not answered, e.g. "2020-08-27 11:02:40",,"2020-08-27 11:02:40",21,11,
			strncpy(cdr.start_time, token, end - token);
			token = end + 4;
		} else {
			// Answered, e.g. "2020-08-25 16:11:41","2020-08-25 16:11:50","2020-08-25 16:12:02",21,11,
			end = strstr(token, SEPARATOR);
			CHECK_RESULT(end);
			strncpy(cdr.start_time, token, end - token);
			token = strstr(end + SEPARATOR_SIZE, SEPARATOR); // Skip the middle date and come to the last date
			CHECK_RESULT(token);
			token += SEPARATOR_SIZE;
		}
		end = strstr(token, "\",");
		CHECK_RESULT(end);
		strncpy(end_time, token, end - token);
		// termination cause
		token = strstr(end + 2, ",\""); // ANSWERED in the last example
		CHECK_RESULT(token);
		token += 2;
		end = strstr(token, SEPARATOR);
		CHECK_RESULT(end);
		strncpy(cdr.termination_cause, token, end - token);

		// session id
		token = strstr(token, ",");
		CHECK_RESULT(token);
		token += 1;
		end = strstr(token, ",");
		CHECK_RESULT(end);
		strncpy(cdr.sessionId, token, end - token);

		// SIP IP Address
		token = strstr(token, ",\"");
		CHECK_RESULT(token);
		token += 2;
		end = strstr(token, "\",");
		CHECK_RESULT(end);
		strncpy(cdr.sipIpAddress, token, end - token);

		// Far End IP Address
		token = strstr(token, ",\"");
		CHECK_RESULT(token);
		token += 2;
		end = strstr(token, "\",");
		CHECK_RESULT(end);
		strncpy(cdr.farEndIPAddress, token, end - token);

		// Sip Response Code
		token = strstr(token, ",");
		CHECK_RESULT(token);
		token += 1;
		end = strstr(token, ",");
		CHECK_RESULT(end);
		strncpy(cdr.sipResponseCode, token, end - token);

		// Codec
		token = strstr(token, ",\"");
		CHECK_RESULT(token);
		token += 2;
		end = strstr(token, "\",");
		CHECK_RESULT(end);
		strncpy(cdr.codec, token, end - token);

		// RTP statistic values
		token = strstr(token, ",");
		CHECK_RESULT(token);
		token += 1;
		end = strstr(token, ",");
		CHECK_RESULT(end);
		strncpy(cdr.localBurstDensity, token, end - token);
		// for incoming unanswered call cdr does not contain RTP stats
		if (strcasecmp(cdr.localBurstDensity, "\"DOCUMENTATION\"") == 0) {
			cdr.localBurstDensity[0] = '\0';
		} else {
			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteBurstDensity, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localBurstDuration, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteBurstDuration, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localGapDensity, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteGapDensity, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localGapDuration, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteGapDuration, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localJbRate, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteJbRate, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localJbMax, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteJbMax, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localJbNominal, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteJbNominal, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.localJbAbsMax, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.remoteJbAbsMax, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.jbAvg, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.uLossRate, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.discarded, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.lost, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.rxpkts, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.txpkts, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.jitter, token, end - token);

			token = strstr(token, ",");
			CHECK_RESULT(token);
			token += 1;
			end = strstr(token, ",");
			CHECK_RESULT(end);
			strncpy(cdr.maxJitter, token, end - token);
		}
		// Skip invalid call logs
		if (cdr.calling_num[0] == '\0' || cdr.called_num[0] == '\0' ||
			cdr.start_time[0] == '\0' || end_time[0] == '\0') {
			BBF_DEBUG("Invalid CDR: [%s]\ncalling_number = [%s], called_number = [%s], "
				"start_time = [%s], end_time = [%s]\n", line,
				cdr.calling_num, cdr.called_num, cdr.start_time, end_time);
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
		char *tel_line = NULL;
		if ((tel_line = strcasestr(cdr.source, "TELCHAN")) != NULL) {
			DM_STRNCPY(cdr.direction, "Outgoing", sizeof(cdr.direction));
		} else if ((tel_line = strcasestr(cdr.destination, "TELCHAN")) != NULL) {
			DM_STRNCPY(cdr.direction, "Incoming", sizeof(cdr.direction));
		} else {
			BBF_DEBUG("Invalid CDR: [%s]\ndirection = [%s]\n", line, cdr.direction);
			continue;
		}
		DM_STRNCPY(cdr.used_line, tel_line, sizeof(cdr.used_line));

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
		convert_src_dst(cdr.source, sizeof(cdr.source));
		convert_src_dst(cdr.destination, sizeof(cdr.destination));
		convert_src_dst(cdr.used_line, sizeof(cdr.used_line));

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
			// NOTE: dmmalloc() caused uspd crash when reusing the existing list entries!!!
			entry = malloc(sizeof(struct call_log_entry));
			if (!entry)
				return -1;

			list_add_tail(&entry->list, &call_log_list);
			call_log_list_size++;
		}

		// Fill out the entry
		struct list_head tmp = entry->list;
		memcpy(entry, &cdr, sizeof(*entry));
		entry->list = tmp;

		// Increase the call log count
		i++;
	}

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
