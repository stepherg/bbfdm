/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dmcommon.h"

char *Encapsulation[] = {"LLC", "VCMUX", NULL};
char *LinkType[] = {"EoA", "IPoA", "PPPoA", "CIP", "Unconfigured", NULL};
char *BridgeStandard[] = {"802.1D-2004", "802.1Q-2005", "802.1Q-2011", NULL};
char *BridgeType[] = {"ProviderNetworkPort", "CustomerNetworkPort", "CustomerEdgePort", "CustomerVLANPort", "VLANUnawarePort", NULL};
char *VendorClassIDMode[] = {"Exact", "Prefix", "Suffix", "Substring", NULL};
char *DiagnosticsState[] = {"None", "Requested", "Canceled", "Complete", "Error", NULL};
char *SupportedProtocols[] = {"HTTP", "HTTPS", NULL};
char *InstanceMode[] = {"InstanceNumber", "InstanceAlias", NULL};
char *NATProtocol[] = {"TCP", "UDP", NULL};
char *Config[] = {"High", "Low", "Off", "Advanced", NULL};
char *Target[] = {"Drop", "Accept", "Reject", "Return", "TargetChain", NULL};
char *ServerConnectAlgorithm[] = {"DNS-SRV", "DNS", "ServerTable", "WebSocket", NULL};
char *KeepAlivePolicy[] = {"ICMP", "None", NULL};
char *DeliveryHeaderProtocol[] = {"IPv4", "IPv6", NULL};
char *KeyIdentifierGenerationPolicy[] = {"Disabled", "Provisioned", "CPE_Generated", NULL};
char *PreambleType[] = {"short", "long", "auto", NULL};
char *MFPConfig[] = {"Disabled", "Optional", "Required", NULL};
char *DuplexMode[] = {"Half", "Full", "Auto", NULL};
char *RequestedState[] = {"Idle", "Active", NULL};
char *BulkDataProtocols[] = {"Streaming", "File", "HTTP", NULL};
char *EncodingTypes[] = {"XML", "XDR", "CSV", "JSON", NULL};
char *CSVReportFormat[] = {"ParameterPerRow", "ParameterPerColumn", NULL};
char *RowTimestamp[] = {"Unix-Epoch", "ISO-8601", "None", NULL};
char *JSONReportFormat[] = {"ObjectHierarchy", "NameValuePair", NULL};
char *StaticType[] = {"Static", "Inapplicable", "PrefixDelegation", "Child", NULL};
char *ProtocolVersion[] = {"Any", "IPv4", "IPv6", NULL};
char *ServerSelectionProtocol[] = {"ICMP", "UDP Echo", NULL};
char *DHCPType[] = {"DHCPv4", "DHCPv6", NULL};
char *DropAlgorithm[] = {"RED", "DT", "WRED", "BLUE", NULL};
char *SchedulerAlgorithm[] = {"WFQ", "WRR", "SP", NULL};
char *ProfileEnable[] = {"Disabled", "Quiescent", "Enabled", NULL};
char *SupportedOperatingChannelBandwidth[] = {"20MHz", "40MHz", "80MHz", "160MHz", "80+80MHz", "Auto", NULL};
char *SupportedStandards[] = {"a", "b", "g", "n", "ac", "ax", NULL};
char *SupportedFrequencyBands[] = {"2.4GHz", "5GHz", NULL};
char *Provider_Bridge_Type[] = {"S-VLAN", "PE", NULL};
char *AdvPreferredRouterFlag[] = {"High", "Medium", "Low", NULL};
char *PowerState[] = {"On", "Power_Save", "Off", "Unsupported", NULL};
char *FW_Mode[] = {"AnyTime", "Immediately", "WhenIdle", "ConfirmationNeeded", NULL};
char *AKMsAllowed[] = {"psk", "dpp", "sae", "psk+sae", "dpp+sae", "dpp+psk+sae", "SuiteSelector", NULL};
char *CellularDataPreference[] = {"Excluded", "Should not use", "Should use", NULL};

char *PIN[] = {"^\\d{4}|\\d{8}$", NULL};
char *DestinationAddress[] = {"^\\d+/\\d+$", NULL};
char *RegulatoryDomain[] = {"^[A-Z][A-Z][ OI]$", NULL};
char *ConformingAction[] = {"^Null$", "^Drop$", "^[0-9]|[1-5][0-9]|6[0-3]$", "^:[0-7]$", "^([0-9]|[1-5][0-9]|6[0-3]):[0-7]$", NULL};
char *IPv4Address[] = {"^$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$", NULL};
char *IPv6Address[] = {"^$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$", NULL};
char *IPAddress[] = {"^$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$", NULL};
char *MACAddress[] = {"^$", "^([0-9A-Fa-f][0-9A-Fa-f]:){5}([0-9A-Fa-f][0-9A-Fa-f])$", NULL};
char *IPPrefix[] = {"^$", "^/(3[0-2]|[012]?[0-9])$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[012]?[0-9])$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/(12[0-8]|1[0-1][0-9]|[0-9]?[0-9])$", NULL};
char *IPv4Prefix[] = {"^$", "^/(3[0-2]|[012]?[0-9])$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[012]?[0-9])$", NULL};
char *IPv6Prefix[] = {"^$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/(12[0-8]|1[0-1][0-9]|[0-9]?[0-9])$", NULL};

struct option_tag_type TYPE_TAG_ARRAY[] = {
{1, OPTION_IP, 4},
{2, OPTION_INT, 4},
{3, OPTION_IP, 4},
{4, OPTION_IP, 4},
{5, OPTION_IP, 4},
{6, OPTION_IP, 4},
{7, OPTION_IP, 4},
{8, OPTION_IP, 4},
{9, OPTION_IP, 4},
{10, OPTION_IP, 4},
{11, OPTION_IP, 4},
{13, OPTION_INT, 2},
{16, OPTION_IP, 4},
{19, OPTION_INT, 1},
{20, OPTION_INT, 1},
{21, OPTION_IP, 4},
{22, OPTION_INT, 2},
{23, OPTION_INT, 1},
{24, OPTION_INT, 4},
{25, OPTION_INT, 2},
{26, OPTION_INT, 2},
{27, OPTION_INT, 1},
{28, OPTION_IP, 4},
{29, OPTION_INT, 1},
{30, OPTION_INT, 1},
{31, OPTION_INT, 1},
{32, OPTION_IP, 4},
{33, OPTION_IP, 4},
{34, OPTION_INT, 1},
{35, OPTION_INT, 4},
{36, OPTION_INT, 1},
{37, OPTION_INT, 1},
{38, OPTION_INT, 4},
{39, OPTION_INT, 1},
{41, OPTION_IP, 4},
{42, OPTION_IP, 4},
{43, OPTION_HEX, 1},
{44, OPTION_IP, 4},
{45, OPTION_IP, 4},
{46, OPTION_INT, 1},
{48, OPTION_IP, 4},
{49, OPTION_IP, 4},
{50, OPTION_IP, 4},
{51, OPTION_IP, 4},
{52, OPTION_INT, 1},
{53, OPTION_INT, 1},
{54, OPTION_INT, 4},
{57, OPTION_INT, 2},
{58, OPTION_INT, 4},
{59, OPTION_INT, 4},
{65, OPTION_IP, 4},
{68, OPTION_IP, 4},
{69, OPTION_IP, 4},
{70, OPTION_IP, 4},
{71, OPTION_IP, 4},
{72, OPTION_IP, 4},
{73, OPTION_IP, 4},
{74, OPTION_IP, 4},
{75, OPTION_IP, 4},
{76, OPTION_IP, 4},
{118, OPTION_IP, 4},
{125, OPTION_HEX, 1},
{145, OPTION_INT, 1},
{152, OPTION_INT, 4},
{153, OPTION_INT, 4},
{154, OPTION_INT, 4},
{155, OPTION_INT, 4},
{156, OPTION_INT, 1},
{157, OPTION_INT, 1},
{159, OPTION_INT, 4}
};

pid_t get_pid(const char *pname)
{
	DIR* dir;
	struct dirent* ent;
	char* endptr;
	char buf[512];

	if (!(dir = opendir("/proc"))) {
		return -1;
	}
	while((ent = readdir(dir)) != NULL) {
		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0') {
			continue;
		}
		snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
		FILE* fp = fopen(buf, "r");
		if (fp) {
			if (fgets(buf, sizeof(buf), fp) != NULL) {
				char* first = strtok(buf, " ");
				if (DM_STRSTR(first, pname)) {
					fclose(fp);
					closedir(dir);
					return (pid_t)lpid;
				}
			}
			fclose(fp);
		}
	}
	closedir(dir);
	return -1;
}

int check_file(char *path)
{
	glob_t globbuf;
	if(glob(path, 0, NULL, &globbuf) == 0) {
		globfree(&globbuf);
		return 1;
	}
	return 0;
}

char *cidr2netmask(int bits)
{
	uint32_t mask;
	struct in_addr ip_addr;
	uint8_t u_bits = (uint8_t)bits;

	mask = ((0xFFFFFFFFUL << (32 - u_bits)) & 0xFFFFFFFFUL);
	mask = htonl(mask);
	ip_addr.s_addr = mask;
	return inet_ntoa(ip_addr);
}

bool is_strword_in_optionvalue(char *optionvalue, char *str)
{
	char *s = optionvalue;
	while ((s = DM_STRSTR(s, str))) {
		int len = DM_STRLEN(str); //should be inside while, optimization reason
		if(s[len] == '\0' || s[len] == ' ')
			return true;
		s++;
	}
	return false;
}

void remove_new_line(char *buf)
{
	int len = DM_STRLEN(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = 0;
}

static void dmcmd_exec(char *argv[])
{
	int devnull = open("/dev/null", O_RDWR);

	if (devnull == -1)
		exit(127);

	dup2(devnull, 0);
	dup2(devnull, 1);
	dup2(devnull, 2);

	if (devnull > 2)
		close(devnull);

	execvp(argv[0], argv); /* Flawfinder: ignore */
	exit(127);
}

int dmcmd(char *cmd, int n, ...)
{
	char *argv[n + 2];
	va_list arg;
	int i, status;
	pid_t pid, wpid;

	argv[0] = cmd;
	va_start(arg, n);
	for (i = 0; i < n; i++) {
		argv[i + 1] = va_arg(arg, char *);
	}
	va_end(arg);
	argv[n + 1] = NULL;

	if ((pid = fork()) == -1)
		return -1;

	if (pid == 0)
		dmcmd_exec(argv);

	do {
		wpid = waitpid(pid, &status, 0);
		if (wpid == pid) {
			if (WIFEXITED(status))
				return WEXITSTATUS(status);
			if (WIFSIGNALED(status))
				return 128 + WTERMSIG(status);
		}
	} while (wpid == -1 && errno == EINTR);

	return -1;
}

int dmcmd_no_wait(char *cmd, int n, ...)
{
	char *argv[n + 2];
	va_list arg;
	int i;
	pid_t pid;

	argv[0] = cmd;
	va_start(arg, n);
	for (i = 0; i < n; i++) {
		argv[i + 1] = va_arg(arg, char *);
	}
	va_end(arg);
	argv[n + 1] = NULL;

	if ((pid = fork()) == -1)
		return -1;

	if (pid == 0)
		dmcmd_exec(argv);

	return 0;
}

void hex_to_ip(char *address, char *ret, size_t size)
{
	unsigned int ip[4] = {0};

	sscanf(address, "%2x%2x%2x%2x", &(ip[0]), &(ip[1]), &(ip[2]), &(ip[3]));
	if (htonl(13) == 13) {
		snprintf(ret, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	} else {
		snprintf(ret, size, "%u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);
	}
}

/*
 * dmmap_config sections list manipulation
 */
void add_dmmap_config_dup_list(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section)
{
	struct dmmap_dup *dmmap_config;

	dmmap_config = dmcalloc(1, sizeof(struct dmmap_dup));
	list_add_tail(&dmmap_config->list, dup_list);
	dmmap_config->config_section = config_section;
	dmmap_config->dmmap_section = dmmap_section;
}

static void dmmap_config_dup_delete(struct dmmap_dup *dmmap_config)
{
	list_del(&dmmap_config->list);
}

void free_dmmap_config_dup_list(struct list_head *dup_list)
{
	struct dmmap_dup *dmmap_config = NULL;
	while (dup_list->next != dup_list) {
		dmmap_config = list_entry(dup_list->next, struct dmmap_dup, list);
		dmmap_config_dup_delete(dmmap_config);
	}
}

/*
 * Function allows to synchronize config section with dmmap config
 */
struct uci_section *get_origin_section_from_config(char *package, char *section_type, char *orig_section_name)
{
	struct uci_section *s = NULL;

	uci_foreach_sections(package, section_type, s) {
		char sec_name[128] = {0};

		dmuci_replace_invalid_characters_from_section_name(orig_section_name, sec_name, sizeof(sec_name));

		if (strcmp(section_name(s), sec_name) == 0)
			return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap(char *dmmap_package, char *section_type, char *orig_section_name)
{
	struct uci_section *s;

	uci_path_foreach_sections(bbfdm, dmmap_package, section_type, s) {
		char *dmmap_sec_name = NULL;
		char sec_name[128] = {0};

		dmuci_get_value_by_section_string(s, "section_name", &dmmap_sec_name);
		dmuci_replace_invalid_characters_from_section_name(dmmap_sec_name, sec_name, sizeof(sec_name));

		if (DM_STRCMP(sec_name, orig_section_name) == 0)
			return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_config_opt(char *package, char *section_type, char *opt_name, char *opt_value)
{
	struct uci_section *s;

	uci_foreach_option_eq(package, section_type, opt_name, opt_value, s) {
		return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap_opt(char *dmmap_package, char *section_type, char *opt_name, char *opt_value)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt_name, opt_value, s) {
		return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap_eq(char *dmmap_package, char* section_type, char*sect_name, char *opt_name, char *opt_value)
{
	struct uci_section *s;
	char *v;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", sect_name, s) {
		dmuci_get_value_by_section_string(s, opt_name, &v);
		if (opt_value && DM_STRCMP(v, opt_value) == 0)
			return s;
	}
	return NULL;
}

struct uci_section *get_section_in_dmmap_with_options_eq(char *dmmap_package, char *section_type, char *opt1_name, char *opt1_value, char *opt2_name, char *opt2_value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt1_name, opt1_value, s) {
		char *value = NULL;

		dmuci_get_value_by_section_string(s, opt2_name, &value);
		if (opt2_value && value && DM_STRCMP(value, opt2_value) == 0)
			return s;
	}

	return NULL;
}

void synchronize_specific_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *v;

	uci_foreach_sections(package, section_type, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(s));
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_dmmap_config_dup_list(dup_list, s, dmmap_sect);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_eq(char *package, char *section_type, char *dmmap_package, char* option_name, char* option_value, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sec;
	char *v;

	uci_foreach_option_eq(package, section_type, option_name, option_value, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sec = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sec);
			dmuci_set_value_by_section_bbfdm(dmmap_sec, "section_name", section_name(s));
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_dmmap_config_dup_list(dup_list, s, dmmap_sec);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_cont(char *package, char *section_type, char *dmmap_package, char* option_name, char* option_value, struct list_head *dup_list)
{
	struct uci_section *uci_s, *stmp, *dmmap_sect;
	char *v;

	uci_foreach_option_cont(package, section_type, option_name, option_value, uci_s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(uci_s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(uci_s));
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_dmmap_config_dup_list(dup_list, uci_s, dmmap_sect);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, uci_s) {
		dmuci_get_value_by_section_string(uci_s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(uci_s, NULL, NULL);
	}
}

void add_sysfs_section_list(struct list_head *dup_list, struct uci_section *dmmap_section, char *file_name, char *file_path)
{
	struct sysfs_dmsection *dmmap_sysfs;

	dmmap_sysfs = dmcalloc(1, sizeof(struct sysfs_dmsection));
	list_add_tail(&dmmap_sysfs->list, dup_list);
	dmmap_sysfs->dmmap_section = dmmap_section;
	dmmap_sysfs->sysfs_folder_name = dmstrdup(file_name);
	dmmap_sysfs->sysfs_folder_path = dmstrdup(file_path);
}

int synchronize_system_folders_with_dmmap_opt(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, char* inst_opt, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_sect = NULL;
	char sysfs_rep_path[512];
	DIR *dir;
	struct dirent *ent;

	sysfs_foreach_file(sysfsrep, dir, ent) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		snprintf(sysfs_rep_path, sizeof(sysfs_rep_path), "%s/%s", sysfsrep, ent->d_name);
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, dmmap_section, opt_name, sysfs_rep_path)) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, dmmap_section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, opt_name, sysfs_rep_path);
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_sysfs_section_list(dup_list, dmmap_sect, ent->d_name, sysfs_rep_path);
	}
	if (dir)
		closedir(dir);

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_section, stmp, s) {
		char *opt_val = NULL;

		dmuci_get_value_by_section_string(s, opt_name, &opt_val);
		if (!folder_exists(opt_val))
			dmuci_delete_by_section(s, NULL, NULL);
	}
	return 0;
}

void get_dmmap_section_of_config_section(char* dmmap_package, char* section_type, char *section_name, struct uci_section **dmmap_section)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", section_name, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_dmmap_section_of_config_section_eq(char* dmmap_package, char* section_type, char *opt, char* value, struct uci_section **dmmap_section)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt, value, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_dmmap_section_of_config_section_cont(char* dmmap_package, char* section_type, char *opt, char* value, struct uci_section **dmmap_section)
{
	struct uci_section *s;

	uci_path_foreach_option_cont(bbfdm, dmmap_package, section_type, opt, value, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_config_section_of_dmmap_section(char* package, char* section_type, char *section_name, struct uci_section **config_section)
{
	struct uci_section *s;

	uci_foreach_sections(package, section_type, s) {
		if (strcmp(section_name(s), section_name) == 0) {
			*config_section = s;
			return;
		}
	}
	*config_section = NULL;
}

char *check_create_dmmap_package(const char *dmmap_package)
{
	char *path;
	int rc;

	rc = dmasprintf(&path, "/etc/bbfdm/dmmap/%s", dmmap_package);
	if (rc == -1)
		return NULL;

	if (!file_exists(path)) {
		/*
		 *File does not exist
		 **/
		FILE *fp = fopen(path, "w"); // new empty file
		if (fp)
			fclose(fp);
	}
	return path;
}

__attribute__ ((deprecated)) int is_section_unnamed(char *section_name)
{
	int i;

	if (section_name == NULL)
		return 0;

	if (strlen(section_name) != 9)
		return 0;

	if(strstr(section_name, "cfg") != section_name)
		return 0;

	for (i = 3; i < 9; i++) {
		if (!isxdigit(section_name[i]))
			return 0;
	}

	return 1;
}

static void add_dmmap_list_section(struct list_head *dup_list, char* section_name, char* instance)
{
	struct dmmap_sect *dmsect;

	dmsect = dmcalloc(1, sizeof(struct dmmap_sect));
	list_add_tail(&dmsect->list, dup_list);
	dmasprintf(&dmsect->section_name, "%s", section_name);
	dmasprintf(&dmsect->instance, "%s", instance);
}

__attribute__ ((deprecated)) void delete_sections_save_next_sections(char* dmmap_package, char *section_type, char *instancename, char *section_name, int instance, struct list_head *dup_list)
{
	struct uci_section *s, *stmp;
	char *v = NULL, *lsectname = NULL, *tmp = NULL;
	int inst;

	dmasprintf(&lsectname, "%s", section_name);

	uci_path_foreach_sections(bbfdm, dmmap_package, section_type, s) {
		dmuci_get_value_by_section_string(s, instancename, &v);
		inst = DM_STRTOL(v);
		if (inst > instance){
			dmuci_get_value_by_section_string(s, "section_name", &tmp);
			add_dmmap_list_section(dup_list, lsectname, v);
			dmfree(lsectname);
			lsectname = NULL;
			dmasprintf(&lsectname, "%s", tmp);
			dmfree(tmp);
			tmp = NULL;
		}
	}

	if(lsectname != NULL) dmfree(lsectname);

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, instancename, &v);
		inst = DM_STRTOL(v);
		if (inst >= instance)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

__attribute__ ((deprecated)) void update_dmmap_sections(struct list_head *dup_list, char *instancename, char* dmmap_package, char *section_type)
{
	struct uci_section *dm_sect = NULL;
	struct dmmap_sect *p = NULL;

	list_for_each_entry(p, dup_list, list) {
		dmuci_add_section_bbfdm(dmmap_package, section_type, &dm_sect);
		dmuci_set_value_by_section(dm_sect, "section_name", p->section_name);
		dmuci_set_value_by_section(dm_sect, instancename, p->instance);
	}
}

struct uci_section *is_dmmap_section_exist(char* package, char* section)
{
	struct uci_section *s;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		return s;
	}
	return NULL;
}

struct uci_section *is_dmmap_section_exist_eq(char* package, char* section, char* opt, char* value)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, package, section, opt, value, s) {
		return s;
	}
	return NULL;
}

unsigned char isdigit_str(char *str)
{
	if (!(*str)) return 0;
	while(isdigit(*str++));
	return ((*(str-1)) ? 0 : 1);
}

static inline int isword_delim(char c)
{
	if (c == ' ' ||
		c == ',' ||
		c == '.' ||
		c == '\t' ||
		c == '\v' ||
		c == '\r' ||
		c == '\n' ||
		c == '\0')
		return 1;
	return 0;
}

char *dm_strword(char *src, char *str)
{
	if (!src || src[0] == 0 || !str || str[0] == 0)
		return NULL;

	int len = strlen(str);
	char *ret = src;

	while ((ret = strstr(ret, str)) != NULL) {
		if ((ret == src && isword_delim(ret[len])) ||
			(ret != src && isword_delim(ret[len]) && isword_delim(*(ret - 1))))
			return ret;
		ret++;
	}
	return NULL;
}

char **strsplit(const char *str, const char *delim, size_t *numtokens)
{
	char *s = strdup(str);
	size_t tokens_alloc = 1;
	size_t tokens_used = 0;
	char **tokens = dmcalloc(tokens_alloc, sizeof(char*));
	char *token, *strtok_ctx;

	for (token = strtok_r(s, delim, &strtok_ctx);
		token != NULL;
		token = strtok_r(NULL, delim, &strtok_ctx)) {

		if (tokens_used == tokens_alloc) {
			tokens_alloc *= 2;
			tokens = dmrealloc(tokens, tokens_alloc * sizeof(char*));
		}
		tokens[tokens_used++] = dmstrdup(token);
	}
	if (tokens_used == 0) {
		dmfree(tokens);
		tokens = NULL;
	} else {
		tokens = dmrealloc(tokens, tokens_used * sizeof(char*));
	}
	*numtokens = tokens_used;
	FREE(s);
	return tokens;
}

char **strsplit_by_str(const char str[], char *delim)
{
	char *substr = NULL;
	size_t tokens_alloc = 1;
	size_t tokens_used = 0;
	char **tokens = dmcalloc(tokens_alloc, sizeof(char*));
	char *strparse = strdup(str);
	do {
		if (strparse == NULL || strparse[0] == '\0')
			break;

		substr = DM_STRSTR(strparse, delim);

		if (substr == NULL) {
			substr = strdup(strparse);
			tokens[tokens_used] = dmcalloc(DM_STRLEN(substr)+1, sizeof(char));
			DM_STRNCPY(tokens[tokens_used], strparse, DM_STRLEN(substr)+1);
			tokens_used++;
			FREE(strparse);
			break;
		}

		if (tokens_used == tokens_alloc) {
			tokens_alloc += 2;
			tokens = dmrealloc(tokens, tokens_alloc * sizeof(char*));
		}

		tokens[tokens_used] = dmcalloc(substr-strparse+1, sizeof(char));
		DM_STRNCPY(tokens[tokens_used], strparse, substr - strparse + 1);
		tokens_used++;
		FREE(strparse);
		strparse = strdup(substr+DM_STRLEN(delim));
	} while (substr != NULL);
	FREE(strparse);
	tokens[tokens_used] = NULL;
	return tokens;
}

void convert_str_to_uppercase(char *str)
{
	for (int i = 0; str[i] != '\0'; i++) {
		if (str[i] >= 'a' && str[i] <= 'z') {
			str[i] = str[i] - 32;
		}
	}
}

char *get_macaddr(char *interface_name)
{
	char *device = get_device(interface_name);
	char *mac;

	if (device[0]) {
		char file[128];
		char val[32];

		snprintf(file, sizeof(file), "/sys/class/net/%s/address", device);
		dm_read_sysfs_file(file, val, sizeof(val));
		convert_str_to_uppercase(val);
		mac = dmstrdup(val);
	} else {
		mac = "";
	}
	return mac;
}

char *get_device(char *interface_name)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface_name, String}}, 1, &res);
	return dmjson_get_value(res, 1, "device");
}

char *get_l3_device(char *interface_name)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface_name, String}}, 1, &res);
	return dmjson_get_value(res, 1, "l3_device");
}

char *get_device_from_wifi_iface(const char *wifi_iface, const char *wifi_section)
{
	json_object *jobj;
	array_list *jarr;
	unsigned n = 0, i;
	const char *ifname = "";

	if (!wifi_iface || wifi_iface[0] == 0 || !wifi_section || wifi_section[0] == 0)
		return "";

	dmubus_call("network.wireless", "status", UBUS_ARGS{{}}, 0, &jobj);
	if (jobj == NULL)
		return "";

	json_object_object_get_ex(jobj, wifi_iface, &jobj);
	json_object_object_get_ex(jobj, "interfaces", &jobj);

	jarr = json_object_get_array(jobj);
	if (jarr)
		n = array_list_length(jarr);

	for (i = 0; i < n; i++) {
		json_object *j_e = jarr->array[i];
		const char *sect;

		sect = dmjson_get_value(j_e, 1, "section");
		if (!strcmp(sect, wifi_section)) {
			ifname = dmjson_get_value(j_e, 2, "config", "ifname");
			break;
		}
	}
	return (char *)ifname;
}

bool value_exists_in_uci_list(struct uci_list *list, const char *value)
{
	struct uci_element *e;

	if (list == NULL)
		return false;

	uci_foreach_element(list, e) {
		if (!DM_STRCMP(e->name, value))
			return true;
	}

	return false;
}

bool value_exits_in_str_list(char *str_list, const char *delimitor, const char *value)
{
	char *pch, *spch;

	if (str_list == NULL || *str_list == '\0')
		return false;

	char *list = dmstrdup(str_list);
	for (pch = strtok_r(list, delimitor, &spch); pch != NULL; pch = strtok_r(NULL, delimitor, &spch)) {
		if (DM_STRCMP(pch, value) == 0)
			return true;
	}
	return false;
}

void add_elt_to_str_list(char **str_list, char *elt)
{
	if (*str_list == NULL || DM_STRLEN(*str_list) == 0) {
		dmasprintf(str_list, "%s", elt);
		return;
	}

	char *list = dmstrdup(*str_list);
	dmfree(*str_list);
	*str_list = NULL;
	dmasprintf(str_list, "%s %s", list, elt);
}

void remove_elt_from_str_list(char **str_list, char *ifname)
{
	char *list = NULL, *tmp = NULL, *pch = NULL, *spch = NULL;

	if (*str_list == NULL || DM_STRLEN(*str_list) == 0)
		return;

	list = dmstrdup(*str_list);
	dmfree(*str_list);
	*str_list = NULL;

	for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		if (DM_STRCMP(pch, ifname) == 0)
			continue;

		if (tmp == NULL)
			dmasprintf(str_list, "%s", pch);
		else
			dmasprintf(str_list, "%s %s", tmp, pch);

		if (tmp) {
			dmfree(tmp);
			tmp = NULL;
		}

		if (*str_list) {
			tmp = dmstrdup(*str_list);
			dmfree(*str_list);
			*str_list = NULL;
		}
	}

	dmasprintf(str_list, "%s", tmp ? tmp : "");
}

bool elt_exists_in_array(char **str_array, char *str, int length)
{
	int i;

	for (i = 0; i < length; i++) {
		if (DM_STRCMP(str_array[i], str) == 0)
			return true;
	}
	return false;
}

int get_shift_utc_time(int shift_time, char *utc_time, int size)
{
	struct tm *t_tm;
	time_t now = time(NULL);

	now = now + shift_time;
	t_tm = gmtime(&now);
	if (t_tm == NULL)
		return -1;

	if (strftime(utc_time, size, "%Y-%m-%dT%H:%M:%SZ", t_tm) == 0)
		return -1;

	return 0;
}

int get_shift_time_time(int shift_time, char *local_time, int size)
{
	time_t t_time;
	struct tm *t_tm;

	t_time = time(NULL) + shift_time;
	t_tm = localtime(&t_time);
	if (t_tm == NULL)
		return -1;

	if (strftime(local_time, size, "%Y-%m-%dT%H:%M:%SZ", t_tm) == 0)
		return -1;

	return 0;
}

static inline int char_is_valid(char c)
{
	return c >= 0x20 && c < 0x7f;
}

int dm_read_sysfs_file(const char *file, char *dst, unsigned len)
{
	char content[len];
	int fd;
	int rlen;
	int i, n;
	int rc = 0;

	dst[0] = 0;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;

	rlen = read(fd, content, len - 1);
	if (rlen == -1) {
		rc = -1;
		goto out;
	}

	content[rlen] = 0;
	for (i = 0, n = 0; i < rlen; i++) {
		if (!char_is_valid(content[i])) {
			if (i == 0)
				continue;
			else
				break;
		}
		dst[n++] = content[i];
	}
	dst[n] = 0;

out:
	close(fd);
	return rc;
}

int get_net_device_sysfs(const char *device, const char *name, char **value)
{
	if (device && device[0]) {
		char file[256];
		char val[32] = {0};

		snprintf(file, sizeof(file), "/sys/class/net/%s/%s", device, name);
		dm_read_sysfs_file(file, val, sizeof(val));
		if (strcmp(name, "address") == 0) {
			// Convert the mac address to upper case
			convert_str_to_uppercase(val);
		}
		*value = dmstrdup(val);
	} else {
		*value = "0";
	}
	return 0;
}

int get_net_device_status(const char *device, char **value)
{
	char *operstate = NULL;

	get_net_device_sysfs(device, "operstate", &operstate);
	if (operstate == NULL || *operstate == '\0') {
		*value = "Down";
		return 0;
	}

	if (strcmp(operstate, "up") == 0)
		*value = "Up";
	else if (strcmp(operstate, "unknown") == 0)
		*value = "Unknown";
	else if (strcmp(operstate, "notpresent") == 0)
		*value = "NotPresent";
	else if (strcmp(operstate, "lowerlayerdown") == 0)
		*value = "LowerLayerDown";
	else if (strcmp(operstate, "dormant") == 0)
		*value = "Dormant";
	else
		*value = "Down";

	return 0;
}

int get_net_iface_sysfs(const char *uci_iface, const char *name, char **value)
{
	const char *device = get_device((char *)uci_iface);

	return get_net_device_sysfs(device, name, value);
}

int dm_time_utc_format(time_t ts, char **dst)
{
	char time_buf[32] = { 0, 0 };
	struct tm *t_tm;

	*dst = "0001-01-01T00:00:00Z";

	t_tm = gmtime(&ts);
	if (t_tm == NULL)
		return -1;

	if(strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", t_tm) == 0)
		return -1;

	*dst = dmstrdup(time_buf);
	return 0;
}

int dm_time_format(time_t ts, char **dst)
{
	char time_buf[32] = { 0, 0 };
	struct tm *t_tm;

	*dst = "0001-01-01T00:00:00+00:00";

	t_tm = localtime(&ts);
	if (t_tm == NULL)
		return -1;

	if(strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S%z", t_tm) == 0)
		return -1;

	time_buf[25] = time_buf[24];
	time_buf[24] = time_buf[23];
	time_buf[22] = ':';
	time_buf[26] = '\0';

	*dst = dmstrdup(time_buf);
	return 0;
}

void convert_string_to_hex(const char *str, char *hex, size_t size)
{
	int i, len = DM_STRLEN(str);
	unsigned pos = 0;

	for (i = 0; i < len && pos < size - 2; i++) {
		pos += snprintf((char *)hex + pos, size - pos, "%02X", str[i]);
	}

	hex[pos] = '\0';
}

void convert_hex_to_string(const char *hex, char *str, size_t size)
{
	int i, len = DM_STRLEN(hex);
	unsigned pos = 0;
	char buf[3] = {0};

	for (i = 0; i < len && pos < size - 1; i += 2) {
		DM_STRNCPY(buf, &hex[i], 3);

		char c = (char)strtol(buf, NULL, 16);
		if (!char_is_valid(c))
			continue;

		pos += snprintf((char *)str + pos, size - pos, "%c", c);
	}

	str[pos] = '\0';
}

void convert_str_option_to_hex(unsigned int tag, const char *str, char *hex, size_t size)
{
	int idx = -1;

	if (str == NULL || hex == NULL || size == 0)
		return;

	for (int i = 0; i < ARRAY_SIZE(TYPE_TAG_ARRAY); i++) {
		if (TYPE_TAG_ARRAY[i].tag == tag) {
			idx = i;
			break;
		}
	}

	if (idx == -1) {
		convert_string_to_hex(str, hex, size);
		return;
	}

	char *pch = NULL, *spch = NULL;
	unsigned pos = 0;
	char buf[512] = {0};

	DM_STRNCPY(buf, str, sizeof(buf));
	for (pch = strtok_r(buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		if (TYPE_TAG_ARRAY[idx].type == OPTION_IP) {
			struct in_addr ip_bin;

			if (!inet_aton(pch, &ip_bin))
				continue;

			unsigned int ip = ntohl(ip_bin.s_addr);

			if (size - pos < TYPE_TAG_ARRAY[idx].len * 2)
				return;

			pos += snprintf(&hex[pos], size - pos, "%08X", ip);
		} else if (TYPE_TAG_ARRAY[idx].type == OPTION_HEX) {
			for (int j = 0; j < DM_STRLEN(pch) && pos < size - 1; j++) {
				if (pch[j] == ':')
					continue;

				pos += snprintf(&hex[pos], size - pos, "%c", pch[j]);
			}
		} else {
			long int val = DM_STRTOL(pch);

			if (size - pos < TYPE_TAG_ARRAY[idx].len * 2)
				return;

			pos += snprintf(&hex[pos], size - pos, (TYPE_TAG_ARRAY[idx].len == 4) ? "%08lX" : (TYPE_TAG_ARRAY[idx].len == 2) ? "%04lX" : "%02lX", val);
		}
	}
}

void convert_hex_option_to_string(unsigned int tag, const char *hex, char *str, size_t size)
{
	int idx = -1;

	if (hex == NULL || str == NULL || size == 0)
		return;

	for (int i = 0; i < ARRAY_SIZE(TYPE_TAG_ARRAY); i++) {
		if (TYPE_TAG_ARRAY[i].tag == tag) {
			idx = i;
			break;
		}
	}

	if (idx == -1) {
		convert_hex_to_string(hex, str, size);
		return;
	}

	unsigned pos = 0;
	unsigned int str_len = DM_STRLEN(hex);
	unsigned int len = TYPE_TAG_ARRAY[idx].len * 2;
	char buffer[32] = {0};
	char buf[16] = {0};

	for (int i = 0; i + len <= str_len; i = i + len) {
		DM_STRNCPY(buf, &hex[i], len + 1);

		if (TYPE_TAG_ARRAY[idx].type == OPTION_IP) {
			struct in_addr addr;
			unsigned int ip;

			sscanf(buf, "%X", &ip);
			addr.s_addr = htonl(ip);
			char *ipaddr = inet_ntoa(addr);
			snprintf(buffer, sizeof(buffer), "%s,", ipaddr);
		} else if (TYPE_TAG_ARRAY[idx].type == OPTION_HEX) {
			snprintf(buffer, sizeof(buffer), "%s:", buf);
		} else {
			snprintf(buffer, sizeof(buffer), "%d,", (int)strtol(buf, NULL, 16));
		}

		if (size - pos < DM_STRLEN(buffer) + 1)
			break;

		pos += snprintf(&str[pos], size - pos, "%s", buffer);
	}

	if (pos)
		str[pos - 1] = 0;
}

bool match(const char *string, const char *pattern)
{
	regex_t re;
	if (regcomp(&re, pattern, REG_EXTENDED) != 0) return 0;
	int status = regexec(&re, string, 0, NULL, 0);
	regfree(&re);
	if (status != 0) return false;
	return true;
}

static int dm_validate_string_length(char *value, int min_length, int max_length)
{
	if (((min_length > 0) && (DM_STRLEN(value) < min_length)) || ((max_length > 0) && (DM_STRLEN(value) > max_length)))
		return -1;
	return 0;
}

static int dm_validate_string_enumeration(char *value, char *enumeration[])
{
	for (; *enumeration; enumeration++) {
		if (DM_STRCMP(*enumeration, value) == 0)
			return 0;
	}
	return -1;
}

static int dm_validate_string_pattern(char *value, char *pattern[])
{
	for (; *pattern; pattern++) {
		if (match(value, *pattern))
			return 0;
	}
	return -1;
}

int dm_validate_string(char *value, int min_length, int max_length, char *enumeration[], char *pattern[])
{
	/* check size */
	if (dm_validate_string_length(value, min_length, max_length))
		return -1;

	/* check enumeration */
	if (enumeration && dm_validate_string_enumeration(value, enumeration))
		return -1;

	/* check pattern */
	if (pattern && dm_validate_string_pattern(value, pattern))
		return -1;

	return 0;
}

int dm_validate_boolean(char *value)
{
	/* check format */
	if ((value[0] == '1' && value[1] == '\0') ||
		(value[0] == '0' && value[1] == '\0') ||
		!strcasecmp(value, "true") ||
		!strcasecmp(value, "false")) {
		return 0;
	}
	return -1;
}

int dm_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0)
		return -1;

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		unsigned long ui_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtoul(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtoul(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		ui_val = strtoul(value, &endval, 10);

		if ((*value == '-') || (*endval != 0) || (errno != 0)) return -1;

		if (r_args[i].min && r_args[i].max) {

			if (minval == maxval) {
				if (strlen(value) == minval)
					break;
			} else {
				if (ui_val >= minval && ui_val <= maxval)
					break;
			}

			if (i == r_args_size - 1)
				return -1;

			continue;
		}

		/* check size */
		if ((r_args[i].min && ui_val < minval) || (r_args[i].max && ui_val > maxval) || (ui_val > (unsigned int)UINT_MAX))
			return -1;
	}

	return 0;
}

int dm_validate_int(char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0)
		return -1;

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		long i_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtol(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtol(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		i_val = strtol(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) return -1;

		if (r_args[i].min && r_args[i].max) {

			if (i_val >= minval && i_val <= maxval)
				break;

			if (i == r_args_size - 1)
				return -1;

			continue;
		}

		/* check size */
		if ((r_args[i].min && i_val < minval) || (r_args[i].max && i_val > maxval) || (i_val < INT_MIN) || (i_val > INT_MAX))
			return -1;
	}

	return 0;
}

int dm_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0)
		return -1;

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		unsigned long ul_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtoul(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtoul(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		ul_val = strtoul(value, &endval, 10);

		if ((*value == '-') || (*endval != 0) || (errno != 0)) return -1;

		if (r_args[i].min && r_args[i].max) {

			if (ul_val >= minval && ul_val <= maxval)
				break;

			if (i == r_args_size - 1)
				return -1;

			continue;
		}

		/* check size */
		if ((r_args[i].min && ul_val < minval) || (r_args[i].max && ul_val > maxval) || (ul_val > (unsigned long)ULONG_MAX))
			return -1;
	}

	return 0;
}

int dm_validate_long(char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0)
		return -1;

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		long u_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtol(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtol(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		u_val = strtol(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) return -1;

		if (r_args[i].min && r_args[i].max) {

			if (u_val >= minval && u_val <= maxval)
				break;

			if (i == r_args_size - 1)
				return -1;

			continue;
		}

		/* check size */
		if ((r_args[i].min && u_val < minval) || (r_args[i].max && u_val > maxval))
			return -1;
	}

	return 0;
}

int dm_validate_dateTime(char *value)
{
	/*
	 * Allowed format:
	 * XXXX-XX-XXTXX:XX:XXZ
	 * XXXX-XX-XXTXX:XX:XX.XXXZ
	 * XXXX-XX-XXTXX:XX:XX.XXXXXXZ
	 */

	char *p = NULL;
	struct tm tm;
	int m;

	p = strptime(value, "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (p && *p == '\0')
		return 0;

	p = strptime(value, "%Y-%m-%dT%H:%M:%S.", &tm);
	if (!p || *p == '\0' || value[DM_STRLEN(value) - 1] != 'Z')
		return -1;

	int num_parsed = sscanf(p, "%dZ", &m);
	if (num_parsed != 1 || (DM_STRLEN(p) != 7 && DM_STRLEN(p) != 4))
		return -1;

	return 0;
}

int dm_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check format */
	for (i = 0; i < DM_STRLEN(value); i++) {
		if (!isxdigit(value[i]))
			return -1;
	}

	/* check size */
	for (i = 0; i < r_args_size; i++) {

		if (r_args[i].min && r_args[i].max && (DM_STRTOL(r_args[i].min) == DM_STRTOL(r_args[i].max))) {

			if (DM_STRLEN(value) == 2 * DM_STRTOL(r_args[i].max))
				break;

			if (i == r_args_size - 1)
				return -1;

			continue;
		}

		if ((r_args[i].min && (DM_STRLEN(value) < DM_STRTOL(r_args[i].min))) ||
			(r_args[i].max && (DM_STRLEN(value) > DM_STRTOL(r_args[i].max)))) {
			return -1;
		}
	}

	return 0;
}

static int dm_validate_size_list(int min_item, int max_item, int nbr_item)
{
	if (((min_item > 0) && (max_item > 0) && (min_item == max_item) && (nbr_item == 2 * min_item)))
		return 0;

	if (((min_item > 0) && (nbr_item < min_item)) ||
		((max_item > 0) && (nbr_item > max_item))) {
		return -1;
	}
	return 0;
}

int dm_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])
{
	char *pch, *pchr;
	int nbr_item = 0;

	if (!value)
		return -1;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
		if (dm_validate_string(pch, min, max, enumeration, pattern))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int dm_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *tmp, *saveptr;
	int nbr_item = 0;

	if (!value)
		return -1;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (tmp = strtok_r(buf, ",", &saveptr); tmp != NULL; tmp = strtok_r(NULL, ",", &saveptr)) {
		if (dm_validate_unsignedInt(tmp, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int dm_validate_int_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *token, *pchr;
	int nbr_item = 0;

	if (!value)
		return -1;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (token = strtok_r(buf, ",", &pchr); token != NULL; token = strtok_r(NULL, ",", &pchr)) {
		if (dm_validate_int(token, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int dm_validate_unsignedLong_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *token, *tmp;
	int nbr_item = 0;

	if (!value)
		return -1;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (token = strtok_r(buf, ",", &tmp); token != NULL; token = strtok_r(NULL, ",", &tmp)) {
		if (dm_validate_unsignedLong(token, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int dm_validate_long_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *pch, *saveptr;
	int nbr_item = 0;

	if (!value)
		return -1;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &saveptr); pch != NULL; pch = strtok_r(NULL, ",", &saveptr)) {
		if (dm_validate_long(pch, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int dm_validate_hexBinary_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *pch, *spch;
	int nbr_item = 0;

	if (!value)
		return -1;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		if (dm_validate_hexBinary(pch, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

bool folder_exists(const char *path)
{
	struct stat buffer;

	return stat(path, &buffer) == 0 && S_ISDIR(buffer.st_mode);
}

bool file_exists(const char *path)
{
	struct stat buffer;

	return stat(path, &buffer) == 0;
}

bool is_regular_file(const char *path)
{
	struct stat buffer;

	return stat(path, &buffer) == 0 && S_ISREG(buffer.st_mode);
}

unsigned long file_system_size(const char *path, const enum fs_size_type_enum type)
{
	struct statvfs vfs;

	statvfs(path, &vfs);

	switch (type) {
		case FS_SIZE_TOTAL:
			return vfs.f_blocks * vfs.f_frsize;
		case FS_SIZE_AVAILABLE:
			return vfs.f_bavail * vfs.f_frsize;
		case FS_SIZE_USED:
			return (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize;
		default:
			return -1;
	}
}

static int get_base64_char(char b64)
{
	char *base64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (int i = 0; i < 64; i++)
		if (base64C[i] == b64)
		return i;

	return -1;
}

char *base64_decode(const char *src)
{
	int i, j = 0;

	if (!src || *src == '\0')
		return "";

	size_t decsize = DM_STRLEN(src)*6/8;
	char *out = (char *)dmmalloc((decsize +1) * sizeof(char));

	for (i = 0; i < DM_STRLEN(src)-1; i++) {
		out[j] = (get_base64_char(src[i]) << (j%3==0?2:(j%3==1?4:6))) + (get_base64_char(src[i+1]) >> (j%3==0?4:(j%3==1? 2:0)));
		if (j%3 == 2)
			i++;
		j++;
	}
	out[j] = '\0';

	return out;
}

void string_to_mac(const char *str, size_t str_len, char *out, size_t out_len)
{
	unsigned pos = 0;
	int i, j;

	if (!str || !str_len)
		return;

	for (i = 0, j = 0; i < str_len; ++i, j += 3) {
		pos += snprintf(out + j, out_len - pos, "%02x", str[i] & 0xff);
		if (i < str_len - 1)
			pos += snprintf(out + j + 2, out_len - pos, "%c", ':');
	}
}

char *replace_char(char *str, char find, char replace)
{
	char *current_pos = DM_STRCHR(str, find);
	while (current_pos) {
		*current_pos = replace;
		current_pos = DM_STRCHR(current_pos, find);
	}
	return str;
}

char *replace_str(const char *str, const char *substr, const char *replacement)
{
	int replacement_len = DM_STRLEN(replacement);
	int substr_len = DM_STRLEN(substr);
	int i, cnt = 0;

	for (i = 0; str[i] != '\0'; i++) {
		if (DM_STRSTR(&str[i], substr) == &str[i]) {
			cnt++;
			i += substr_len - 1;
		}
	}

	size_t new_str_len = i + cnt * (replacement_len - substr_len) + 1;
	char *value = (char *)dmmalloc(new_str_len * sizeof(char));

	i = 0;
	while (*str) {
		if (strstr(str, substr) == str) {
			i += snprintf(&value[i], new_str_len - i, "%s", replacement);
			str += substr_len;
		}
		else
			value[i++] = *str++;
	}
	value[i] = '\0';

	return value;
}

void strip_lead_trail_whitespace(char *str)
{
	if (str == NULL)
		return;

	/* First remove leading whitespace */
	const char* first_valid = str;

	while (*first_valid == ' ') {
		++first_valid;
	}

	size_t len = strlen(first_valid) + 1;

	memmove(str, first_valid, len);

	/* Now remove trailing whitespace */
	char* end_str = str + strlen(str) - 1;

	while (str < end_str  && *end_str == ' ') {
		*end_str = '\0';
		--end_str ;
	}
}

int dm_file_to_buf(const char *filename, void *buf, size_t buf_size)
{
	FILE *file;
	int ret = -1;

	file = fopen(filename, "r");
	if (file) {
		ret = fread(buf, 1, buf_size - 1, file);
		fclose(file);
	}
	((char *)buf)[ret > 0 ? ret : 0] = '\0';
	return ret;
}

int check_browse_section(struct uci_section *s, void *data)
{
	struct browse_args *browse_args = (struct browse_args *)data;
	char *opt_val;

	dmuci_get_value_by_section_string(s, browse_args->option, &opt_val);
	if (DM_STRCMP(opt_val, browse_args->value) == 0)
		return 0;
	return -1;
}

int parse_proc_intf6_line(const char *line, const char *device, char *ipstr, size_t str_len)
{
	char ip6buf[INET6_ADDRSTRLEN] = {0}, dev[32] = {0};
	unsigned int ip[4], prefix;

	sscanf(line, "%8x%8x%8x%8x %*s %x %*s %*s %31s",
				&ip[0], &ip[1], &ip[2], &ip[3],
				&prefix, dev);

	if (DM_STRCMP(dev, device) != 0)
		return -1;

	ip[0] = htonl(ip[0]);
	ip[1] = htonl(ip[1]);
	ip[2] = htonl(ip[2]);
	ip[3] = htonl(ip[3]);

	inet_ntop(AF_INET6, ip, ip6buf, INET6_ADDRSTRLEN);
	snprintf(ipstr, str_len, "%s/%u", ip6buf, prefix);

	if (strncmp(ipstr, "fe80:", 5) != 0)
		return -1;

	return 0;
}

// Get IPv4 address assigned to an interface using ioctl
// return ==> dynamically allocated IPv4 address on success,
//        ==> empty string on failure
// Note: Ownership of returned dynamically allocated IPv4 address is with caller
char *ioctl_get_ipv4(char *interface_name)
{
	int fd;
	struct ifreq ifr;
	char *ip = "";

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		goto exit;

	ifr.ifr_addr.sa_family = AF_INET;
	DM_STRNCPY(ifr.ifr_name, interface_name, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
		goto exit;

	ip = dmstrdup(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));

exit:
	close(fd);

	return ip;
}

char *get_ipv6(char *interface_name)
{
	FILE *fp = NULL;
	char buf[512] = {0};
	char ipstr[64] = {0};

	fp = fopen(PROC_INTF6, "r");
	if (fp == NULL)
		return "";

	while (fgets(buf, 512, fp) != NULL) {
		ipstr[0] = '\0';

		if (parse_proc_intf6_line(buf, interface_name, ipstr, sizeof(ipstr)) == 0) {
			if (DM_STRLEN(ipstr) != 0) {
				char *slash = DM_STRCHR(ipstr, '/');
				if (slash)
					*slash = '\0';
			}
			break;
		}
	}
	fclose(fp);

	return (*ipstr) ? dmstrdup(ipstr) : "";
}

static bool validate_blob_dataval(struct blob_attr *src_attr, struct blob_attr *dst_attr)
{
	if (!src_attr || !dst_attr)
		return false;

	int src_type = blob_id(src_attr);
	int dst_type = blob_id(dst_attr);
	if (src_type != dst_type)
		return false;

	void *src_val = blobmsg_data(src_attr);
	void *dst_val = blobmsg_data(dst_attr);

	switch (src_type) {
	case BLOBMSG_TYPE_STRING:
		if (src_val == NULL && dst_val == NULL)
			return true;

		if (src_val && dst_val && DM_STRCMP((char *)src_val, (char*)dst_val) == 0)
			return true;
		break;
	default:
		break;
	}

	return false;
}

/*********************************************************************//**
**
** validate_blob_message
**
** This API is to validate the 'src' blob message against 'dst' blob message. It
** validates the attributes(key:value pair) present in 'src' are also exist in 'dst'.
** 'dst' may have more attributes than 'src'.
**
** NOTE: currently we only support string type value in key:val i.e if the attribute
** in 'src' blob message is other than of type string (like array, table etc) this
** API will return false.
**
** \param   src - blob message to validate
** \param   dst - blob message against which the validation is performed
**
** \return  true: if all key:value pairs in 'src' are present in 'dst'
**          false: otherwise
**
**************************************************************************/
bool validate_blob_message(struct blob_attr *src, struct blob_attr *dst)
{
	if (!src || !dst)
		return false;

	size_t src_len = (size_t)blobmsg_data_len(src);
	size_t dst_len = (size_t)blobmsg_data_len(dst);

	if (dst_len < src_len)
		return false;

	bool res = true;
	struct blob_attr *src_attr, *dst_attr;

	__blob_for_each_attr(src_attr, blobmsg_data(src), src_len) {
		bool matched = false;
		__blob_for_each_attr(dst_attr, blobmsg_data(dst), dst_len) {
			if (DM_STRCMP(blobmsg_name(src_attr), blobmsg_name(dst_attr)) != 0) {
				continue;
			}

			matched = validate_blob_dataval(src_attr, dst_attr);
			break;
		}
		if (matched == false) {
			res = false;
			break;
		}
	}

	return res;
}
