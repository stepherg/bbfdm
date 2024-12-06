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

#include <curl/curl.h>

#include "dmcommon.h"

char *DiagnosticsState[] = {"None", "Requested", "Canceled", "Complete", "Error", NULL};

char *IPv4Address[] = {"^$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$", NULL};
char *IPv6Address[] = {"^$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$", NULL};
char *IPAddress[] = {"^$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$", NULL};
char *MACAddress[] = {"^$", "^([0-9A-Fa-f][0-9A-Fa-f]:){5}([0-9A-Fa-f][0-9A-Fa-f])$", NULL};
char *IPPrefix[] = {"^$", "^/(3[0-2]|[012]?[0-9])$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[012]?[0-9])$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/(12[0-8]|1[0-1][0-9]|[0-9]?[0-9])$", NULL};
char *IPv4Prefix[] = {"^$", "^/(3[0-2]|[012]?[0-9])$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[012]?[0-9])$", NULL};
char *IPv6Prefix[] = {"^$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/(12[0-8]|1[0-1][0-9]|[0-9]?[0-9])$", NULL};

pid_t get_pid(const char *pname)
{
	DIR *dir = NULL;
	struct dirent *ent = NULL;

	if (!pname)
		return -1;

	if (!(dir = opendir("/proc")))
		return -1;

	while((ent = readdir(dir)) != NULL) {
		char *endptr = NULL;
		char buf[512] = {0};

		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0')
			continue;

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

int compare_strings(const void *a, const void *b)
{
	return DM_STRCMP(*(const char **)a, *(const char **)b);
}

char *get_uptime(void)
{
    FILE *fp = fopen(UPTIME, "r");
    char *uptime = NULL;

	if (fp != NULL) {
		char *pch = NULL, *spch = NULL, buf[64] = {0};

		if (fgets(buf, 64, fp) != NULL) {
			pch = strtok_r(buf, ".", &spch);
			uptime = (pch) ? dmstrdup(pch) : "0";
		}
		fclose(fp);
	}

    return uptime ? uptime : "0";
}

int check_file(const char *path)
{
	glob_t globbuf;

	if (!path)
		return 0;

	if(glob(path, 0, NULL, &globbuf) == 0) {
		globfree(&globbuf);
		return 1;
	}

	return 0;
}

char *cidr2netmask(int bits)
{
	char *buf = (char *)dmcalloc(INET_ADDRSTRLEN, sizeof(char));
	if (!buf)
		return "";

	uint32_t mask = (bits >= 32) ? 0xFFFFFFFFUL : (0xFFFFFFFFUL << (32 - bits));
	mask = htonl(mask);

	struct in_addr ip_addr;
	ip_addr.s_addr = mask;

	if (inet_ntop(AF_INET, &ip_addr, buf, INET_ADDRSTRLEN) == NULL) {
		// Error converting binary to presentation format
		return "";
	}

	return buf;
}

int netmask2cidr(const char *netmask)
{
	struct in_addr addr;
	int bits = 0;

	if (!netmask || inet_aton(netmask, &addr) == 0) {
		// Invalid netmask format
		return -1;
	}

	uint32_t mask = ntohl(addr.s_addr);

	while (mask & 0x80000000) {
		bits++;
		mask <<= 1;
	}

	return bits;
}


bool is_strword_in_optionvalue(const char *option_value, const char *str)
{
	if (!option_value || !str)
		return false;

	const char *s = option_value;

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

int dmcmd(const char *cmd, int n, ...)
{
	char *argv[n + 2];
	va_list arg;
	int i, status;
	pid_t pid, wpid;

	argv[0] = dmstrdup(cmd);
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

int dmcmd_no_wait(const char *cmd, int n, ...)
{
	char *argv[n + 2];
	va_list arg;
	int i;
	pid_t pid;

	argv[0] = dmstrdup(cmd);
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

int run_cmd(const char *cmd, char *output, size_t out_len)
{
	int ret = -1;
	FILE *pp;

	if (cmd == NULL) {
		return 0;
	}

	if (output == NULL || out_len == 0) {
		return ret;
	}

	memset(output, 0, out_len);

	pp = popen(cmd, "r"); // flawfinder: ignore
	if (pp != NULL) {
		if (!(fgets(output, out_len, pp) == NULL && ferror(pp) != 0)) {
			ret = 0;
		}
		pclose(pp);
	}

	return ret;
}

int hex_to_ip(const char *address, char *ret, size_t size)
{
	unsigned int ip[4] = {0};

	if (!address || !ret || !size)
		return -1;

	sscanf(address, "%2x%2x%2x%2x", &(ip[0]), &(ip[1]), &(ip[2]), &(ip[3]));
	if (htonl(13) == 13) {
		snprintf(ret, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	} else {
		snprintf(ret, size, "%u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);
	}

	return 0;
}

/*
 * dmmap_config sections list manipulation
 */
void add_dmmap_config_dup_list(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section)
{
	struct dm_data *dm_data = NULL;

	dm_data = (struct dm_data *)dmcalloc(1, sizeof(struct dm_data));
	if (!dm_data)
		return;

	list_add_tail(&dm_data->list, dup_list);
	dm_data->config_section = config_section;
	dm_data->dmmap_section = dmmap_section;
}

void free_dmmap_config_dup_list(struct list_head *dup_list)
{
	struct dm_data *dm_data = NULL, *tmp = NULL;

	list_for_each_entry_safe(dm_data, tmp, dup_list, list) {
		list_del(&dm_data->list);
		dmfree(dm_data);
	}
}

/*
 * Function allows to synchronize config section with dmmap config
 */
struct uci_section *get_origin_section_from_config(const char *package, const char *section_type, const char *orig_section_name)
{
	struct uci_section *s = NULL;

	uci_foreach_sections(package, section_type, s) {
		if (strcmp(section_name(s), orig_section_name) == 0)
			return s;
	}

	return NULL;
}

struct uci_section *get_origin_section_from_dmmap(const char *package, const char *section_type, const char *orig_section_name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_sections(bbfdm, package, section_type, s) {
		if (strcmp(section_name(s), orig_section_name) == 0)
			return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap(const char *dmmap_package, const char *section_type, const char *orig_section_name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_sections(bbfdm, dmmap_package, section_type, s) {
		char *dmmap_sec_name = NULL;

		dmuci_get_value_by_section_string(s, "section_name", &dmmap_sec_name);

		if (DM_STRCMP(dmmap_sec_name, orig_section_name) == 0)
			return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_config_opt(const char *package, const char *section_type, const char *opt_name, const char *opt_value)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq(package, section_type, opt_name, opt_value, s) {
		return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap_opt(const char *dmmap_package, const char *section_type, const char *opt_name, const char *opt_value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt_name, opt_value, s) {
		return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap_eq(const char *dmmap_package, const char *section_type,
		const char *sect_name, const char *opt_name, const char *opt_value)
{
	struct uci_section *s = NULL;
	char *v = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", sect_name, s) {
		dmuci_get_value_by_section_string(s, opt_name, &v);
		if (DM_STRCMP(v, opt_value) == 0)
			return s;
	}

	return NULL;
}

struct uci_section *get_section_in_dmmap_with_options_eq(const char *dmmap_package, const char *section_type,
		const char *opt1_name, const char *opt1_value, const char *opt2_name, const char *opt2_value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt1_name, opt1_value, s) {
		char *value = NULL;

		dmuci_get_value_by_section_string(s, opt2_name, &value);
		if (DM_STRCMP(value, opt2_value) == 0)
			return s;
	}

	return NULL;
}

void synchronize_specific_config_sections_with_dmmap(const char *package, const char *section_type, const char *dmmap_package, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_sect = NULL;
	char *v = NULL;

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

void synchronize_specific_config_sections_with_dmmap_eq(const char *package, const char *section_type, const char *dmmap_package,
		const char *option_name, const char *option_value, struct list_head *dup_list)
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

void synchronize_specific_config_sections_with_dmmap_cont(const char *package, const char *section_type, const char *dmmap_package,
		const char *option_name, const char *option_value, struct list_head *dup_list)
{
	struct uci_section *uci_s = NULL, *stmp = NULL, *dmmap_sect = NULL;
	char *v = NULL;

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

void synchronize_specific_config_sections_with_dmmap_option(const char *package, const char *section_type, const char *dmmap_package,
		const char *option_name, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_sec = NULL;
	char *option_value = NULL;

	uci_foreach_sections(package, section_type, s) {
		dmuci_get_value_by_section_string(s, option_name, &option_value);

		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sec = get_dup_section_in_dmmap_opt(dmmap_package, section_type, option_name, option_value)) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sec);
			dmuci_set_value_by_section_bbfdm(dmmap_sec, option_name, option_value);
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
		dmuci_get_value_by_section_string(s, option_name, &option_value);
		if (get_dup_section_in_config_opt(package, section_type, option_name, option_value) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

void get_dmmap_section_of_config_section(const char *dmmap_package, const char *section_type, const char *section_name, struct uci_section **dmmap_section)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", section_name, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_dmmap_section_of_config_section_eq(const char *dmmap_package, const char *section_type, const char *opt, const char *value, struct uci_section **dmmap_section)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt, value, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_dmmap_section_of_config_section_cont(const char *dmmap_package, const char *section_type, const char *opt, const char *value, struct uci_section **dmmap_section)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_cont(bbfdm, dmmap_package, section_type, opt, value, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_config_section_of_dmmap_section(const char *package, const char *section_type, const char *section_name, struct uci_section **config_section)
{
	struct uci_section *s = NULL;

	uci_foreach_sections(package, section_type, s) {
		if (strcmp(section_name(s), section_name) == 0) {
			*config_section = s;
			return;
		}
	}
	*config_section = NULL;
}

static char *check_create_dmmap_package(const char *dmmap_package)
{
	char *path = NULL;
	int rc;

	if (!dmmap_package)
		return NULL;

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

struct uci_section *is_dmmap_section_exist(const char *package, const char *section)
{
	struct uci_section *s = NULL;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		return s;
	}
	return NULL;
}

struct uci_section *is_dmmap_section_exist_eq(const char *package, const char *section, const char *opt, const char *value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, package, section, opt, value, s) {
		return s;
	}
	return NULL;
}

unsigned int count_occurrences(const char *str, char c)
{
	int count = 0;

	if (!str)
		return 0;

	char *pch = strchr(str, c);
	while (pch) {
		count++;
		pch = strchr(pch + 1, c);
	}

	return count;
}

bool isdigit_str(const char *str)
{
	if (!DM_STRLEN(str))
		return false;

	while (*str) {
		if (!isdigit((unsigned char)*str))
			return false;
		str++;
	}

	return true;
}

bool ishex_str(const char *str)
{
	char *endptr = NULL;

	if (DM_STRLEN(str) < 2)
		return 0;

	if (str[0] != '0' || (str[1] != 'x' && str[1] != 'X'))
		return 0;

	strtol(str, &endptr, 0);

	return DM_STRLEN(endptr) ? 0 : 1;
}

bool special_char(char c)
{
	if ((c >= 'a' && c <= 'z') ||
	    (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		(c == '_'))
		return false;
	else
		return true;
}

bool special_char_exits(const char *str)
{
	if (!DM_STRLEN(str))
		return false;

	while (*str) {
		if (special_char(*str))
			return true;
		str++;
	}

	return false;
}

void replace_special_char(char *str, char c)
{
	for (int i = 0; i < DM_STRLEN(str); i++) {
		if (special_char(str[i]))
			str[i] = c;
	}
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

char **strsplit(const char *str, const char *delim, size_t *num_tokens)
{
	char *token = NULL, *save_ptr = NULL;
	char buf[2048] = {0};
	size_t tokens_num = 0;

	if (!str || !delim || !num_tokens) {
		if (num_tokens)
			*num_tokens = 0;
		return NULL;
	}

	DM_STRNCPY(buf, str, sizeof(buf));

	for (token = strtok_r(buf, delim, &save_ptr);
			token != NULL;
			token = strtok_r(NULL, delim, &save_ptr))
		tokens_num++;

	if (tokens_num == 0) {
		*num_tokens = 0;
		return NULL;
	}

	char **tokens = dmcalloc(tokens_num, sizeof(char *));
	if (!tokens) {
		*num_tokens = 0;
		return NULL;
	}

	DM_STRNCPY(buf, str, sizeof(buf));

	token = strtok_r(buf, delim, &save_ptr);
	for (size_t idx = 0; idx < tokens_num && token != NULL; idx++) {
		tokens[idx] = dmstrdup(token);
		token = strtok_r(NULL, delim, &save_ptr);
	}

	*num_tokens = tokens_num;
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

char *get_macaddr(const char *interface_name)
{
	char *device = get_device(interface_name);
	char *mac = NULL;

	if (device[0]) {
		char file[128];
		char val[32];

		snprintf(file, sizeof(file), "/sys/class/net/%s/address", device);
		dm_read_sysfs_file(file, val, sizeof(val));
		convert_str_to_uppercase(val);
		mac = dmstrdup(val);
	}

	return mac ? mac : "";
}

char *get_device(const char *interface_name)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface_name, String}}, 1, &res);
	return dmjson_get_value(res, 1, "device");
}

char *get_l3_device(const char *interface_name)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface_name, String}}, 1, &res);
	return dmjson_get_value(res, 1, "l3_device");
}

bool value_exists_in_uci_list(struct uci_list *list, const char *value)
{
	struct uci_element *e = NULL;

	if (list == NULL || value == NULL)
		return false;

	uci_foreach_element(list, e) {
		if (!DM_STRCMP(e->name, value))
			return true;
	}

	return false;
}

bool value_exits_in_str_list(const char *str_list, const char *delimitor, const char *str)
{
	char *pch = NULL, *spch = NULL;

	if (!DM_STRLEN(str_list) || !delimitor || !str)
		return false;

	char *list = dmstrdup(str_list);

	for (pch = strtok_r(list, delimitor, &spch); pch != NULL; pch = strtok_r(NULL, delimitor, &spch)) {
		if (DM_STRCMP(pch, str) == 0)
			return true;
	}

	return false;
}

char *add_str_to_str_list(const char *str_list, const char *delimitor, const char *str)
{
	char *res = NULL;

	if (!str_list || !delimitor || !str)
		return "";

	dmasprintf(&res, "%s%s%s", str_list, strlen(str_list) ? delimitor : "", str);

	return res ? res : "";
}

char *remove_str_from_str_list(const char *str_list, const char *delimitor, const char *str)
{
	char *pch = NULL, *spch = NULL;
	unsigned pos = 0;

	if (!str_list || !delimitor || !str)
		return "";

	int len = strlen(str_list);
	int del_len = strlen(delimitor);

	char *res = (char *)dmcalloc(len + 1, sizeof(char));
	char *list = dmstrdup(str_list);

	for (pch = strtok_r(list, delimitor, &spch); pch != NULL; pch = strtok_r(NULL, delimitor, &spch)) {

		if (DM_LSTRCMP(str, pch) == 0)
			continue;

		pos += snprintf(&res[pos], len + 1 - pos, "%s%s", pch, delimitor);
	}

	dmfree(list);

	if (pos)
		res[pos - del_len] = 0;

	return res;
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
		*value = dmstrdup("0");
	}

	return 0;
}

int get_net_device_status(const char *device, char **value)
{
	char *operstate = NULL;

	get_net_device_sysfs(device, "operstate", &operstate);
	if (operstate == NULL || *operstate == '\0') {
		*value = dmstrdup("Down");
		return 0;
	}

	if (strcmp(operstate, "up") == 0)
		*value = dmstrdup("Up");
	else if (strcmp(operstate, "unknown") == 0)
		*value = dmstrdup("Unknown");
	else if (strcmp(operstate, "notpresent") == 0)
		*value = dmstrdup("NotPresent");
	else if (strcmp(operstate, "lowerlayerdown") == 0)
		*value = dmstrdup("LowerLayerDown");
	else if (strcmp(operstate, "dormant") == 0)
		*value = dmstrdup("Dormant");
	else
		*value = dmstrdup("Down");

	return 0;
}

int get_net_iface_sysfs(const char *uci_iface, const char *name, char **value)
{
	const char *device = get_device(uci_iface);

	return get_net_device_sysfs(device, name, value);
}

int dm_time_utc_format(time_t ts, char **dst)
{
	char time_buf[32] = { 0, 0 };
	struct tm *t_tm;

	*dst = dmstrdup("0001-01-01T00:00:00Z");

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

	*dst = dmstrdup("0001-01-01T00:00:00+00:00");

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

bool match(const char *string, const char *pattern, size_t nmatch, regmatch_t pmatch[])
{
	regex_t re;

	if (!string || !pattern)
		return 0;

	if (regcomp(&re, pattern, REG_EXTENDED) != 0)
		return 0;

	int status = regexec(&re, string, nmatch, pmatch, 0);

	regfree(&re);

	return (status != 0) ? false : true;
}

void bbfdm_set_fault_message(struct dmctx *ctx, const char *format, ...)
{
	va_list args;
	int len = DM_STRLEN(ctx->fault_msg);

	if (len)
		return;

	va_start(args, format);
	vsnprintf(ctx->fault_msg, sizeof(ctx->fault_msg), format, args); // flawfinder: ignore
	va_end(args);
}

static int bbfdm_validate_string_length(struct dmctx *ctx, const char *value, int min_length, int max_length)
{
	if ((min_length > 0) && (DM_STRLEN(value) < min_length)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' value must be greater than '%d'.", value, min_length);
		return -1;
	}

	if ((max_length > 0) && (DM_STRLEN(value) > max_length)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' value must be lower than '%d'.", value, max_length);
		return -1;
	}

	return 0;
}

static int bbfdm_validate_string_enumeration(struct dmctx *ctx, const char *value, char *enumeration[])
{
	for (; *enumeration; enumeration++) {
		if (DM_STRCMP(*enumeration, value) == 0)
			return 0;
	}

	bbfdm_set_fault_message(ctx, "List enumerations did not include '%s' value", value);
	return -1;
}

static int bbfdm_validate_string_pattern(struct dmctx *ctx, const char *value, char *pattern[])
{
	for (; *pattern; pattern++) {
		if (match(value, *pattern, 0, NULL))
			return 0;
	}

	bbfdm_set_fault_message(ctx, "List patterns did not match '%s' value", value);
	return -1;
}

int bbfdm_validate_string(struct dmctx *ctx, const char *value, int min_length, int max_length, char *enumeration[], char *pattern[])
{
	/* check size */
	if (bbfdm_validate_string_length(ctx, value, min_length, max_length))
		return -1;

	/* check enumeration */
	if (enumeration && bbfdm_validate_string_enumeration(ctx, value, enumeration))
		return -1;

	/* check pattern */
	if (pattern && bbfdm_validate_string_pattern(ctx, value, pattern))
		return -1;

	return 0;
}

int bbfdm_validate_boolean(struct dmctx *ctx, const char *value)
{
	/* check format */
	if ((value[0] == '1' && value[1] == '\0') ||
		(value[0] == '0' && value[1] == '\0') ||
		!strcasecmp(value, "true") ||
		!strcasecmp(value, "false")) {
		return 0;
	}

	bbfdm_set_fault_message(ctx, "'%s' value must be ['boolean']. Acceptable values are ['true', 'false', '1', '0'].", value);
	return -1;
}

int bbfdm_validate_unsignedInt(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		unsigned long ui_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtoul(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtoul(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		ui_val = strtoul(value, &endval, 10);

		if ((*value == '-') || (*endval != 0) || (errno != 0)) {
			bbfdm_set_fault_message(ctx, "'%s' value is not a real unsigned integer", value);
			return -1;
		}

		if (r_args[i].min && r_args[i].max) {

			if (minval == maxval) {
				if (strlen(value) == minval)
					break;
			} else {
				if (ui_val >= minval && ui_val <= maxval)
					break;
			}

			if (i == r_args_size - 1) {
				bbfdm_set_fault_message(ctx, "'%s' value is not within range (min: '%s' max: '%s')", value, r_args[i].min, r_args[i].max);
				return -1;
			}

			continue;
		}

		/* check size */
		if (r_args[i].min && ui_val < minval) {
			bbfdm_set_fault_message(ctx, "'%lu' value must be greater than '%s'.", ui_val, r_args[i].min);
			return -1;
		}

		if (r_args[i].max && ui_val > maxval) {
			bbfdm_set_fault_message(ctx, "'%lu' value must be lower than '%s'.", ui_val, r_args[i].max);
			return -1;
		}

		if (ui_val > (unsigned int)UINT_MAX) {
			bbfdm_set_fault_message(ctx, "'%lu' value must be lower than '%u'.", ui_val, (unsigned int)UINT_MAX);
			return -1;
		}
	}

	return 0;
}

int bbfdm_validate_int(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		long i_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtol(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtol(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		i_val = strtol(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) {
			bbfdm_set_fault_message(ctx, "'%s' value is not a real integer", value);
			return -1;
		}

		if (r_args[i].min && r_args[i].max) {

			if (i_val >= minval && i_val <= maxval)
				break;

			if (i == r_args_size - 1) {
				bbfdm_set_fault_message(ctx, "'%s' value is not within range (min: '%s' max: '%s')", value, r_args[i].min, r_args[i].max);
				return -1;
			}

			continue;
		}

		/* check size */
		if (r_args[i].min && i_val < minval) {
			bbfdm_set_fault_message(ctx, "'%ld' value must be greater than '%s'.", i_val, r_args[i].min);
			return -1;
		}

		if (r_args[i].max && i_val > maxval) {
			bbfdm_set_fault_message(ctx, "'%ld' value must be lower than '%s'.", i_val, r_args[i].max);
			return -1;
		}

		if ((i_val < INT_MIN) || (i_val > INT_MAX)) {
			bbfdm_set_fault_message(ctx, "'%ld' value is not within range (min: '%d' max: '%d')", i_val, INT_MIN, INT_MAX);
			return -1;
		}
	}

	return 0;
}

int bbfdm_validate_unsignedLong(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		unsigned long ul_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtoul(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtoul(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		ul_val = strtoul(value, &endval, 10);

		if ((*value == '-') || (*endval != 0) || (errno != 0)) {
			bbfdm_set_fault_message(ctx, "'%s' value is not a real unsigned long", value);
			return -1;
		}

		if (r_args[i].min && r_args[i].max) {

			if (ul_val >= minval && ul_val <= maxval)
				break;

			if (i == r_args_size - 1) {
				bbfdm_set_fault_message(ctx, "'%s' value is not within range (min: '%s' max: '%s')", value, r_args[i].min, r_args[i].max);
				return -1;
			}

			continue;
		}

		/* check size */
		if (r_args[i].min && ul_val < minval) {
			bbfdm_set_fault_message(ctx, "'%lu' value must be greater than '%s'.", ul_val, r_args[i].min);
			return -1;
		}

		if (r_args[i].max && ul_val > maxval) {
			bbfdm_set_fault_message(ctx, "'%lu' value must be lower than '%s'.", ul_val, r_args[i].max);
			return -1;
		}

		if (ul_val > (unsigned long)ULONG_MAX) {
			bbfdm_set_fault_message(ctx, "'%lu' value must be lower than '%lu'.", ul_val, (unsigned long)ULONG_MAX);
			return -1;
		}
	}

	return 0;
}

int bbfdm_validate_long(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size)
{
	if (!value || value[0] == 0) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check size for each range */
	for (int i = 0; i < r_args_size; i++) {
		long u_val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtol(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtol(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		u_val = strtol(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) {
			bbfdm_set_fault_message(ctx, "'%s' value is not a real long", value);
			return -1;
		}

		if (r_args[i].min && r_args[i].max) {

			if (u_val >= minval && u_val <= maxval)
				break;

			if (i == r_args_size - 1) {
				bbfdm_set_fault_message(ctx, "'%s' value is not within range (min: '%s' max: '%s')", value, r_args[i].min, r_args[i].max);
				return -1;
			}

			continue;
		}

		/* check size */
		if (r_args[i].min && u_val < minval) {
			bbfdm_set_fault_message(ctx, "'%ld' value must be greater than '%s'.", u_val, r_args[i].min);
			return -1;
		}

		if (r_args[i].max && u_val > maxval) {
			bbfdm_set_fault_message(ctx, "'%ld' value must be lower than '%s'.", u_val, r_args[i].max);
			return -1;
		}
	}

	return 0;
}

int bbfdm_validate_dateTime(struct dmctx *ctx, const char *value)
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
	if (!p || *p == '\0' || value[DM_STRLEN(value) - 1] != 'Z') {
		bbfdm_set_fault_message(ctx, "'%s' value must be ['dateTime']. Acceptable formats are ['XXXX-XX-XXTXX:XX:XXZ', 'XXXX-XX-XXTXX:XX:XX.XXXZ', 'XXXX-XX-XXTXX:XX:XX.XXXXXXZ'].", value);
		return -1;
	}

	int num_parsed = sscanf(p, "%dZ", &m);
	if (num_parsed != 1 || (DM_STRLEN(p) != 7 && DM_STRLEN(p) != 4)) {
		bbfdm_set_fault_message(ctx, "'%s' value must be ['dateTime']. Acceptable formats are ['XXXX-XX-XXTXX:XX:XXZ', 'XXXX-XX-XXTXX:XX:XX.XXXZ', 'XXXX-XX-XXTXX:XX:XX.XXXXXXZ'].", value);
		return -1;
	}

	return 0;
}

int bbfdm_validate_hexBinary(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check format */
	for (i = 0; i < DM_STRLEN(value); i++) {
		if (!isxdigit(value[i])) {
			bbfdm_set_fault_message(ctx, "'%s' value is not a real hexBinary", value);
			return -1;
		}
	}

	/* check size */
	for (i = 0; i < r_args_size; i++) {

		if (r_args[i].min && r_args[i].max && (DM_STRTOL(r_args[i].min) == DM_STRTOL(r_args[i].max))) {

			if (DM_STRLEN(value) == 2 * DM_STRTOL(r_args[i].max))
				break;

			if (i == r_args_size - 1) {
				bbfdm_set_fault_message(ctx, "The length of '%s' value is not within range (min: '%s' max: '%s')", value, r_args[i].min, r_args[i].max);
				return -1;
			}

			continue;
		}

		if (r_args[i].min && (DM_STRLEN(value) < DM_STRTOL(r_args[i].min))) {
			bbfdm_set_fault_message(ctx, "The length of '%s' value must be greater than '%s'.", value, r_args[i].min);
			return -1;
		}

		if (r_args[i].max && (DM_STRLEN(value) > DM_STRTOL(r_args[i].max))) {
			bbfdm_set_fault_message(ctx, "The length of '%s' value must be lower than '%s'.", value, r_args[i].max);
			return -1;
		}
	}

	return 0;
}

static int bbfdm_validate_size_list(struct dmctx *ctx, int min_item, int max_item, int nbr_item)
{
	if (((min_item > 0) && (max_item > 0) && (min_item == max_item) && (nbr_item == 2 * min_item)))
		return 0;

	if ((min_item > 0) && (nbr_item < min_item)) {
		bbfdm_set_fault_message(ctx, "The number of item of '%d' list must be greater than '%d'.", nbr_item, min_item);
		return -1;
	}

	if ((max_item > 0) && (nbr_item > max_item)) {
		bbfdm_set_fault_message(ctx, "The number of item of '%d' list must be lower than '%d'.", nbr_item, max_item);
		return -1;
	}

	return 0;
}

int bbfdm_validate_string_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])
{
	char *pch, *pchr;
	int nbr_item = 0;

	if (!value) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' list must be lower than '%d'.", value, max_size);
		return -1;
	}

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
		if (bbfdm_validate_string(ctx, pch, min, max, enumeration, pattern))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (bbfdm_validate_size_list(ctx, min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int bbfdm_validate_unsignedInt_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *tmp, *saveptr;
	int nbr_item = 0;

	if (!value) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' list must be lower than '%d'.", value, max_size);
		return -1;
	}

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (tmp = strtok_r(buf, ",", &saveptr); tmp != NULL; tmp = strtok_r(NULL, ",", &saveptr)) {
		if (bbfdm_validate_unsignedInt(ctx, tmp, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (bbfdm_validate_size_list(ctx, min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int bbfdm_validate_int_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *token, *pchr;
	int nbr_item = 0;

	if (!value) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' list must be lower than '%d'.", value, max_size);
		return -1;
	}

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (token = strtok_r(buf, ",", &pchr); token != NULL; token = strtok_r(NULL, ",", &pchr)) {
		if (bbfdm_validate_int(ctx, token, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (bbfdm_validate_size_list(ctx, min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int bbfdm_validate_unsignedLong_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *token, *tmp;
	int nbr_item = 0;

	if (!value) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' list must be lower than '%d'.", value, max_size);
		return -1;
	}

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (token = strtok_r(buf, ",", &tmp); token != NULL; token = strtok_r(NULL, ",", &tmp)) {
		if (bbfdm_validate_unsignedLong(ctx, token, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (bbfdm_validate_size_list(ctx, min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int bbfdm_validate_long_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *pch, *saveptr;
	int nbr_item = 0;

	if (!value) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' list must be lower than '%d'.", value, max_size);
		return -1;
	}

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &saveptr); pch != NULL; pch = strtok_r(NULL, ",", &saveptr)) {
		if (bbfdm_validate_long(ctx, pch, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (bbfdm_validate_size_list(ctx, min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int bbfdm_validate_hexBinary_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *pch, *spch;
	int nbr_item = 0;

	if (!value) {
		bbfdm_set_fault_message(ctx, "Value should not be blank.");
		return -1;
	}

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size)) {
		bbfdm_set_fault_message(ctx, "The length of '%s' list must be lower than '%d'.", value, max_size);
		return -1;
	}

	/* copy data in buffer */
	char buf[strlen(value)+1];
	DM_STRNCPY(buf, value, sizeof(buf));

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		if (bbfdm_validate_hexBinary(ctx, pch, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (bbfdm_validate_size_list(ctx, min_item, max_item, nbr_item))
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

int create_empty_file(const char *file_name)
{
	if (!file_name)
		return -1;

	// Skip creating the file if it already exists
	if (file_exists(file_name))
		return 0;

	FILE *fp = fopen(file_name, "w");
	if (fp == NULL)
		return -1;

	fclose(fp);
	return 0;
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
	const char *base64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
	char *out = (char *)dmcalloc(decsize + 1, sizeof(char));

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

void remove_char(char *str, const char c)
{
	int i = 0, j = 0;

	if (DM_STRLEN(str) == 0)
		return;

	while (str[i]) {
		if (str[i] != c)
			str[j++] = str[i];
		i++;
	}

	str[j] = 0;
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

/**
 * Replace all occurrences of a substring in a given string with another substring.
 *
 * @param input_str The input string where replacements will be performed.
 * @param old_substr The substring to be replaced.
 * @param new_substr The substring to replace `old_substr`.
 * @param result_str The buffer to store the result. If NULL, memory will be allocated.
 * @param buffer_len The length of the buffer. If `result_str` is not NULL, this should be the size of the buffer.
 * @return A pointer to the result string. If `result_str` is provided, it will point to `result_str`, otherwise, it will be dynamically allocated.
 */
char *replace_str(const char *input_str, const char *old_substr, const char *new_substr, char *result_str, size_t buffer_len)
{
	if (result_str && buffer_len > 0)
		result_str[0] = 0;

	if (!input_str || !old_substr || !new_substr || (result_str && buffer_len == 0))
		return NULL;

	size_t input_str_len = strlen(input_str);
	size_t old_substr_len = strlen(old_substr);
	size_t new_substr_len = strlen(new_substr);
	size_t occurrences = 0;

	if (input_str_len == 0) {
		// Handle case where the input string is empty
		if (result_str && buffer_len > 0) {
			return result_str;
		} else {
			return strdup("");
		}
	}

	if (old_substr_len == 0) {
		// Handle case where the input substring is empty
		if (result_str && buffer_len > 0) {
			snprintf(result_str, buffer_len, "%s", input_str);
			return result_str;
		} else {
			return strdup(input_str);
		}
	}

	// Count occurrences of old_substr in input_str
	for (size_t i = 0; i < input_str_len; i++) {
		if (strstr(&input_str[i], old_substr) == &input_str[i]) {
			occurrences++;
			i += old_substr_len;
		}
	}

	size_t new_str_len = input_str_len + occurrences * (new_substr_len - old_substr_len) + 1;

	if (result_str && buffer_len > 0 && new_str_len > buffer_len) {
		// Buffer size is too small
		return NULL;
	}

	// Allocate memory only if result_str is not provided
	char *result = result_str ? result_str : (char *)calloc(new_str_len, sizeof(char));

	if (!result) {
		// Memory allocation failed
		return NULL;
	}

	size_t i = 0;
	while (*input_str) {
		char *tmp = strstr(input_str, old_substr);
		if (tmp == input_str) {
			// Replace old_substr with new_substr
			strncpy(&result[i], new_substr, new_substr_len);
			i += new_substr_len;
			input_str += old_substr_len;
		} else if (tmp) {
			// Copy characters from input_str to result until the match
			size_t len = tmp - input_str;
			strncpy(&result[i], input_str, len);
			i += len;
			input_str += len;
		} else {
			// No more occurrences, copy the remaining characters
			result[i++] = *input_str++;
		}
	}
	result[i] = '\0';

	return result;
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

int dm_buf_to_file(const char *buf, const char *filename)
{
	FILE *file;
	int ret = -1;

	if (buf == NULL || filename == NULL)
		return ret;

	file = fopen(filename, "w");
	if (file) {
		ret = fputs(buf, file);
		fclose(file);
	}

	return ret;
}

int dm_file_to_buf(const char *filename, char *buf, size_t buf_size)
{
	FILE *file;
	int ret = -1;

	file = fopen(filename, "r");
	if (file) {
		ret = fread(buf, 1, buf_size - 1, file);
		fclose(file);
	}
	buf[ret > 0 ? ret : 0] = '\0';
	return ret;
}

int dm_file_copy(const char *src, const char *dst)
{
	size_t n;
	char buf[1024];
	int ret = -1;
	FILE *file_src = NULL, *file_dst = NULL;

	if (DM_STRLEN(src) == 0 || DM_STRLEN(dst) == 0) {
		return -1;
	}

	file_src = fopen(src, "r");
	if (!file_src)
		goto exit;

	file_dst = fopen(dst, "w");
	if (!file_dst)
		goto exit;

	while ((n = fread(buf, 1, sizeof(buf), file_src)) > 0) {
		if (fwrite(buf, 1, n, file_dst) != n)
			goto exit;
	}

	ret = 0;
exit:
	if (file_dst)
		fclose(file_dst);
	if (file_src)
		fclose(file_src);
	return ret;
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

char *diagnostics_get_option(const char *sec_name, const char *option)
{
	char *value = NULL;
	dmuci_get_option_value_string_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, &value);
	return value;
}

char *diagnostics_get_option_fallback_def(const char *sec_name, const char *option, const char *default_value)
{
	char *value = diagnostics_get_option(sec_name, option);
	if (DM_STRLEN(value) == 0)
		value = dmstrdup(default_value);

	return value;
}

void diagnostics_set_option(const char *sec_name, const char *option, const char *value)
{
	check_create_dmmap_package(DMMAP_DIAGNOSTIGS);
	struct uci_section *section = dmuci_walk_section_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
	if (!section)
		dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, "", sec_name);

	dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, value);
}

void diagnostics_reset_state(const char *sec_name)
{
	char *diag_state = diagnostics_get_option(sec_name, "DiagnosticState");
	if (strcmp(diag_state, "Requested") != 0) {
		diagnostics_set_option(sec_name, "DiagnosticState", "None");
	}
}

char *diagnostics_get_interface_name(struct dmctx *ctx, const char *value)
{
	char *linker = NULL;

	if (!value || *value == 0)
		return "";

	if (strncmp(value, "Device.IP.Interface.", 20) != 0)
		return "";

	bbfdm_operate_reference_linker(ctx, value, &linker);
	return linker ? linker : "";
}

long download_file(char *file_path, const char *url, const char *username, const char *password)
{
	long res_code = 0;

	if (!file_path || !url)
		return -1;

	if (strncmp(url, FILE_URI, strlen(FILE_URI)) == 0) {

		const char *curr_path = (!strncmp(url, FILE_LOCALHOST_URI, strlen(FILE_LOCALHOST_URI))) ? url + strlen(FILE_LOCALHOST_URI) : url + strlen(FILE_URI);

		if (!file_exists(curr_path))
			return -1;

		DM_STRNCPY(file_path, curr_path, 256);
	} else {

		CURL *curl = curl_easy_init();
		if (curl) {
			curl_easy_setopt(curl, CURLOPT_URL, url);
			if (username) curl_easy_setopt(curl, CURLOPT_USERNAME, username);
			if (password) curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600);

			FILE *fp = fopen(file_path, "wb");
			if (fp) {
				curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
				curl_easy_perform(curl);
				fclose(fp);
			}

			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_code);
			curl_easy_cleanup(curl);
		}
	}

	return res_code;
}

long upload_file(const char *file_path, const char *url, const char *username, const char *password)
{
	long res_code = 0;

	if (!file_path || !url)
		return -1;

	if (strncmp(url, FILE_URI, strlen(FILE_URI)) == 0) {
		char dst_path[2046] = {0};
		char buff[BUFSIZ] = {0};
		FILE *sfp, *dfp;
		size_t n;

		sfp = fopen(file_path, "rb");
		if (sfp == NULL) {
			return -1;
		}

		snprintf(dst_path, sizeof(dst_path), "%s", url + strlen(FILE_URI));
		dfp = fopen(dst_path, "wb");
		if (dfp == NULL) {
			fclose(sfp);
			return -1;
		}

		while ((n = fread(buff, 1, BUFSIZ, sfp)) != 0) {
			fwrite(buff, 1, n, dfp);
		}

		fclose(sfp);
		fclose(dfp);
	} else {
		CURL *curl = curl_easy_init();
		if (curl) {
			curl_easy_setopt(curl, CURLOPT_URL, url);
			if (username) curl_easy_setopt(curl, CURLOPT_USERNAME, username);
			if (password) curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600);
			curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

			FILE *fp = fopen(file_path, "rb");
			if (fp) {
				curl_easy_setopt(curl, CURLOPT_READDATA, fp);
				curl_easy_perform(curl);
				fclose(fp);
			}

			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_code);
			curl_easy_cleanup(curl);
		}
	}

	return res_code;
}

int get_proto_type(const char *proto)
{
	int type = BBFDM_BOTH;

	if (proto) {
		if (is_str_eq("cwmp", proto))
			type = BBFDM_CWMP;
		else if (is_str_eq("usp", proto))
			type = BBFDM_USP;
		else
			type = BBFDM_BOTH;
	}

	return type;
}

bool is_str_eq(const char *s1, const char *s2)
{
	if (strcmp(s1, s2) == 0)
		return true;

	return false;
}

