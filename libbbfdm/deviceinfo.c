/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "sys/statvfs.h"
#include <libgen.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "deviceinfo.h"

extern struct list_head global_memhead;

LIST_HEAD(process_list);
static int process_count = 0;

#define PROCPS_BUFSIZE 1024
#define CONFIG_BACKUP "/tmp/bbf_config_backup"
#define MAX_TIME_WINDOW 5

struct process_entry {
	struct list_head list;

	char command[256];
	char state[16];
	char pid[8];
	char size[8];
	char priority[8];
	char cputime[8];
};

typedef struct jiffy_counts_t {
	unsigned long long usr, nic, sys, idle;
	unsigned long long iowait, irq, softirq, steal;
	unsigned long long total;
	unsigned long long busy;
} jiffy_counts_t;

struct Supported_Data_Models
{
	char url[128];
	char urn[128];
	char features[128];
};

struct Supported_Data_Models Data_Models[] = {
{"http://www.broadband-forum.org/cwmp/tr-181-2-14-1.xml","urn:broadband-forum-org:tr-181-2-14-1","IP,Wireless,Firewall,NAT,DHCP,QoS,DNS,GRE,UPnP"},
{"http://www.broadband-forum.org/cwmp/tr-104-2-0-2.xml","urn:broadband-forum-org:tr-104-2-0-2", "VoiceService"},
{"http://www.broadband-forum.org/cwmp/tr-143-1-1-0.xml","urn:broadband-forum-org:tr-143-1-1-0", "Ping,TraceRoute,Download,Upload,UDPecho,ServerSelectionDiag"},
{"http://www.broadband-forum.org/cwmp/tr-157-1-3-0.xml","urn:broadband-forum-org:tr-157-1-3-0", "Bulkdata,SoftwareModules"},
};

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static void get_jif_val(jiffy_counts_t *p_jif)
{
	FILE *file = NULL;
	char line[128];
	int ret;

	if ((file = fopen("/proc/stat", "r"))) {
		while(fgets(line, sizeof(line), file) != NULL)
		{
			remove_new_line(line);
			ret = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &p_jif->usr, &p_jif->nic, &p_jif->sys, &p_jif->idle,
				&p_jif->iowait, &p_jif->irq, &p_jif->softirq, &p_jif->steal);

			if (ret >= 4) {
				p_jif->total = p_jif->usr + p_jif->nic + p_jif->sys + p_jif->idle
					+ p_jif->iowait + p_jif->irq + p_jif->softirq + p_jif->steal;

				p_jif->busy = p_jif->total - p_jif->idle - p_jif->iowait;
				break;
			}
		}
		fclose(file);
	}
}

static unsigned int get_cpu_load(jiffy_counts_t *prev_jif, jiffy_counts_t *cur_jif)
{
	unsigned total_diff, cpu;

	total_diff = (unsigned)(cur_jif->total - prev_jif->total);

	if (total_diff == 0)
		total_diff = 1;

	cpu = 100 * (unsigned)(cur_jif->busy - prev_jif->busy) / total_diff;

	return cpu;
}

static unsigned int get_cpu_usage(void)
{
	jiffy_counts_t prev_jif = {0};
	jiffy_counts_t cur_jif = {0};

	get_jif_val(&prev_jif);
	usleep(100000);
	get_jif_val(&cur_jif);

	return get_cpu_load(&prev_jif, &cur_jif);
}

static bool is_update_process_allowed(void)
{
	char *tr069_status = NULL;

	if (dmubus_object_method_exists("tr069")) {
		struct uci_section *s = NULL, *stmp = NULL;
		uci_path_foreach_sections_safe(varstate, "icwmp", "sess_status", stmp, s) {
			dmuci_get_value_by_section_string(s, "current_status", &tr069_status);
		}
	}

	if (tr069_status == NULL)
		goto end;

	if (strcmp(tr069_status, "running") == 0) {
		return false;
	}

end:
	return true;
}

static char *get_proc_state(char state)
{
	switch(state) {
		case 'R':
			return "Running";
		case 'S':
			return "Sleeping";
		case 'T':
			return "Stopped";
		case 'D':
			return "Uninterruptible";
		case 'Z':
			return "Zombie";
		case 'I':
			return "Idle";
	};

	return "Idle";
}

static struct process_entry *check_entry_exists(const char *pid)
{
	struct process_entry *entry = NULL;

	list_for_each_entry(entry, &process_list, list) {
		if (DM_STRCMP(entry->pid, pid) == 0)
			return entry;
	}

	return NULL;
}

static void check_killed_process(void)
{
	struct process_entry *entry = NULL;
	struct process_entry *entry_tmp = NULL;
	char fstat[32];

	list_for_each_entry_safe(entry, entry_tmp, &process_list, list) {

		snprintf(fstat, sizeof(fstat), "/proc/%s/stat", entry->pid);
		if (file_exists(fstat))
			continue;

		list_del(&entry->list);
		dmfree(entry);
	}
}

static void procps_get_cmdline(char *buf, int bufsz, const char *pid, const char *comm)
{
	int sz;
	char filename[270];

	snprintf(filename, sizeof(filename), "/proc/%s/cmdline", pid);
	sz = dm_file_to_buf(filename, buf, bufsz);
	if (sz > 0) {
		const char *base;
		int comm_len;

		while (--sz >= 0 && buf[sz] == '\0')
			continue;
		/* Prevent basename("process foo/bar") = "bar" */
		strchrnul(buf, ' ')[0] = '\0';
		base = basename(buf); /* before we replace argv0's NUL with space */
		while (sz >= 0) {
			if ((unsigned char)(buf[sz]) < ' ')
				buf[sz] = ' ';
			sz--;
		}
		if (base[0] == '-') /* "-sh" (login shell)? */
			base++;

		/* If comm differs from argv0, prepend "{comm} ".
		 * It allows to see thread names set by prctl(PR_SET_NAME).
		 */
		if (!comm)
			return;
		comm_len = strlen(comm);
		/* Why compare up to comm_len?
		 * Well, some processes rewrite argv, and use _spaces_ there
		 * while rewriting. (KDE is observed to do it).
		 * I prefer to still treat argv0 "process foo bar"
		 * as 'equal' to comm "process".
		 */
		if (strncmp(base, comm, comm_len) != 0) {
			comm_len += 3;
			if (bufsz > comm_len)
				memmove(buf + comm_len, buf, bufsz - comm_len);
			snprintf(buf, bufsz, "{%s}", comm);
			if (bufsz <= comm_len)
				return;
			buf[comm_len - 1] = ' ';
			buf[bufsz - 1] = '\0';
		}
	} else {
		snprintf(buf, bufsz, "[%s]", comm ? comm : "?");
	}
}

static void init_processes(void)
{
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	struct stat stats = {0};
	char buf[PROCPS_BUFSIZE];
	char fstat[288];
	char command[256];
	char comm[32];
	char bsize[32];
	char cputime[32];
	char priori[32];
	char *comm1 = NULL;
	char *comm2 = NULL;
	char state;
	unsigned long stime;
	unsigned long utime;
	unsigned long vsize;
	int priority, n;
	int curr_process_idx = 0;

	if (!is_update_process_allowed())
		return;

	check_killed_process();

	dir = opendir("/proc");
	if (dir == NULL)
		return;

	while ((entry = readdir(dir)) != NULL) {
		struct process_entry *pentry = NULL;
		struct process_entry *pentry_exits = NULL;

		int digit = entry->d_name[0] - '0';
		if (digit < 0 || digit > 9)
			continue;

		snprintf(fstat, sizeof(fstat), "/proc/%s/stat", entry->d_name);
		if (stat(fstat, &stats))
			continue;

		n = dm_file_to_buf(fstat, buf, PROCPS_BUFSIZE);
		if (n < 0)
			continue;

		comm2 = strrchr(buf, ')'); /* split into "PID (cmd" and "<rest>" */
		if (!comm2) /* sanity check */
		  continue;

		comm2[0] = '\0';
		comm1 = strchr(buf, '(');
		if (!comm1) /* sanity check */
		  continue;

		DM_STRNCPY(comm, comm1 + 1, sizeof(comm));

		n = sscanf(comm2 + 2,			  /* Flawfinder: ignore */ \
				"%c %*u "                 /* state, ppid */
				"%*u %*u %*d %*s "        /* pgid, sid, tty, tpgid */
				"%*s %*s %*s %*s %*s "    /* flags, min_flt, cmin_flt, maj_flt, cmaj_flt */
				"%lu %lu "                /* utime, stime */
				"%*u %*u %d "             /* cutime, cstime, priority */
				"%*d "                    /* niceness */
				"%*s %*s "                /* timeout, it_real_value */
				"%*s "                    /* start_time */
				"%lu "                    /* vsize */
				,
				&state,
				&utime, &stime,
				&priority,
				&vsize
			  );

		if (n != 5)
			continue;

		procps_get_cmdline(command, sizeof(command), entry->d_name, comm);
		curr_process_idx++;

		snprintf(cputime, sizeof(cputime), "%lu", ((stime / sysconf(_SC_CLK_TCK)) + (utime / sysconf(_SC_CLK_TCK))) * 1000);
		snprintf(bsize, sizeof(bsize), "%lu", vsize >> 10);
		snprintf(priori, sizeof(priori), "%u", (unsigned)round((priority + 100) * 99 / 139));

		if (process_count == 0 || !(pentry_exits = check_entry_exists(entry->d_name))) {

			pentry = dm_dynamic_calloc(&global_memhead, 1, sizeof(struct process_entry));
			if (!pentry)
				return;

			list_add_tail(&pentry->list, &process_list);
		}

		if (pentry_exits)
			pentry = pentry_exits;

		DM_STRNCPY(pentry->pid, entry->d_name, sizeof(pentry->pid));
		DM_STRNCPY(pentry->command, command, sizeof(pentry->command));
		DM_STRNCPY(pentry->size, bsize, sizeof(pentry->size));
		DM_STRNCPY(pentry->priority, priori, sizeof(pentry->priority));
		DM_STRNCPY(pentry->cputime, cputime, sizeof(pentry->cputime));
		DM_STRNCPY(pentry->state, get_proc_state(state), sizeof(pentry->state));
	}

	closedir(dir);
	process_count = curr_process_idx;
}

static bool check_file_dir(char *name)
{
	DIR *dir = NULL;
	struct dirent *d_file = NULL;

	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if (DM_STRCMP(name, d_file->d_name) == 0) {
				closedir(dir);
				return true;
			}
		}
		closedir(dir);
	}
	return false;
}

static int get_number_of_cpus(void)
{
	char val[16];

	dm_read_sysfs_file("/sys/devices/system/cpu/present", val, sizeof(val));
	char *max = DM_STRCHR(val, '-');
	return max ? DM_STRTOL(max+1)+1 : 0;
}

static bool get_response_code_status(const char *url, int response_code)
{
	if ((strncmp(url, HTTP_URI, strlen(HTTP_URI)) == 0 && response_code != 200) ||
		(strncmp(url, FTP_URI, strlen(FTP_URI)) == 0 && response_code != 226) ||
		(strncmp(url, FILE_URI, strlen(FILE_URI)) == 0 && response_code != 0) ||
		(strncmp(url, HTTP_URI, strlen(HTTP_URI)) && strncmp(url, FTP_URI, strlen(FTP_URI)) && strncmp(url, FILE_URI, strlen(FILE_URI)))) {
		return false;
	}

	return true;
}

static void send_transfer_complete_event(const char *command, const char *obj_path, const char *transfer_url,
	char *fault_string, time_t start_t, time_t complete_t,const char *commandKey, const char *transfer_type)
{
	char start_time[32] = {0};
	char complete_time[32] = {0};
	struct blob_buf bb;

	strftime(start_time, sizeof(start_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&start_t));
	strftime(complete_time, sizeof(complete_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&complete_t));

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "name", "Device.LocalAgent.TransferComplete!");
	void *arr = blobmsg_open_array(&bb, "input");

	fill_blob_param(&bb, "Command", command, DMT_TYPE[DMT_STRING], 0);
	if(commandKey)
		fill_blob_param(&bb, "CommandKey", commandKey, DMT_TYPE[DMT_STRING], 0);
	else
		fill_blob_param(&bb, "CommandKey", "", DMT_TYPE[DMT_STRING], 0);

	fill_blob_param(&bb, "Requestor", "", DMT_TYPE[DMT_STRING], 0);
	fill_blob_param(&bb, "TransferType", transfer_type, DMT_TYPE[DMT_STRING], 0);
	fill_blob_param(&bb, "Affected", obj_path, DMT_TYPE[DMT_STRING], 0);
	fill_blob_param(&bb, "TransferURL", transfer_url, DMT_TYPE[DMT_STRING], 0);
	fill_blob_param(&bb, "StartTime", start_time, DMT_TYPE[DMT_STRING], 0);
	fill_blob_param(&bb, "CompleteTime", complete_time, DMT_TYPE[DMT_STRING], 0);

	if (DM_STRLEN(fault_string) == 0) {
		fill_blob_param(&bb, "FaultCode", "0", DMT_TYPE[DMT_STRING], 0);
	} else {
		fill_blob_param(&bb, "FaultCode", "7000", DMT_TYPE[DMT_STRING], 0);
	}

	fill_blob_param(&bb, "FaultString", fault_string, DMT_TYPE[DMT_STRING], 0);
	blobmsg_close_array(&bb, arr);

	dmubus_call_blob_msg_set("bbfdm", "notify_event", &bb);

	blob_buf_free(&bb);
}

const bool validate_file_system_size(const char *file_size)
{
	if (file_size && *file_size) {
		unsigned long f_size = strtoul(file_size, NULL, 10);
		unsigned long fs_available_size = file_system_size("/tmp", FS_SIZE_AVAILABLE);

		if (fs_available_size < f_size)
			return false;
	}

	return true;
}


const bool validate_hash_value(const char *algo, const char *file_path, const char *checksum)
{
	unsigned char buffer[1024 * 16] = {0};
	char hash[BUFSIZ] = {0};
	bool res = false;
	unsigned int bytes = 0;
	FILE *file;

	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];

	file = fopen(file_path, "rb");
	if (!file)
		return false;

	md = EVP_get_digestbyname(algo);
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);

	if (md == NULL)
		goto end;

	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
		EVP_DigestUpdate(mdctx, buffer, bytes);
	}

	bytes = 0;
	EVP_DigestFinal_ex(mdctx, md_value, &bytes);

	for (int i = 0; i < bytes; i++)
		snprintf(&hash[i * 2], sizeof(hash) - (i * 2), "%02x", md_value[i]);

	if (DM_STRCMP(hash, checksum) == 0)
		res = true;

end:
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();

	fclose(file);
	return res;
}

const bool validate_checksum_value(const char *file_path, const char *checksum_algorithm, const char *checksum)
{
	if (checksum && *checksum) {

		if (strcmp(checksum_algorithm, "SHA-1") == 0)
			return validate_hash_value("SHA1", file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-224") == 0)
			return validate_hash_value("SHA224", file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-256") == 0)
			return validate_hash_value("SHA256", file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-384") == 0)
			return validate_hash_value("SHA384", file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-512") == 0)
			return validate_hash_value("SHA512", file_path, checksum);
		else
			return false;
	}

	return true;
}

int bbf_config_backup(const char *url, const char *username, const char *password,
		char *config_name, const char *command, const char *obj_path)
{
	int res = 0;
	char fault_msg[128] = {0};
	time_t complete_time = 0;
	time_t start_time = time(NULL);

	// Export config file to backup file
	if (dmuci_export_package(config_name, CONFIG_BACKUP)) {
		snprintf(fault_msg, sizeof(fault_msg), "Failed to export the configurations");
		res = -1;
		goto end;
	}

	// Upload the config file
	long res_code = upload_file(CONFIG_BACKUP, url, username, password);
	complete_time = time(NULL);

	// Check if the upload operation was successful
	if (!get_response_code_status(url, res_code)) {
		res = -1;
		snprintf(fault_msg, sizeof(fault_msg), "Upload operation is failed, fault code (%ld)", res_code);
	}

end:
	// Send the transfer complete event
	send_transfer_complete_event(command, obj_path, url, fault_msg, start_time, complete_time, NULL, "Upload");

	// Remove temporary file
	if (file_exists(CONFIG_BACKUP) && remove(CONFIG_BACKUP))
		res = -1;

	return res;
}


int bbf_config_restore(const char *url, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *command, const char *obj_path)
{
	char config_restore[256] = {0};
	int res = 0;
	char fault_msg[128] = {0};
	time_t complete_time = 0;
	time_t start_time = time(NULL);

	DM_STRNCPY(config_restore, "/tmp/bbf_config_restore", sizeof(config_restore));

	// Check the file system size if there is sufficient space for downloading the config file
	if (!validate_file_system_size(file_size)) {
		snprintf(fault_msg, sizeof(fault_msg), "Available memory space is less than required for the operation");
		res = -1;
		goto end;
	}

	// Download the firmware image
	long res_code = download_file(config_restore, url, username, password);
	complete_time = time(NULL);

	// Check if the download operation was successful
	if (!get_response_code_status(url, res_code)) {
		snprintf(fault_msg, sizeof(fault_msg), "Upload operation is failed, fault code (%ld)", res_code);
		res = -1;
		goto end;
	}

	// Validate the CheckSum value according to its algorithm
	if (!validate_checksum_value(config_restore, checksum_algorithm, checksum)) {
		snprintf(fault_msg, sizeof(fault_msg), "Checksum of the downloaded file is mismatched");
		res = -1;
		goto end;
	}

	// Apply config file
	if (dmuci_import(NULL, config_restore)) {
		snprintf(fault_msg, sizeof(fault_msg), "Failed to import the configurations");
		res = -1;
	}

end:
	// Send the transfer complete event
	send_transfer_complete_event(command, obj_path, url, fault_msg, start_time, complete_time, NULL, "Download");

	// Remove temporary file
	if (file_exists(config_restore) && strncmp(url, FILE_URI, strlen(FILE_URI)) && remove(config_restore))
		res = -1;

	return res;
}

struct sysupgrade_ev_data {
	const char *bank_id;
	bool status;
};

static void dmubus_receive_sysupgrade(struct ubus_context *ctx, struct ubus_event_handler *ev,
				const char *type, struct blob_attr *msg)
{
	struct dmubus_event_data *data;
	struct blob_attr *msg_attr;

	if (!msg || !ev)
		return;

	data = container_of(ev, struct dmubus_event_data, ev);
	if (data == NULL)
		return;

	struct sysupgrade_ev_data *ev_data = (struct sysupgrade_ev_data *)data->ev_data;
	if (ev_data == NULL)
		return;

	size_t msg_len = (size_t)blobmsg_data_len(msg);
	__blob_for_each_attr(msg_attr, blobmsg_data(msg), msg_len) {
		if (DM_STRCMP("bank_id", blobmsg_name(msg_attr)) == 0) {
			char *attr_val = (char *)blobmsg_data(msg_attr);
			if (DM_STRCMP(attr_val, ev_data->bank_id) != 0)
				return;
		}

		if (DM_STRCMP("status", blobmsg_name(msg_attr)) == 0) {
			char *attr_val = (char *)blobmsg_data(msg_attr);
			if (DM_STRCMP(attr_val, "Downloading") == 0)
				return;
			else if (DM_STRCMP(attr_val, "Available") == 0)
				ev_data->status = true;
			else
				ev_data->status = false;

		}
	}

	uloop_end();
	return;
}

static int bbf_fw_image_download(const char *url, const char *auto_activate, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *bank_id, const char *command, const char *obj_path, const char *commandKey, char *keep)
{
	char fw_image_path[256] = {0};
	json_object *json_obj = NULL;
	bool activate = false, valid = false;
	int res = 0;
	char fault_msg[128] = {0};
	time_t complete_time = 0;
	time_t start_time = time(NULL);

	DM_STRNCPY(fw_image_path, "/tmp/firmware-XXXXXX", sizeof(fw_image_path));

	// Check the file system size if there is sufficient space for downloading the firmware image
	if (!validate_file_system_size(file_size)) {
		res = -1;
		snprintf(fault_msg, sizeof(fault_msg), "Available memory space is lower than required for downloading");
		goto end;
	}

	res = mkstemp(fw_image_path);
	if (res == -1) {
		snprintf(fault_msg, sizeof(fault_msg), "Operation failed due to some internal failure");
		goto end;
	} else {
		close(res); // close the fd, as only filename required
		res = 0;
	}

	// Download the firmware image
	long res_code = download_file(fw_image_path, url, username, password);
	complete_time = time(NULL);

	// Check if the download operation was successful
	if (!get_response_code_status(url, res_code)) {
		snprintf(fault_msg, sizeof(fault_msg), "Download operation is failed, fault code (%ld)", res_code);
		res = -1;
		goto end;
	}

	// Validate the CheckSum value according to its algorithm
	if (!validate_checksum_value(fw_image_path, checksum_algorithm, checksum)) {
		res = -1;
		snprintf(fault_msg, sizeof(fault_msg), "Checksum of the file is not matched with the specified value");
		goto end;
	}

	string_to_bool(auto_activate, &activate);
	char *act = (activate) ? "1" : "0";

	dmubus_call_blocking("system", "validate_firmware_image", UBUS_ARGS{{"path", fw_image_path, String}}, 1, &json_obj);
	if (json_obj == NULL) {
		res = -1;
		snprintf(fault_msg, sizeof(fault_msg), "Failed in validation of the file");
		goto end;
	}

	char *val = dmjson_get_value(json_obj, 1, "valid");
	string_to_bool(val, &valid);
	json_object_put(json_obj);
	json_obj = NULL;
	if (valid == false) {
		snprintf(fault_msg, sizeof(fault_msg), "File is not a valid firmware image");
		res = -1;
		goto end;
	}

	// default state is to preserve the config over firmware upgrades
	char *keep_config = DM_STRLEN((char *)keep) ? keep : "1";

	// Apply Firmware Image
	dmubus_call_blocking("fwbank", "upgrade", UBUS_ARGS{{"path", fw_image_path, String}, {"auto_activate", act, Boolean}, {"bank", bank_id, Integer}, {"keep_settings", keep_config, Boolean}}, 4, &json_obj);
	if (json_obj == NULL) {
		res = 1;
		snprintf(fault_msg, sizeof(fault_msg), "Internal error occurred when applying the firmware");
		goto end;
	}

	struct sysupgrade_ev_data ev_data = {
		.bank_id = bank_id,
		.status = false,
	};

	dmubus_wait_for_event("sysupgrade", 120, &ev_data, dmubus_receive_sysupgrade, NULL);

	if (ev_data.status == false) {
		res = 1;
		snprintf(fault_msg, sizeof(fault_msg), "Failed to apply the downloaded image file");
		goto end;
	}

	// Schedule a device Reboot, if auto activation is true
	if (activate) {
		bbfdm_task_fork(_exec_reboot, NULL, NULL, NULL);
	}

end:
	// Send the transfer complete event
	send_transfer_complete_event(command, obj_path, url, fault_msg, start_time, complete_time, commandKey, "Download");

	// Remove temporary file if ubus upgrade failed and file exists
	if (!json_obj && file_exists(fw_image_path) && strncmp(url, FILE_URI, strlen(FILE_URI))) {
		remove(fw_image_path);
		res = -1;
	}

	if (json_obj != NULL)
		json_object_put(json_obj);

	return res;
}

static int dmmap_synchronizeVcfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;
	DIR *dir;
	struct dirent *d_file;

	sysfs_foreach_file(DEFAULT_CONFIG_DIR, dir, d_file) {

		if(d_file->d_name[0] == '.')
			continue;

		if (!is_dmmap_section_exist_eq("dmmap", "vcf", "name", d_file->d_name)) {
			dmuci_add_section_bbfdm("dmmap", "vcf", &s);
			dmuci_set_value_by_section(s, "name", d_file->d_name);
			dmuci_set_value_by_section(s, "backup_restore", "1");
		}
	}

	if (dir)
		closedir (dir);

	uci_path_foreach_sections_safe(bbfdm, "dmmap", "vcf", stmp, s) {
		char *name;

		dmuci_get_value_by_section_string(s, "name", &name);
		if (check_file_dir(name) == 0)
			dmuci_delete_by_section_bbfdm(s, NULL, NULL);
	}

	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseVcfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data curr_data = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeVcfInst(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap", "vcf", s) {

		curr_data.config_section = s;

		inst = handle_instance(dmctx, parent_node, s, "vcf_instance", "vcf_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDeviceInfoProcessorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int nbr_cpus = get_number_of_cpus();
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int i;

	for (i = 0; i < nbr_cpus; i++) {
		inst = handle_instance_without_section(dmctx, parent_node, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDeviceInfoSupportedDataModelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(Data_Models); i++) {
		inst = handle_instance_without_section(dmctx, parent_node, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&Data_Models[i], inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDeviceInfoFirmwareImageInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *bank_obj = NULL, *arrobj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{0}, 0, &res);

	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {

		curr_data.json_object = bank_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseProcessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct process_entry *entry = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0;

	init_processes();
	list_for_each_entry(entry, &process_list, list) {

		curr_data.additional_data = entry;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDeviceInfoRebootsRebootInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data curr_data = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_foreach_sections("deviceinfo", "reboot", s) {

		curr_data.config_section = s;

		inst = handle_instance(dmctx, parent_node, s, "reboot_instance", "reboot_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.DeviceInfo.Manufacturer!UCI:cwmp/cpe,cpe/manufacturer*/
static int get_device_manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp","cpe","manufacturer", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "Manufacturer", value);

	return 0;
}

/*#Device.DeviceInfo.ManufacturerOUI!UCI:cwmp/cpe,cpe/manufacturer_oui*/
static int get_device_manufactureroui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "manufacturer_oui", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "ManufacturerOUI", value);

	return 0;
}

/*#Device.DeviceInfo.ProductClass!UCI:cwmp/cpe,cpe/product_class*/
static int get_device_productclass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "product_class", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "ProductClass", value);

	return 0;
}

static int get_device_serialnumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "serial_number", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "SerialNumber", value);

	return 0;
}

static int get_device_softwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "software_version", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "SoftwareVersion", value);

	return 0;
}

static int get_device_active_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *bank_obj = NULL, *arrobj = NULL;
	char linker[16] = {0}, *id = NULL;
	int i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {
		char *active = dmjson_get_value(bank_obj, 1, "active");
		if (active && DM_LSTRCMP(active, "true") == 0) {
			id = dmjson_get_value(bank_obj, 1, "id");
			break;
		}
	}

	if (DM_STRLEN(id) == 0) {
		*value = dmstrdup("");
		return 0;
	}

	snprintf(linker, sizeof(linker), "cpe-%s", id);
	_bbfdm_get_references(ctx, "Device.DeviceInfo.FirmwareImage.", "Alias", linker, value);
	return 0;
}

static int get_device_boot_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *bank_obj = NULL, *arrobj = NULL;
	char linker[16] = {0}, *id = NULL;
	int i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {
		char *boot = dmjson_get_value(bank_obj, 1, "boot");
		if (boot && DM_LSTRCMP(boot, "true") == 0) {
			id = dmjson_get_value(bank_obj, 1, "id");
			break;
		}
	}

	if (DM_STRLEN(id) == 0) {
		*value = dmstrdup("");
		return 0;
	}

	snprintf(linker, sizeof(linker), "cpe-%s", id);
	_bbfdm_get_references(ctx, "Device.DeviceInfo.FirmwareImage.", "Alias", linker, value);
	return 0;
}

static int set_device_boot_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.DeviceInfo.FirmwareImage.", NULL};
	struct dm_reference reference = {0};

	bbfdm_get_reference_linker(ctx, value, &reference);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			if (DM_STRLEN(reference.value)) {
				struct uci_section *dmmap_s = NULL;
				json_object *res = NULL;
				char *available = NULL;

				char *bank_id = DM_STRCHR(reference.value, '-'); // Get bank id 'X' which is linker from Alias prefix 'cpe-X'
				if (!bank_id)
					return FAULT_9001;

				get_dmmap_section_of_config_section_cont("dmmap_fw_image", "fw_image", "id", bank_id + 1, &dmmap_s);
				dmuci_get_value_by_section_string(dmmap_s, "available", &available);
				if (DM_LSTRCMP(available, "false") == 0)
					return FAULT_9001;

				dmubus_call("fwbank", "set_bootbank", UBUS_ARGS{{"bank", bank_id + 1, Integer}}, 1, &res);
				char *success = dmjson_get_value(res, 1, "success");
				if (DM_LSTRCMP(success, "true") != 0)
					return FAULT_9001;

			}
			break;
	}
	return 0;
}

static int get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "HardwareVersion", value);
	return 0;
}

static int get_device_devicecategory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "DeviceCategory", value);
	return 0;
}

static int get_device_additionalhardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "AdditionalHardwareVersion", value);
	return 0;
}

static int get_device_additionalsoftwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "AdditionalSoftwareVersion", value);
	return 0;
}

/*#Device.DeviceInfo.ModelName!UCI:cwmp/cpe,cpe/model_name*/
static int get_device_modelname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "model_name", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "ModelName", value);
	return 0;
}

/*#Device.DeviceInfo.Description!UCI:cwmp/cpe,cpe/description*/
static int get_device_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "description", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "Description", value);
	return 0;
}

/*#Device.DeviceInfo.UpTime!PROCFS:/proc/uptime*/
static int get_device_info_uptime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uptime();
	return 0;
}

static int get_device_info_firstusedate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("time", "global", "first_use_date", value);
	return 0;
}

/*#Device.DeviceInfo.ProvisioningCode!UCI:cwmp/cpe,cpe/provisioning_code*/
static int get_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp = NULL, *provisioning_code = NULL, *dhcp_provisioning_code = NULL;
	bool discovery = false;

	dmuci_get_option_value_string("cwmp", "acs", "dhcp_discovery", &dhcp);
	dmuci_get_option_value_string("cwmp", "cpe", "provisioning_code", &provisioning_code);
	dmuci_get_option_value_string("cwmp", "cpe", "dhcp_provisioning_code", &dhcp_provisioning_code);

	discovery = dmuci_string_to_boolean(dhcp);

	if ((discovery == true) && (DM_STRLEN(dhcp_provisioning_code) != 0))
		*value = dhcp_provisioning_code;
	else
		*value = provisioning_code;

	return 0;
}

static int set_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "provisioning_code", value);
			return 0;
	}
	return 0;
}

static int get_DeviceInfo_ProcessorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDeviceInfoProcessorInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DeviceInfo_VendorConfigFileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseVcfInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DeviceInfo_SupportedDataModelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%d", ARRAY_SIZE(Data_Models));
	return 0;
}

static int get_DeviceInfo_FirmwareImageNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDeviceInfoFirmwareImageInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_deviceinfo_cid (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "CID", value);
	return 0;
}

static int get_deviceinfo_friendlyname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "FriendlyName", value);
	return 0;
}

static int get_deviceinfo_pen (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "PEN", value);
	return 0;
}

static int get_deviceinfo_modelnumber (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "ModelNumber", value);
	return 0;
}

static int get_DeviceInfo_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("system", "@system[0]", "hostname", value);
	return 0;
}

static int set_DeviceInfo_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 255, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "hostname", value);
			break;
	}
	return 0;
}

static int get_vcf_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "name", value);
	return 0;
}

static int get_vcf_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "version", value);
	return 0;
}

static int get_vcf_date(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	DIR *dir = NULL;
	struct dirent *d_file = NULL;
	char *config_name = NULL;

	*value = dmstrdup("0001-01-01T00:00:00Z");
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "name", &config_name);
	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if (config_name && DM_STRCMP(config_name, d_file->d_name) == 0) {
				char date[sizeof("AAAA-MM-JJTHH:MM:SSZ")], path[280] = {0};
				struct stat attr;

				snprintf(path, sizeof(path), "%s%s", DEFAULT_CONFIG_DIR, d_file->d_name);
				stat(path, &attr);
				strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%SZ", gmtime(&attr.st_mtime));
				*value = dmstrdup(date);
			}
		}
		closedir (dir);
	}
	return 0;
}

static int get_vcf_backup_restore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "backup_restore", value);
	return 0;
}

static int get_vcf_desc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "description", value);
	return 0;
}

static int get_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->config_section, "vcf_alias", instance, value);
}

static int set_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->config_section, "vcf_alias", instance, value);
}

static int get_DeviceInfoProcessor_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "processor", "processor_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DeviceInfoProcessor_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "processor", "processor_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "processor", &dmmap);
			dmuci_set_value_by_section(dmmap, "processor_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DeviceInfoProcessor_Architecture(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct utsname utsname;

	if (uname(&utsname) < 0)
		return 0;

	if (DM_LSTRSTR(utsname.machine, "arm") || DM_LSTRSTR(utsname.machine, "aarch64")) {
		*value = dmstrdup("arm");
	} else if(DM_LSTRSTR(utsname.machine, "mips")) {
		union {
		    uint16_t value;
		    uint8_t bytes[2];
		} endian_test = { .bytes = { 0x00, 0xff } };

		const bool is_big_endian = (endian_test.value < 0x100);

		*value = (is_big_endian) ? dmstrdup("mipseb") : dmstrdup("mipsel");
	} else
		*value = dmstrdup(utsname.machine);
	return 0;
}

static int get_DeviceInfoSupportedDataModel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "data_model", "data_model_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DeviceInfoSupportedDataModel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "data_model", "data_model_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "data_model", &dmmap);
			dmuci_set_value_by_section(dmmap, "data_model_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DeviceInfoSupportedDataModel_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct Supported_Data_Models *)data)->url);
	return 0;
}

static int get_DeviceInfoSupportedDataModel_URN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct Supported_Data_Models *)data)->urn);
	return 0;
}

static int get_DeviceInfoSupportedDataModel_Features(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct Supported_Data_Models *)data)->features);
	return 0;
}

static int get_DeviceInfoFirmwareImage_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *id = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "id");
	dmasprintf(value, "cpe-%s", id ? id : instance);
	return 0;
}

static int set_DeviceInfoFirmwareImage_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			bbfdm_set_fault_message(ctx, "Internal designated unique identifier, not allowed to update");
			return FAULT_9007;
	}
	return 0;
}

static int get_DeviceInfoFirmwareImage_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name;

	name = dmstrdup(dmjson_get_value(((struct dm_data *)data)->json_object, 1, "fwver"));
	if (DM_STRLEN(name) > 64 ) {
		name[64] = '\0';
	}

	*value = name;
	return 0;
}

static int get_DeviceInfoFirmwareImage_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "swver");
	return 0;
}

static int get_DeviceInfoFirmwareImage_Available(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	char *id = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "id");

	uci_path_foreach_option_eq(bbfdm, "dmmap_fw_image", "fw_image", "id", id, s) {
		dmuci_get_value_by_section_string(s, "available", value);
		break;
	}

	if ((*value)[0] == '\0')
		*value = dmstrdup("true");
	return 0;
}

static int set_DeviceInfoFirmwareImage_Available(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *id = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			if (!b) {
				char *boot = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "boot");
				char *active = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "active");
				if (DM_LSTRCMP(boot, "true") == 0 || DM_LSTRCMP(active, "true") == 0)
					return FAULT_9001;
			}

			id = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "id");

			uci_path_foreach_option_eq(bbfdm, "dmmap_fw_image", "fw_image", "id", id, s) {
				dmuci_set_value_by_section_bbfdm(s, "available", b ? "true" : "false");
				return 0;
			}

			dmuci_add_section_bbfdm("dmmap_fw_image", "fw_image", &dmmap);
			dmuci_set_value_by_section(dmmap, "id", id);
			dmuci_set_value_by_section(dmmap, "available", b ? "true" : "false");
			break;
	}
	return 0;
}

static int get_DeviceInfoFirmwareImage_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "status");
	return 0;
}

static int get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = dmstrdup("0"));
	char *total = dmjson_get_value(res, 2, "memory", "total");
	dmasprintf(value, "%lu", DM_STRTOUL(total) / 1024);
	return 0;
}

static int get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = dmstrdup("0"));
	char *free = dmjson_get_value(res, 2, "memory", "free");
	dmasprintf(value, "%lu", DM_STRTOUL(free) / 1024);
	return 0;
}

static int get_memory_status_total_persistent(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct statvfs dinfo;
	if (statvfs("/overlay/", &dinfo) == 0) {
		unsigned int total = (dinfo.f_bsize * dinfo.f_blocks) / 1024;
		dmasprintf(value, "%u", total);
	} else {
		*value = dmstrdup("0");
	}

	return 0;
}

static int get_memory_status_free_persistent(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct statvfs dinfo;
	if (statvfs("/overlay/", &dinfo) == 0) {
		unsigned int free = (dinfo.f_bsize * dinfo.f_bavail) / 1024;
		dmasprintf(value, "%u", free);
	} else {
		*value = dmstrdup("0");
	}

	return 0;
}

static int get_process_cpu_usage(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%u", get_cpu_usage());
	return 0;
}

static int get_process_number_of_entries(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseProcessEntriesInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)((struct dm_data *)data)->additional_data)->pid : "";
	return 0;
}

static int get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)((struct dm_data *)data)->additional_data)->command : "";
	return 0;
}

static int get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)((struct dm_data *)data)->additional_data)->size : "";
	return 0;
}

static int get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)((struct dm_data *)data)->additional_data)->priority : "";
	return 0;
}

static int get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)((struct dm_data *)data)->additional_data)->cputime : "";
	return 0;
}

static int get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)((struct dm_data *)data)->additional_data)->state : "";
	return 0;
}

static int get_DeviceInfoReboots_BootCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("deviceinfo", "globals", "boot_count", value);
	return 0;
}

static int get_DeviceInfoReboots_CurrentVersionBootCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("deviceinfo", "globals", "curr_version_boot_count", value);
	return 0;
}

static int get_DeviceInfoReboots_WatchdogBootCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("deviceinfo", "globals", "watchdog_boot_count", value);
	return 0;
}

static int get_DeviceInfoReboots_ColdBootCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("deviceinfo", "globals", "cold_boot_count", value);
	return 0;
}

static int get_DeviceInfoReboots_WarmBootCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("deviceinfo", "globals", "warm_boot_count", value);
	return 0;
}

static int get_DeviceInfoReboots_MaxRebootEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("deviceinfo", "globals", "max_reboot_entries", "3");
	return 0;
}

static int set_DeviceInfoReboots_MaxRebootEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *tmp_s = NULL;
	int max_entries = DM_STRTOL(value);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (max_entries == 0) {
				// Delete all sections if value is "0"
				uci_foreach_sections_safe("deviceinfo", "reboot", tmp_s, s) {
					dmuci_delete_by_section(s, NULL, NULL);
				}
			} else if (max_entries > 0) {
				// Step 1: Count total sections
				int total_sections = 0;

				uci_foreach_sections_safe("deviceinfo", "reboot", tmp_s, s) {
					total_sections++;
				}

				// Step 2: Calculate how many sections to delete (earliest sections)
				int to_delete = total_sections - max_entries;

				// Step 3: Delete the earliest sections that exceed max_entries
				if (to_delete > 0) {
					int idx = 0;
					uci_foreach_sections_safe("deviceinfo", "reboot", tmp_s, s) {
						if (idx++ < to_delete) {
							dmuci_delete_by_section(s, NULL, NULL);
						}
					}
				}
			}

			dmuci_set_value("deviceinfo", "globals", "max_reboot_entries", value);
			break;
	}
	return 0;
}

static int get_DeviceInfoReboots_RebootNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDeviceInfoRebootsRebootInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DeviceInfoRebootsReboot_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->config_section, "reboot_alias", instance, value);
}

static int set_DeviceInfoRebootsReboot_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->config_section, "reboot_alias", instance, value);
}

static int get_DeviceInfoRebootsReboot_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "time_stamp", value);
	return 0;
}

static int get_DeviceInfoRebootsReboot_FirmwareUpdated(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "firmware_updated", value);
	return 0;
}

static int get_DeviceInfoRebootsReboot_Cause(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "cause", value);
	return 0;
}

static int get_DeviceInfoRebootsReboot_Reason(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "reason", value);
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static operation_args vendor_config_file_backup_args = {
	.in = (const char *[]) {
		"URL",
		"Username",
		"Password",
		NULL
	}
};

static int get_operate_args_DeviceInfoVendorConfigFile_Backup(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&vendor_config_file_backup_args;
	return 0;
}

static int operate_DeviceInfoVendorConfigFile_Backup(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	const char *backup_command = "Backup()";
	char backup_path[256] = {'\0'};
	char *vcf_name = NULL;

	char *ret = DM_STRRCHR(refparam, '.');
	if (!ret)
		return USP_FAULT_INVALID_ARGUMENT;

	if ((ret - refparam + 2) < sizeof(backup_path))
		snprintf(backup_path, ret - refparam + 2, "%s", refparam);

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	if (url[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	char *pass = dmjson_get_value((json_object *)value, 1, "Password");

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "name", &vcf_name);

	int res = bbf_config_backup(url, user, pass, vcf_name, backup_command, backup_path);

	return res ? USP_FAULT_COMMAND_FAILURE : 0;
}

static operation_args vendor_config_file_restore_args = {
	.in = (const char *[]) {
		"URL",
		"Username",
		"Password",
		"FileSize",
		"TargetFileName",
		"CheckSumAlgorithm",
		"CheckSum",
		NULL
	}
};

static int get_operate_args_DeviceInfoVendorConfigFile_Restore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&vendor_config_file_restore_args;
	return 0;
}

static int operate_DeviceInfoVendorConfigFile_Restore(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	const char *restore_command = "Restore()";
	char restore_path[256] = {'\0'};

	char *ret = DM_STRRCHR(refparam, '.');
	if (!ret)
		return USP_FAULT_INVALID_ARGUMENT;

	if ((ret - refparam + 2) < sizeof(restore_path))
		snprintf(restore_path, ret - refparam + 2, "%s", refparam);

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	if (url[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	char *pass = dmjson_get_value((json_object *)value, 1, "Password");
	char *file_size = dmjson_get_value((json_object *)value, 1, "FileSize");
	char *checksum_algorithm = dmjson_get_value((json_object *)value, 1, "CheckSumAlgorithm");
	char *checksum = dmjson_get_value((json_object *)value, 1, "CheckSum");

	int res = bbf_config_restore(url, user, pass, file_size, checksum_algorithm, checksum, restore_command, restore_path);

	return res ? USP_FAULT_COMMAND_FAILURE : 0;
}

static operation_args firmware_image_download_args = {
	.in = (const char *[]) {
		"URL",
		"AutoActivate",
		"Username",
		"Password",
		"FileSize",
		"CheckSumAlgorithm",
		"CheckSum",
		"CommandKey",
		BBF_VENDOR_PREFIX"KeepConfig",
		NULL
	}
};

static int get_operate_args_DeviceInfoFirmwareImage_Download(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&firmware_image_download_args;
	return 0;
}

static int operate_DeviceInfoFirmwareImage_Download(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	const char *command = "Download()";
	char obj_path[256] = {0};

	char *ret = DM_STRRCHR(refparam, '.');
	if (!ret)
		return USP_FAULT_INVALID_ARGUMENT;

	if ((ret - refparam + 2) < sizeof(obj_path))
		snprintf(obj_path, ret - refparam + 2, "%s", refparam);

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	char *auto_activate = dmjson_get_value((json_object *)value, 1, "AutoActivate");
	if (url[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	// Assuming auto activate as false, if not provided by controller, in case of strict validation,
	// this should result into a fault
	if (DM_STRLEN(auto_activate) == 0)
		auto_activate = dmstrdup("0");

	char *username = dmjson_get_value((json_object *)value, 1, "Username");
	char *password = dmjson_get_value((json_object *)value, 1, "Password");
	char *file_size = dmjson_get_value((json_object *)value, 1, "FileSize");
	char *checksum_algorithm = dmjson_get_value((json_object *)value, 1, "CheckSumAlgorithm");
	char *checksum = dmjson_get_value((json_object *)value, 1, "CheckSum");
	char *commandKey = dmjson_get_value((json_object *)value, 1, "CommandKey");
	char *keep_config = dmjson_get_value((json_object *)value, 1, BBF_VENDOR_PREFIX"KeepConfig");

	char *bank_id = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "id");

	int res = bbf_fw_image_download(url, auto_activate, username, password, file_size, checksum_algorithm, checksum, bank_id, command, obj_path, commandKey, keep_config);

	if (res == 1) {
		bbfdm_set_fault_message(ctx, "Firmware validation failed");
	}

	return res ? USP_FAULT_COMMAND_FAILURE : 0;
}

static operation_args firmware_image_activate_args = {
	.in = (const char *[]) {
		
		"TimeWindow.{i}.Start",
		"TimeWindow.{i}.End",
		"TimeWindow.{i}.Mode",
		"TimeWindow.{i}.UserMessage",
		"TimeWindow.{i}.MaxRetries",
		NULL
	}
};

static int get_operate_args_DeviceInfoFirmwareImage_Activate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&firmware_image_activate_args;
	return 0;
}

void _exec_reboot(const void *arg1, void *arg2)
{
	char config_name[16] = {0};

	snprintf(config_name, sizeof(config_name), "%s", "deviceinfo");

	// Set last_reboot_cause to 'RemoteReboot' because the upcoming reboot will be initiated by USP Operate
	dmuci_set_value(config_name, "globals", "last_reboot_cause", "RemoteReboot");
	dmuci_commit_package(config_name);

	sleep(3);
	dmubus_call_set("rpc-sys", "reboot", UBUS_ARGS{0}, 0);
	sleep(5); // Wait for reboot to happen
	BBF_ERR("Reboot call failed with rpc-sys, trying again with system");
	dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0);
	sleep(5); // Wait for reboot
	BBF_ERR("Reboot call failed!!!");

	// Set last_reboot_cause to empty because there is a problem in the system reboot
	dmuci_set_value(config_name, "globals", "last_reboot_cause", "");
	dmuci_commit_package(config_name);
}

static int operate_DeviceInfoFirmwareImage_Activate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
#define CRONTABS_ROOT "/etc/crontabs/root"
#define ACTIVATE_HANDLER_FILE "/usr/share/bbfdm/scripts/bbf_activate_handler.sh"

	char *FW_Mode[] = {"AnyTime", "Immediately", "WhenIdle", "ConfirmationNeeded", NULL};
	char *start_time[MAX_TIME_WINDOW] = {0};
	char *end_time[MAX_TIME_WINDOW] = {0};
	char *mode[MAX_TIME_WINDOW] = {0};
	char *user_message[MAX_TIME_WINDOW] = {0};
	char *max_retries[MAX_TIME_WINDOW] = {0};
	int res = 0, last_idx = -1;

	for (int i = 0; i < MAX_TIME_WINDOW; i++) {
		char buf[32] = {0};

		snprintf(buf, sizeof(buf), "TimeWindow.%d.Start", i + 1);
		start_time[i] = dmjson_get_value((json_object *)value, 1, buf);

		snprintf(buf, sizeof(buf), "TimeWindow.%d.End", i + 1);
		end_time[i] = dmjson_get_value((json_object *)value, 1, buf);

		snprintf(buf, sizeof(buf), "TimeWindow.%d.Mode", i + 1);
		mode[i] = dmjson_get_value((json_object *)value, 1, buf);

		snprintf(buf, sizeof(buf), "TimeWindow.%d.UserMessage", i + 1);
		user_message[i] = dmjson_get_value((json_object *)value, 1, buf);

		snprintf(buf, sizeof(buf), "TimeWindow.%d.MaxRetries", i + 1);
		max_retries[i] = dmjson_get_value((json_object *)value, 1, buf);

		if (!DM_STRLEN(start_time[i]))
			break;

		if (!DM_STRLEN(end_time[i]) || !DM_STRLEN(mode[i]))
			return USP_FAULT_INVALID_ARGUMENT;

		if (bbfdm_validate_unsignedInt(ctx, start_time[i], RANGE_ARGS{{NULL,NULL}}, 1))
			return USP_FAULT_INVALID_ARGUMENT;

		if (bbfdm_validate_unsignedInt(ctx, end_time[i], RANGE_ARGS{{NULL,NULL}}, 1))
			return USP_FAULT_INVALID_ARGUMENT;

		if (DM_STRLEN(max_retries[i]) && bbfdm_validate_int(ctx, max_retries[i], RANGE_ARGS{{"-1","10"}}, 1))
			return USP_FAULT_INVALID_ARGUMENT;

		if (bbfdm_validate_string(ctx, mode[i], -1, -1, FW_Mode, NULL))
			return USP_FAULT_INVALID_ARGUMENT;

		if (DM_STRTOL(start_time[i]) > DM_STRTOL(end_time[i]))
			return USP_FAULT_INVALID_ARGUMENT;

		if (i != 0 && DM_STRTOL(end_time[i - 1]) > DM_STRTOL(start_time[i]))
			return USP_FAULT_INVALID_ARGUMENT;

		last_idx++;
	}

	char *bank_id = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "id");
	if (!DM_STRLEN(bank_id))
		return USP_FAULT_COMMAND_FAILURE;

	if (DM_STRLEN(start_time[0])) {
		FILE *file = fopen(CRONTABS_ROOT, "a");
		if (!file)
			return USP_FAULT_COMMAND_FAILURE;

		for (int i = 0; i < MAX_TIME_WINDOW && DM_STRLEN(start_time[i]); i++) {
			char buffer[512] = {0};
			time_t t_time = time(NULL);
			long int start_t = (DM_STRTOL(start_time[i]) > 60) ? DM_STRTOL(start_time[i]) : 60;
			t_time += start_t;
			struct tm *tm_local = localtime(&t_time);

			snprintf(buffer, sizeof(buffer), "%d %d %d %d * sh %s '%s' '%s' '%ld' '%d' '%s' '%s'\n",
											tm_local->tm_min,
											tm_local->tm_hour,
											tm_local->tm_mday,
											tm_local->tm_mon + 1,
											ACTIVATE_HANDLER_FILE,
											mode[i],
											bank_id,
											(DM_STRTOL(end_time[i]) - DM_STRTOL(start_time[i])),
											(i == last_idx),
											user_message[i],
											max_retries[i]);

			fprintf(file, "%s", buffer);
		}

		fclose(file);

		res = dmcmd_no_wait("/etc/init.d/cron", 1, "restart");
	} else {
		json_object *json_obj = NULL;

		dmubus_call("fwbank", "set_bootbank", UBUS_ARGS{{"bank", bank_id, Integer}}, 1, &json_obj);
		char *status = dmjson_get_value(json_obj, 1, "success");
		if (strcasecmp(status, "true") != 0)
			return USP_FAULT_COMMAND_FAILURE;

		bbfdm_task_fork(_exec_reboot, NULL, NULL, NULL);
	}

	return res ? USP_FAULT_COMMAND_FAILURE : 0;
}

static int operate_DeviceInfoReboots_RemoveAllReboots(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *tmp_s = NULL;

	uci_foreach_sections_safe("deviceinfo", "reboot", tmp_s, s) {
		dmuci_delete_by_section(s, NULL, NULL);
	}
    return 0;
}

static int operate_DeviceInfoRebootsReboot_Remove(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	dmuci_delete_by_section(((struct dm_data *)data)->config_section, NULL, NULL);
    return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.DeviceInfo. *** */
DMOBJ tDeviceInfoObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"VendorConfigFile", &DMREAD, NULL, NULL, NULL, browseVcfInst, NULL, NULL, NULL, tDeviceInfoVendorConfigFileParams, NULL, BBFDM_BOTH, NULL},
{"MemoryStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoMemoryStatusParams, NULL, BBFDM_BOTH, NULL},
{"ProcessStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoProcessStatusObj, tDeviceInfoProcessStatusParams, NULL, BBFDM_BOTH, NULL},
{"Processor", &DMREAD, NULL, NULL, NULL, browseDeviceInfoProcessorInst, NULL, NULL, NULL, tDeviceInfoProcessorParams, NULL, BBFDM_BOTH, NULL},
{"SupportedDataModel", &DMREAD, NULL, NULL, NULL, browseDeviceInfoSupportedDataModelInst, NULL, NULL, NULL, tDeviceInfoSupportedDataModelParams, NULL, BBFDM_CWMP, NULL},
{"FirmwareImage", &DMREAD, NULL, NULL, "file:/usr/libexec/rpcd/fwbank", browseDeviceInfoFirmwareImageInst, NULL, NULL, NULL, tDeviceInfoFirmwareImageParams, NULL, BBFDM_BOTH, NULL},
{"Reboots", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoRebootsObj, tDeviceInfoRebootsParams, NULL, BBFDM_USP, NULL},
{0}
};

DMLEAF tDeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"DeviceCategory", &DMREAD, DMT_STRING, get_device_devicecategory, NULL, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, get_device_manufacturer, NULL, BBFDM_BOTH},
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_device_manufactureroui, NULL, BBFDM_BOTH},
{"ModelName", &DMREAD, DMT_STRING, get_device_modelname, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, get_device_description, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, get_device_productclass, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_device_serialnumber, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, get_device_hardwareversion, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, get_device_softwareversion, NULL, BBFDM_BOTH},
{"ActiveFirmwareImage", &DMREAD, DMT_STRING, get_device_active_fwimage, NULL, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"BootFirmwareImage", &DMWRITE, DMT_STRING, get_device_boot_fwimage, set_device_boot_fwimage, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"AdditionalHardwareVersion", &DMREAD, DMT_STRING, get_device_additionalhardwareversion, NULL, BBFDM_BOTH},
{"AdditionalSoftwareVersion", &DMREAD, DMT_STRING, get_device_additionalsoftwareversion, NULL, BBFDM_BOTH},
{"ProvisioningCode", &DMWRITE, DMT_STRING, get_device_provisioningcode, set_device_provisioningcode, BBFDM_BOTH},
{"UpTime", &DMREAD, DMT_UNINT, get_device_info_uptime, NULL, BBFDM_BOTH},
{"FirstUseDate", &DMREAD, DMT_TIME, get_device_info_firstusedate, NULL, BBFDM_BOTH},
{"ProcessorNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_ProcessorNumberOfEntries, NULL, BBFDM_BOTH},
{"VendorConfigFileNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_VendorConfigFileNumberOfEntries, NULL, BBFDM_BOTH},
{"SupportedDataModelNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_SupportedDataModelNumberOfEntries, NULL, BBFDM_CWMP},
{"FirmwareImageNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_FirmwareImageNumberOfEntries, NULL, BBFDM_BOTH},
{"CID", &DMREAD, DMT_STRING, get_deviceinfo_cid, NULL, BBFDM_USP},
{"FriendlyName", &DMREAD, DMT_STRING, get_deviceinfo_friendlyname, NULL, BBFDM_USP},
{"PEN", &DMREAD, DMT_STRING, get_deviceinfo_pen, NULL, BBFDM_USP},
{"ModelNumber", &DMREAD, DMT_STRING, get_deviceinfo_modelnumber, NULL, BBFDM_BOTH},
{"HostName", &DMWRITE, DMT_STRING, get_DeviceInfo_HostName, set_DeviceInfo_HostName, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.VendorConfigFile.{i}. *** */
DMLEAF tDeviceInfoVendorConfigFileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_vcf_alias, set_vcf_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_vcf_name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Version", &DMREAD, DMT_STRING, get_vcf_version, NULL, BBFDM_BOTH},
{"Date", &DMREAD, DMT_TIME, get_vcf_date, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, get_vcf_desc, NULL, BBFDM_BOTH},
{"UseForBackupRestore", &DMREAD, DMT_BOOL, get_vcf_backup_restore, NULL, BBFDM_BOTH},
{"Backup()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoVendorConfigFile_Backup, operate_DeviceInfoVendorConfigFile_Backup, BBFDM_USP},
{"Restore()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoVendorConfigFile_Restore, operate_DeviceInfoVendorConfigFile_Restore, BBFDM_USP},
{0}
};

/* *** Device.DeviceInfo.MemoryStatus. *** */
DMLEAF tDeviceInfoMemoryStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Total", &DMREAD, DMT_UNINT, get_memory_status_total, NULL, BBFDM_BOTH},
{"Free", &DMREAD, DMT_UNINT, get_memory_status_free, NULL, BBFDM_BOTH},
{"TotalPersistent", &DMREAD, DMT_UNINT, get_memory_status_total_persistent, NULL, BBFDM_BOTH},
{"FreePersistent", &DMREAD, DMT_UNINT, get_memory_status_free_persistent, NULL, BBFDM_BOTH},
{0}
};
/* *** Device.DeviceInfo.ProcessStatus. *** */
DMOBJ tDeviceInfoProcessStatusObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Process", &DMREAD, NULL, NULL, NULL, browseProcessEntriesInst, NULL, NULL, NULL, tDeviceInfoProcessStatusProcessParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tDeviceInfoProcessStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"CPUUsage", &DMREAD, DMT_UNINT, get_process_cpu_usage, NULL, BBFDM_BOTH},
{"ProcessNumberOfEntries", &DMREAD, DMT_UNINT, get_process_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.ProcessStatus.Process.{i}. *** */
DMLEAF tDeviceInfoProcessStatusProcessParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"PID", &DMREAD, DMT_UNINT, get_process_pid, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Command", &DMREAD, DMT_STRING, get_process_command, NULL, BBFDM_BOTH},
{"Size", &DMREAD, DMT_UNINT, get_process_size, NULL, BBFDM_BOTH},
{"Priority", &DMREAD, DMT_UNINT, get_process_priority, NULL, BBFDM_BOTH},
{"CPUTime", &DMREAD, DMT_UNINT, get_process_cpu_time, NULL, BBFDM_BOTH},
{"State", &DMREAD, DMT_STRING, get_process_state, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.Processor.{i}. *** */
DMLEAF tDeviceInfoProcessorParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoProcessor_Alias, set_DeviceInfoProcessor_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Architecture", &DMREAD, DMT_STRING, get_DeviceInfoProcessor_Architecture, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.SupportedDataModel.{i}. *** */
DMLEAF tDeviceInfoSupportedDataModelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoSupportedDataModel_Alias, set_DeviceInfoSupportedDataModel_Alias, BBFDM_CWMP, DM_FLAG_UNIQUE},
{"URL", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_URL, NULL, BBFDM_CWMP, DM_FLAG_UNIQUE},
{"URN", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_URN, NULL, BBFDM_CWMP},
{"Features", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_Features, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.DeviceInfo.FirmwareImage.{i}. *** */
DMLEAF tDeviceInfoFirmwareImageParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoFirmwareImage_Alias, set_DeviceInfoFirmwareImage_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"Name", &DMREAD, DMT_STRING, get_DeviceInfoFirmwareImage_Name, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_DeviceInfoFirmwareImage_Version, NULL, BBFDM_BOTH},
{"Available", &DMWRITE, DMT_BOOL, get_DeviceInfoFirmwareImage_Available, set_DeviceInfoFirmwareImage_Available, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DeviceInfoFirmwareImage_Status, NULL, BBFDM_BOTH},
{"BootFailureLog", &DMREAD, DMT_STRING, get_empty, NULL, BBFDM_BOTH},
{"Download()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoFirmwareImage_Download, operate_DeviceInfoFirmwareImage_Download, BBFDM_USP},
{"Activate()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoFirmwareImage_Activate, operate_DeviceInfoFirmwareImage_Activate, BBFDM_USP},
{0}
};

/* *** Device.DeviceInfo.Reboots. *** */
DMOBJ tDeviceInfoRebootsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Reboot", &DMREAD, NULL, NULL, NULL, browseDeviceInfoRebootsRebootInst, NULL, NULL, NULL, tDeviceInfoRebootsRebootParams, NULL, BBFDM_USP, NULL},
{0}
};

DMLEAF tDeviceInfoRebootsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"BootCount", &DMREAD, DMT_UNINT, get_DeviceInfoReboots_BootCount, NULL, BBFDM_USP},
{"CurrentVersionBootCount", &DMREAD, DMT_UNINT, get_DeviceInfoReboots_CurrentVersionBootCount, NULL, BBFDM_USP},
{"WatchdogBootCount", &DMREAD, DMT_UNINT, get_DeviceInfoReboots_WatchdogBootCount, NULL, BBFDM_USP},
{"ColdBootCount", &DMREAD, DMT_UNINT, get_DeviceInfoReboots_ColdBootCount, NULL, BBFDM_USP},
{"WarmBootCount", &DMREAD, DMT_UNINT, get_DeviceInfoReboots_WarmBootCount, NULL, BBFDM_USP},
{"MaxRebootEntries", &DMWRITE, DMT_INT, get_DeviceInfoReboots_MaxRebootEntries, set_DeviceInfoReboots_MaxRebootEntries, BBFDM_USP},
{"RebootNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfoReboots_RebootNumberOfEntries, NULL, BBFDM_USP},
{"RemoveAllReboots()", &DMASYNC, DMT_COMMAND, NULL, operate_DeviceInfoReboots_RemoveAllReboots, BBFDM_USP},
{0}
};

/* *** Device.DeviceInfo.Reboots.Reboot.{i}. *** */
DMLEAF tDeviceInfoRebootsRebootParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoRebootsReboot_Alias, set_DeviceInfoRebootsReboot_Alias, BBFDM_USP},
{"TimeStamp", &DMREAD, DMT_TIME, get_DeviceInfoRebootsReboot_TimeStamp, NULL, BBFDM_USP},
{"FirmwareUpdated", &DMREAD, DMT_BOOL, get_DeviceInfoRebootsReboot_FirmwareUpdated, NULL, BBFDM_USP},
{"Cause", &DMREAD, DMT_STRING, get_DeviceInfoRebootsReboot_Cause, NULL, BBFDM_USP},
{"Reason", &DMREAD, DMT_STRING, get_DeviceInfoRebootsReboot_Reason, NULL, BBFDM_USP},
{"Remove()", &DMASYNC, DMT_COMMAND, NULL, operate_DeviceInfoRebootsReboot_Remove, BBFDM_USP},
{0}
};
