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

#include "dmcommon.h"
#include "deviceinfo.h"
#include "sys/statvfs.h"

extern struct list_head global_memhead;

LIST_HEAD(process_list);
static int process_count = 0;

#define PROCPS_BUFSIZE 1024
#define DEF_VENDOR_LOG_FILE "/tmp/.vend_log"

struct process_entry {
	struct list_head list;

	char command[256];
	char state[16];
	char pid[8];
	char size[8];
	char priority[8];
	char cputime[8];
	int instance;
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

static int find_last_instance(void)
{
	if (!list_empty(&process_list)) {
		struct process_entry *entry = list_last_entry(&process_list, struct process_entry, list);
		return entry->instance + 1;
	} else {
		return 1;
	}
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

			pentry = dm_dynamic_malloc(&global_memhead, sizeof(struct process_entry));
			if (!pentry)
				return;

			pentry->instance = find_last_instance();
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
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeVcfInst(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap", "vcf", s) {
		inst = handle_instance(dmctx, parent_node, s, "vcf_instance", "vcf_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseVlfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("system", "system", "dmmap", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "vlf_instance", "vlf_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseDeviceInfoProcessorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	int nbr_cpus = get_number_of_cpus();
	int i;

	for (i = 0; i < nbr_cpus; i++) {
		inst = handle_instance_without_section(dmctx, parent_node, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, NULL, inst) == DM_STOP)
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
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bank_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseProcessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct process_entry *entry = NULL;
	char *inst = NULL;

	init_processes();
	list_for_each_entry(entry, &process_list, list) {

		inst = handle_instance_without_section(dmctx, parent_node, entry->instance);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, entry, inst) == DM_STOP)
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
		*value = "";
		return 0;
	}

	snprintf(linker, sizeof(linker), "cpe-%s", id);
	adm_entry_get_reference_param(ctx, "Device.DeviceInfo.FirmwareImage.*.Alias", linker, value);
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
		*value = "";
		return 0;
	}

	snprintf(linker, sizeof(linker), "cpe-%s", id);
	adm_entry_get_reference_param(ctx, "Device.DeviceInfo.FirmwareImage.*.Alias", linker, value);
	return 0;
}

static int set_device_boot_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.DeviceInfo.FirmwareImage.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

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

static int get_DeviceInfo_VendorLogFileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseVlfInst);
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

static int get_vcf_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

static int get_vcf_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", value);
	return 0;
}

static int get_vcf_date(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	DIR *dir = NULL;
	struct dirent *d_file = NULL;
	char *config_name = NULL;

	*value = "0001-01-01T00:00:00Z";
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", &config_name);
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "backup_restore", value);
	return 0;
}

static int get_vcf_desc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "description", value);
	return 0;
}

static int get_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (struct uci_section *)data, "vcf_alias", instance, value);
}

static int set_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (struct uci_section *)data, "vcf_alias", instance, value);
}

static int get_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "vlf_alias", instance, value);
}

static int set_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "vlf_alias", instance, value);
}

static int get_vlf_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "log_file", value);
	return 0;
}

static int get_vlf_max_size (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int size = 0;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "log_size", value);

	// Value defined in system is in KiB in datamodel this is in bytes, convert the value in bytes
	size = (*value && **value) ? DM_STRTOL(*value) * 1000 : 0;

	dmasprintf(value, "%d", size);
	return 0;
}

static int get_vlf_persistent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
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
		*value = "arm";
	} else if(DM_LSTRSTR(utsname.machine, "mips")) {
		const bool is_big_endian = IS_BIG_ENDIAN;
		*value = (is_big_endian) ? "mipseb" : "mipsel";
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
	char *id = dmjson_get_value((json_object *)data, 1, "id");
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

	name = dmstrdup(dmjson_get_value((json_object *)data, 1, "fwver"));
	if (DM_STRLEN(name) > 64 ) {
		name[64] = '\0';
	}

	*value = name;
	return 0;
}

static int get_DeviceInfoFirmwareImage_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "swver");
	return 0;
}

static int get_DeviceInfoFirmwareImage_Available(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	char *id = dmjson_get_value((json_object *)data, 1, "id");

	uci_path_foreach_option_eq(bbfdm, "dmmap_fw_image", "fw_image", "id", id, s) {
		dmuci_get_value_by_section_string(s, "available", value);
		break;
	}

	if ((*value)[0] == '\0')
		*value = "true";
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
				char *boot = dmjson_get_value((json_object *)data, 1, "boot");
				char *active = dmjson_get_value((json_object *)data, 1, "active");
				if (DM_LSTRCMP(boot, "true") == 0 || DM_LSTRCMP(active, "true") == 0)
					return FAULT_9001;
			}

			id = dmjson_get_value((json_object *)data, 1, "id");

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
	*value = dmjson_get_value((json_object *)data, 1, "status");
	return 0;
}

static int get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	char *total = dmjson_get_value(res, 2, "memory", "total");
	dmasprintf(value, "%lu", DM_STRTOUL(total) / 1024);
	return 0;
}

static int get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
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
		*value = "0";
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
		*value = "0";
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
	*value = data ? ((struct process_entry *)data)->pid : "";
	return 0;
}

static int get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)data)->command : "";
	return 0;
}

static int get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)data)->size : "";
	return 0;
}

static int get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)data)->priority : "";
	return 0;
}

static int get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)data)->cputime : "";
	return 0;
}

static int get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = data ? ((struct process_entry *)data)->state : "";
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static operation_args vendor_log_file_upload_args = {
    .in = (const char *[]) {
        "URL",
        "Username",
        "Password",
        NULL
    }
};

static int get_operate_args_DeviceInfoVendorLogFile_Upload(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&vendor_log_file_upload_args;
	return 0;
}
static int operate_DeviceInfoVendorLogFile_Upload(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char upload_path[256] = {'\0'};
	char upload_command[32] = {'\0'};
	char *vlf_file_path = NULL;

	char *ret = DM_STRRCHR(refparam, '.');
	strncpy(upload_path, refparam, ret - refparam +1);
	DM_STRNCPY(upload_command, ret+1, sizeof(upload_command));

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	char *pass = dmjson_get_value((json_object *)value, 1, "Password");
	char *url = dmjson_get_value((json_object *)value, 1, "URL");

	if (url[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "log_file", &vlf_file_path);

	if (DM_STRLEN(vlf_file_path) == 0) {
		vlf_file_path = DEF_VENDOR_LOG_FILE;
		char cmd[64] = {0};
		snprintf(cmd, sizeof(cmd), "logread > %s", DEF_VENDOR_LOG_FILE);
		if (system(cmd) == -1) {
			return USP_FAULT_COMMAND_FAILURE;
		}
	}

	int res = bbf_upload_log(url, user, pass, vlf_file_path, upload_command, upload_path);

	if (file_exists(DEF_VENDOR_LOG_FILE))
		remove(DEF_VENDOR_LOG_FILE);

	return res ? USP_FAULT_COMMAND_FAILURE : 0;
}

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
	char backup_path[256] = {'\0'};
	char backup_command[32] = {'\0'};
	char *vcf_name = NULL;

	char *ret = DM_STRRCHR(refparam, '.');
	strncpy(backup_path, refparam, ret - refparam +1);
	DM_STRNCPY(backup_command, ret+1, sizeof(backup_command));

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	if (url[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	char *pass = dmjson_get_value((json_object *)value, 1, "Password");

	dmuci_get_value_by_section_string((struct uci_section *)data, "name", &vcf_name);

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
	char restore_path[256] = {'\0'};
	char restore_command[32] = {'\0'};

	char *ret = DM_STRRCHR(refparam, '.');
	DM_STRNCPY(restore_path, refparam, ret - refparam + 2);
	DM_STRNCPY(restore_command, ret+1, sizeof(restore_command));

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
	char obj_path[256] = {'\0'};
	char command[32] = {'\0'};

	char *ret = DM_STRRCHR(refparam, '.');
	DM_STRNCPY(obj_path, refparam, ret - refparam + 2);
	DM_STRNCPY(command, ret+1, sizeof(command));

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	char *auto_activate = dmjson_get_value((json_object *)value, 1, "AutoActivate");
	if (url[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	// Assuming auto activate as false, if not provided by controller, in case of strict validation,
	// this should result into a fault
	if (DM_STRLEN(auto_activate) == 0)
		auto_activate="0";

	char *username = dmjson_get_value((json_object *)value, 1, "Username");
	char *password = dmjson_get_value((json_object *)value, 1, "Password");
	char *file_size = dmjson_get_value((json_object *)value, 1, "FileSize");
	char *checksum_algorithm = dmjson_get_value((json_object *)value, 1, "CheckSumAlgorithm");
	char *checksum = dmjson_get_value((json_object *)value, 1, "CheckSum");
	char *commandKey = dmjson_get_value((json_object *)value, 1, "CommandKey");
	char *keep_config = dmjson_get_value((json_object *)value, 1, BBF_VENDOR_PREFIX"KeepConfig");

	char *bank_id = dmjson_get_value((json_object *)data, 1, "id");

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

static int operate_DeviceInfoFirmwareImage_Activate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
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

	char *bank_id = dmjson_get_value((json_object *)data, 1, "id");
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

		res = dmubus_call_set("rpc-sys", "reboot", UBUS_ARGS{0}, 0);
		sleep(10); // Wait for reboot to happen
	}

	return res ? USP_FAULT_COMMAND_FAILURE : 0;
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
{"VendorLogFile", &DMREAD, NULL, NULL, NULL, browseVlfInst, NULL, NULL, NULL, tDeviceInfoVendorLogFileParams, NULL, BBFDM_BOTH, NULL},
{"SupportedDataModel", &DMREAD, NULL, NULL, NULL, browseDeviceInfoSupportedDataModelInst, NULL, NULL, NULL, tDeviceInfoSupportedDataModelParams, NULL, BBFDM_CWMP, NULL},
{"FirmwareImage", &DMREAD, NULL, NULL, "file:/usr/libexec/rpcd/fwbank", browseDeviceInfoFirmwareImageInst, NULL, NULL, NULL, tDeviceInfoFirmwareImageParams, NULL, BBFDM_BOTH, NULL},
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
{"VendorLogFileNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_VendorLogFileNumberOfEntries, NULL, BBFDM_BOTH},
{"VendorConfigFileNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_VendorConfigFileNumberOfEntries, NULL, BBFDM_BOTH},
{"SupportedDataModelNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_SupportedDataModelNumberOfEntries, NULL, BBFDM_CWMP},
{"FirmwareImageNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_FirmwareImageNumberOfEntries, NULL, BBFDM_BOTH},
{"CID", &DMREAD, DMT_STRING, get_deviceinfo_cid, NULL, BBFDM_USP},
{"PEN", &DMREAD, DMT_STRING, get_deviceinfo_pen, NULL, BBFDM_USP},
{"ModelNumber", &DMREAD, DMT_STRING, get_deviceinfo_modelnumber, NULL, BBFDM_BOTH},
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

/* *** Device.DeviceInfo.VendorLogFile.{i}. *** */
DMLEAF tDeviceInfoVendorLogFileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_vlf_alias, set_vlf_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_vlf_name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"MaximumSize", &DMREAD, DMT_UNINT, get_vlf_max_size, NULL, BBFDM_BOTH},
{"Persistent", &DMREAD, DMT_BOOL, get_vlf_persistent, NULL, BBFDM_BOTH},
{"Upload()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoVendorLogFile_Upload, operate_DeviceInfoVendorLogFile_Upload, BBFDM_USP},
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
