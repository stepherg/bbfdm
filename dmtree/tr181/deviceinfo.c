/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 */

#include "dmdiagnostics.h"
#include "deviceinfo.h"

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

/**************************************************************************
* LINKER
***************************************************************************/
static int get_device_fwimage_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	char *id = dmjson_get_value((json_object *)data, 1, "id");
	dmasprintf(linker, "fw_image:%s", id);
	return 0;
}

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
	db_get_value_string("device", "deviceinfo", "SerialNumber", value);
	return 0;
}

static int get_device_softwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "SoftwareVersion", value);
	return 0;
}

static int get_device_active_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *bank_obj = NULL, *arrobj = NULL;
	char *active = NULL, *id = NULL;
	char linker[32];
	int i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {
		active = dmjson_get_value(bank_obj, 1, "active");
		if (active && strcmp(active, "true") == 0) {
			id = dmjson_get_value(bank_obj, 1, "id");
			break;
		}
	}

	snprintf(linker, sizeof(linker), "fw_image:%s", id ? id : "");
	adm_entry_get_linker_param(ctx, "Device.DeviceInfo.FirmwareImage.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_device_boot_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *bank_obj = NULL, *arrobj = NULL;
	char *boot = NULL, *id = NULL;
	char linker[32];
	int i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {
		boot = dmjson_get_value(bank_obj, 1, "boot");
		if (boot && strcmp(boot, "true") == 0) {
			id = dmjson_get_value(bank_obj, 1, "id");
			break;
		}
	}

	snprintf(linker, sizeof(linker), "fw_image:%s", id ? id : "");
	adm_entry_get_linker_param(ctx, "Device.DeviceInfo.FirmwareImage.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_device_boot_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (strncmp(value, "Device.DeviceInfo.FirmwareImage.", 32) != 0)
				return FAULT_9007;

			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker == NULL || *linker == '\0')
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				char *bank_id = strchr(linker, ':');
				if (bank_id) {
					json_object *res = NULL;

					dmubus_call("fwbank", "set_bootbank", UBUS_ARGS{{"bank", bank_id+1, Integer}}, 1, &res);
					char *success = dmjson_get_value(res, 1, "success");
					if (strcmp(success, "true") != 0)
						return FAULT_9001;
				}
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
	FILE *fp = fopen(UPTIME, "r");
	if (fp != NULL) {
		char *pch = NULL, *spch = NULL, buf[64] = {0};

		if (fgets(buf, 64, fp) != NULL) {
			pch = strtok_r(buf, ".", &spch);
			*value = (pch) ? dmstrdup(pch) : "0";
		}
		fclose(fp);
	}
	return 0;
}

/*#Device.DeviceInfo.ProvisioningCode!UCI:cwmp/cpe,cpe/provisioning_code*/
static int get_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "provisioning_code", value);
	return 0;
}

static int set_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "provisioning_code", value);
			return 0;
	}
	return 0;
}

static int get_number_of_cpus(void)
{
	char val[16];

	dm_read_sysfs_file("/sys/devices/system/cpu/present", val, sizeof(val));
	char *max = strchr(val, '-');
	return max ? atoi(max+1)+1 : 0;
}

static int get_DeviceInfo_ProcessorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%d", get_number_of_cpus());
	return 0;
}

static int get_DeviceInfo_VendorLogFileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dm_sec = NULL;
	unsigned int num = 0;

	uci_path_foreach_sections(bbfdm, "dmmap", "vlf", dm_sec) {
		num++;
	}

	dmasprintf(value, "%d", num);
	return 0;
}

static int get_DeviceInfo_SupportedDataModelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%d", ARRAY_SIZE(Data_Models));
	return 0;
}

static int get_DeviceInfo_FirmwareImageNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *banks = NULL;
	size_t nbre_banks = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "bank", &banks);
	nbre_banks = (banks) ? json_object_array_length(banks) : 0;
	dmasprintf(value, "%d", nbre_banks);
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
			if (config_name && strcmp(config_name, d_file->d_name) == 0) {
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "vcf_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "vcf_alias", value);
			return 0;
	}
	return 0;
}

static int check_file_dir(char *name)
{
	DIR *dir = NULL;
	struct dirent *d_file = NULL;

	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if (strcmp(name, d_file->d_name) == 0) {
				closedir(dir);
				return 1;
			}
		}
		closedir(dir);
	}
	return 0;
}

static int get_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vlf_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "vlf_alias", value);
			return 0;
	}
	return 0;
}

static int get_vlf_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "log_file", value);
	return 0;
}

static int get_vlf_max_size (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int size = 0;

	dmuci_get_value_by_section_string((struct uci_section *)data, "log_size", value);

	// Value defined in system is in KiB in datamodel this is in bytes, convert the value in bytes
	size = (*value && **value) ? atoi(*value) * 1000 : 0;

	dmasprintf(value, "%d", size);
	return 0;
}

static int get_vlf_persistent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int browseVcfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *name;
	struct uci_section *s = NULL, *del_sec = NULL;
	DIR *dir = NULL;
	struct dirent *d_file = NULL;

	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if(d_file->d_name[0] == '.')
				continue;
			update_section_list(DMMAP,"vcf", "name", 1, d_file->d_name, NULL, NULL, "backup_restore", "1");
		}
		closedir (dir);
	}
	uci_path_foreach_sections(bbfdm, DMMAP, "vcf", s) {
		dmuci_get_value_by_section_string(s, "name", &name);
		if(del_sec) {
			dmuci_delete_by_section_bbfdm(del_sec, NULL, NULL);
			del_sec = NULL;
		}
		if (check_file_dir(name) == 0) {
			del_sec = s;
			continue;
		}

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   s, "vcf_instance", "vcf_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}

	if(del_sec)
		dmuci_delete_by_section_bbfdm(del_sec, NULL, NULL);

	return 0;
}

static int browseVlfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *sys_log_sec = NULL, *dm_sec = NULL;
	char *log_file = NULL,*log_size = NULL;
	char *inst = NULL, *max_inst = NULL;
	int i = 1;

	uci_foreach_sections("system", "system", sys_log_sec) {
		if (!sys_log_sec)
			break;
		dmuci_get_value_by_section_string(sys_log_sec, "log_file", &log_file);
		dmuci_get_value_by_section_string(sys_log_sec, "log_size", &log_size);
		uci_path_foreach_sections(bbfdm, "dmmap", "vlf", dm_sec) {
			if (dm_sec)
				break;
		}
		if (!dm_sec) {
			update_section_list(DMMAP,"vlf", NULL, i++, NULL, "log_file", log_file, "log_size", log_size);
		} else {
			dmuci_set_value_by_section_bbfdm(dm_sec, "log_file", log_file);
			dmuci_set_value_by_section_bbfdm(dm_sec, "log_size", log_size);
		}
	}
	uci_path_foreach_sections(bbfdm, "dmmap", "vlf", dm_sec) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   dm_sec, "vlf_instance", "vlf_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dm_sec, inst) == DM_STOP){
			break;
		}
	}
	return 0;
}

static int browseDeviceInfoProcessorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	int i;

	for (i = 0; i < get_number_of_cpus(); i++) {
		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, NULL, inst) == DM_STOP)
			break;
	}
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
			if (dm_validate_string(value, -1, 64, NULL, NULL))
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

	if (strstr(utsname.machine, "arm") || strstr(utsname.machine, "aarch64")) {
		*value = "arm";
	} else if(strstr(utsname.machine, "mips")) {
		const bool is_big_endian = IS_BIG_ENDIAN;
		*value = (is_big_endian) ? "mipseb" : "mipsel";
	} else
		*value = dmstrdup(utsname.machine);
	return 0;
}

static int browseDeviceInfoSupportedDataModelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(Data_Models); i++) {
		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&Data_Models[i], inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDeviceInfoFirmwareImageInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *bank_obj = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("fwbank", "dump", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, bank_obj, i, 1, "bank") {
		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bank_obj, inst) == DM_STOP)
			break;
	}
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
			if (dm_validate_string(value, -1, 64, NULL, NULL))
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
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_fw_image", "fw_image", "fw_image_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DeviceInfoFirmwareImage_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_fw_image", "fw_image", "fw_image_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap_fw_image", "fw_image", &dmmap);
			dmuci_set_value_by_section(dmmap, "fw_image_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DeviceInfoFirmwareImage_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "fwver");
	return 0;
}

static int get_DeviceInfoFirmwareImage_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "swver");
	return 0;
}

static int get_DeviceInfoFirmwareImage_Available(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int get_DeviceInfoFirmwareImage_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "status");
	return 0;
}

/*#Device.DeviceInfo.MemoryStatus.Total!UBUS:router.system/memory//total*/
static int get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "memory", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "total");
	return 0;
}

/*#Device.DeviceInfo.MemoryStatus.Free!UBUS:router.system/memory//free*/
static int get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "memory", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "free");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.CPUUsage!UBUS:router.system/process//cpu_usage*/
static int get_process_cpu_usage(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "process", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "cpu_usage");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries!UBUS:router.system/processes//processes*/
static int get_process_number_of_entries(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *processes = NULL;
	int nbre_process = 0;

	dmubus_call("router.system", "processes", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "processes", &processes);
	nbre_process = (processes) ? json_object_array_length(processes) : 0;
	dmasprintf(value, "%d", nbre_process);
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.!UBUS:router.system/processes//processes*/
static int browseProcessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *processes = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("router.system", "processes", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, processes, i, 1, "processes") {
		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)processes, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.PID!UBUS:router.system/processes//processes[@i-1].pid*/
static int get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "pid");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.Command!UBUS:router.system/processes//processes[@i-1].command*/
static int get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "command");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.Size!UBUS:router.system/processes//processes[@i-1].vsz*/
static int get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vsz");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.Priority!UBUS:router.system/processes//processes[@i-1].priority*/
static int get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int priority = 0;

	*value = dmjson_get_value((json_object *)data, 1, "priority");

	priority = (*value && **value) ? atoi(*value) : 0;

	/* Convert Linux priority to a value between 0 and 99 */
	priority = round((priority + 100) * 99 / 139);

	dmasprintf(value, "%d", priority);

	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.CPUTime!UBUS:router.system/processes//processes[@i-1].cputime*/
static int get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "cputime");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.State!UBUS:router.system/processes//processes[@i-1].state*/
static int get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *state = dmjson_get_value((json_object *)data, 1, "state");
	*value = (state && strcmp(state, "Unknown") == 0) ? "Idle" : state;
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
	char backup_path[256] = {'\0'};
	char backup_command[32] = {'\0'};
	char *vcf_name = NULL;

	char *ret = strrchr(refparam, '.');
	strncpy(backup_path, refparam, ret - refparam +1);
	DM_STRNCPY(backup_command, ret+1, sizeof(backup_command));

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	if (url[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	char *pass = dmjson_get_value((json_object *)value, 1, "Password");

	dmuci_get_value_by_section_string((struct uci_section *)data, "name", &vcf_name);

	int res = bbf_config_backup(url, user, pass, vcf_name, backup_command, backup_path);

	return res ? CMD_FAIL : CMD_SUCCESS;
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

	char *ret = strrchr(refparam, '.');
	strncpy(restore_path, refparam, ret - refparam +1);
	DM_STRNCPY(restore_command, ret+1, sizeof(restore_command));

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	if (url[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	char *pass = dmjson_get_value((json_object *)value, 1, "Password");
	char *file_size = dmjson_get_value((json_object *)value, 1, "FileSize");
	char *checksum_algorithm = dmjson_get_value((json_object *)value, 1, "CheckSumAlgorithm");
	char *checksum = dmjson_get_value((json_object *)value, 1, "CheckSum");

	int res = bbf_config_restore(url, user, pass, file_size, checksum_algorithm, checksum, restore_command, restore_path);

	return res ? CMD_FAIL : CMD_SUCCESS;
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

	char *ret = strrchr(refparam, '.');
	strncpy(obj_path, refparam, ret - refparam +1);
	DM_STRNCPY(command, ret+1, sizeof(command));

	char *url = dmjson_get_value((json_object *)value, 1, "URL");
	char *auto_activate = dmjson_get_value((json_object *)value, 1, "AutoActivate");
	if (url[0] == '\0' || auto_activate[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *username = dmjson_get_value((json_object *)value, 1, "Username");
	char *password = dmjson_get_value((json_object *)value, 1, "Password");
	char *file_size = dmjson_get_value((json_object *)value, 1, "FileSize");
	char *checksum_algorithm = dmjson_get_value((json_object *)value, 1, "CheckSumAlgorithm");
	char *checksum = dmjson_get_value((json_object *)value, 1, "CheckSum");

	char *bank_id = dmjson_get_value((json_object *)data, 1, "id");

	int res = bbf_fw_image_download(url, auto_activate, username, password, file_size, checksum_algorithm, checksum, bank_id, command, obj_path);

	return res ? CMD_FAIL : CMD_SUCCESS;
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


static const char *firmware_image_activate_in[] = {
	"TimeWindow.1.Start",
	"TimeWindow.2.Start",
	"TimeWindow.3.Start",
	"TimeWindow.4.Start",
	"TimeWindow.5.Start",
};

static int get_operate_args_DeviceInfoFirmwareImage_Activate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&firmware_image_activate_args;
	return 0;
}

static int operate_DeviceInfoFirmwareImage_Activate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct activate_image active_images[MAX_TIME_WINDOW] = {0};

	for (int i = 0; i < ARRAY_SIZE(firmware_image_activate_in); i++)
		active_images[i].start_time = dmjson_get_value((json_object *)value, 1, firmware_image_activate_in[i]);

	char *bank_id = dmjson_get_value((json_object *)data, 1, "id");

	int res = bbf_fw_image_activate(bank_id, active_images);

	return res ? CMD_FAIL : CMD_SUCCESS;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.DeviceInfo. *** */
DMOBJ tDeviceInfoObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"VendorConfigFile", &DMREAD, NULL, NULL, NULL, browseVcfInst, NULL, NULL, NULL, tDeviceInfoVendorConfigFileParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"MemoryStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoMemoryStatusParams, NULL, BBFDM_BOTH},
{"ProcessStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoProcessStatusObj, tDeviceInfoProcessStatusParams, NULL, BBFDM_BOTH},
{"Processor", &DMREAD, NULL, NULL, NULL, browseDeviceInfoProcessorInst, NULL, NULL, NULL, tDeviceInfoProcessorParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"VendorLogFile", &DMREAD, NULL, NULL, NULL, browseVlfInst, NULL, NULL, NULL, tDeviceInfoVendorLogFileParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"SupportedDataModel", &DMREAD, NULL, NULL, NULL, browseDeviceInfoSupportedDataModelInst, NULL, NULL, NULL, tDeviceInfoSupportedDataModelParams, NULL, BBFDM_CWMP, LIST_KEY{"URL", "Alias", "UUID", NULL}},
{"FirmwareImage", &DMREAD, NULL, NULL, "ubus:fwbank->dump", browseDeviceInfoFirmwareImageInst, NULL, NULL, NULL, tDeviceInfoFirmwareImageParams, get_device_fwimage_linker, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tDeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DeviceCategory", &DMREAD, DMT_STRING, get_device_devicecategory, NULL, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, get_device_manufacturer, NULL, BBFDM_BOTH},
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_device_manufactureroui, NULL, BBFDM_BOTH},
{"ModelName", &DMREAD, DMT_STRING, get_device_modelname, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, get_device_description, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, get_device_productclass, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_device_serialnumber, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, get_device_hardwareversion, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, get_device_softwareversion, NULL, BBFDM_BOTH},
{"ActiveFirmwareImage", &DMREAD, DMT_STRING, get_device_active_fwimage, NULL, BBFDM_BOTH},
{"BootFirmwareImage", &DMWRITE, DMT_STRING, get_device_boot_fwimage, set_device_boot_fwimage, BBFDM_BOTH},
{"AdditionalHardwareVersion", &DMREAD, DMT_STRING, get_device_additionalhardwareversion, NULL, BBFDM_BOTH},
{"AdditionalSoftwareVersion", &DMREAD, DMT_STRING, get_device_additionalsoftwareversion, NULL, BBFDM_BOTH},
{"ProvisioningCode", &DMWRITE, DMT_STRING, get_device_provisioningcode, set_device_provisioningcode, BBFDM_BOTH},
{"UpTime", &DMREAD, DMT_UNINT, get_device_info_uptime, NULL, BBFDM_BOTH},
{"ProcessorNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_ProcessorNumberOfEntries, NULL, BBFDM_BOTH},
{"VendorLogFileNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_VendorLogFileNumberOfEntries, NULL, BBFDM_BOTH},
{"SupportedDataModelNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_SupportedDataModelNumberOfEntries, NULL, BBFDM_CWMP},
{"FirmwareImageNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_FirmwareImageNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.VendorConfigFile.{i}. *** */
DMLEAF tDeviceInfoVendorConfigFileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_vcf_alias, set_vcf_alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_vcf_name, NULL, BBFDM_BOTH},
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Total", &DMREAD, DMT_UNINT, get_memory_status_total, NULL, BBFDM_BOTH},
{"Free", &DMREAD, DMT_UNINT, get_memory_status_free, NULL, BBFDM_BOTH},
{0}
};
/* *** Device.DeviceInfo.ProcessStatus. *** */
DMOBJ tDeviceInfoProcessStatusObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Process", &DMREAD, NULL, NULL, "ubus:router.system->processes", browseProcessEntriesInst, NULL, NULL, NULL, tDeviceInfoProcessStatusProcessParams, NULL, BBFDM_BOTH, LIST_KEY{"PID", NULL}},
{0}
};

DMLEAF tDeviceInfoProcessStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CPUUsage", &DMREAD, DMT_UNINT, get_process_cpu_usage, NULL, BBFDM_BOTH},
{"ProcessNumberOfEntries", &DMREAD, DMT_UNINT, get_process_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.ProcessStatus.Process.{i}. *** */
DMLEAF tDeviceInfoProcessStatusProcessParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"PID", &DMREAD, DMT_UNINT, get_process_pid, NULL, BBFDM_BOTH},
{"Command", &DMREAD, DMT_STRING, get_process_command, NULL, BBFDM_BOTH},
{"Size", &DMREAD, DMT_UNINT, get_process_size, NULL, BBFDM_BOTH},
{"Priority", &DMREAD, DMT_UNINT, get_process_priority, NULL, BBFDM_BOTH},
{"CPUTime", &DMREAD, DMT_UNINT, get_process_cpu_time, NULL, BBFDM_BOTH},
{"State", &DMREAD, DMT_STRING, get_process_state, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.VendorLogFile.{i}. *** */
DMLEAF tDeviceInfoVendorLogFileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_vlf_alias, set_vlf_alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_vlf_name, NULL, BBFDM_BOTH},
{"MaximumSize", &DMREAD, DMT_UNINT, get_vlf_max_size, NULL, BBFDM_BOTH},
{"Persistent", &DMREAD, DMT_BOOL, get_vlf_persistent, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.Processor.{i}. *** */
DMLEAF tDeviceInfoProcessorParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoProcessor_Alias, set_DeviceInfoProcessor_Alias, BBFDM_BOTH},
{"Architecture", &DMREAD, DMT_STRING, get_DeviceInfoProcessor_Architecture, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.SupportedDataModel.{i}. *** */
DMLEAF tDeviceInfoSupportedDataModelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoSupportedDataModel_Alias, set_DeviceInfoSupportedDataModel_Alias, BBFDM_CWMP},
{"URL", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_URL, NULL, BBFDM_CWMP},
{"URN", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_URN, NULL, BBFDM_CWMP},
{"Features", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_Features, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.DeviceInfo.FirmwareImage.{i}. *** */
DMLEAF tDeviceInfoFirmwareImageParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoFirmwareImage_Alias, set_DeviceInfoFirmwareImage_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_DeviceInfoFirmwareImage_Name, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_DeviceInfoFirmwareImage_Version, NULL, BBFDM_BOTH},
{"Available", &DMREAD, DMT_BOOL, get_DeviceInfoFirmwareImage_Available, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DeviceInfoFirmwareImage_Status, NULL, BBFDM_BOTH},
{"BootFailureLog", &DMREAD, DMT_STRING, get_empty, NULL, BBFDM_BOTH},
{"Download()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoFirmwareImage_Download, operate_DeviceInfoFirmwareImage_Download, BBFDM_USP},
{"Activate()", &DMASYNC, DMT_COMMAND, get_operate_args_DeviceInfoFirmwareImage_Activate, operate_DeviceInfoFirmwareImage_Activate, BBFDM_USP},
{0}
};

