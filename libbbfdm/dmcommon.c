/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include <stdlib.h>
#include <curl/curl.h>

#ifdef LOPENSSL
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif

#ifdef LWOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/evp.h>
#endif

#ifdef LMBEDTLS
#include <mbedtls/md.h>
#endif

#include "dmcommon.h"

#define READ_BUF_SIZE (1024 * 16)

char *get_diagnostics_option(char *sec_name, char *option)
{
	char *value;
	dmuci_get_option_value_string_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, &value);
	return value;
}

char *get_diagnostics_option_fallback_def(char *sec_name, char *option, char *default_value)
{
	char *value = get_diagnostics_option(sec_name, option);
	return (*value != '\0') ? value : default_value;
}

void set_diagnostics_option(char *sec_name, char *option, char *value)
{
	check_create_dmmap_package(DMMAP_DIAGNOSTIGS);
	struct uci_section *section = dmuci_walk_section_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
	if (!section)
		dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, "", sec_name);

	dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, value);
}

void reset_diagnostic_state(char *sec_name)
{
	char *diag_state = get_diagnostics_option(sec_name, "DiagnosticState");
	if (strcmp(diag_state, "Requested") != 0) {
		set_diagnostics_option(sec_name, "DiagnosticState", "None");
	}
}

char *get_diagnostics_interface_option(struct dmctx *ctx, char *value)
{
	char *linker = NULL;

	if (!value || *value == 0)
		return "";

	if (strncmp(value, "Device.IP.Interface.", 20) != 0)
		return "";

	adm_entry_get_reference_value(ctx, value, &linker);
	return linker ? linker : "";
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
	unsigned fault_code = 0;

	strftime(start_time, sizeof(start_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&start_t));
	strftime(complete_time, sizeof(complete_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&complete_t));

	if (DM_STRLEN(fault_string) != 0)
		fault_code = USP_FAULT_GENERAL_FAILURE;

	struct json_object *obj = json_object_new_object();

	json_object_object_add(obj, "Command", json_object_new_string(command));
	if(commandKey)
		json_object_object_add(obj, "CommandKey", json_object_new_string(commandKey));
	else
		json_object_object_add(obj, "CommandKey", json_object_new_string(""));
	json_object_object_add(obj, "Requestor", json_object_new_string(""));
	json_object_object_add(obj, "TransferType", json_object_new_string(transfer_type));
	json_object_object_add(obj, "Affected", json_object_new_string(obj_path));
	json_object_object_add(obj, "TransferURL", json_object_new_string(transfer_url));
	json_object_object_add(obj, "StartTime", json_object_new_string(start_time));
	json_object_object_add(obj, "CompleteTime", json_object_new_string(complete_time));
	json_object_object_add(obj, "FaultCode", json_object_new_uint64(fault_code));
	json_object_object_add(obj, "FaultString", json_object_new_string(fault_string));

	dmubus_call_set("bbfdm", "notify_event", UBUS_ARGS{{"name", "Device.LocalAgent.TransferComplete!", String}, {"input", json_object_to_json_string(obj), Table}}, 2);

	json_object_put(obj);
}

static long download_file(char *file_path, const char *url, const char *username, const char *password)
{
	long res_code = 0;

	if (strncmp(url, FILE_URI, strlen(FILE_URI)) == 0) {

		const char *curr_path = (!strncmp(url, FILE_LOCALHOST_URI, strlen(FILE_LOCALHOST_URI))) ? url + strlen(FILE_LOCALHOST_URI) : url + strlen(FILE_URI);

		if (!file_exists(curr_path))
			return -1;

		DM_STRNCPY(file_path, curr_path, 256);
	} else {

		CURL *curl = curl_easy_init();
		if (curl) {
			curl_easy_setopt(curl, CURLOPT_URL, url);
			curl_easy_setopt(curl, CURLOPT_USERNAME, username);
			curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);

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

static long upload_file(const char *file_path, const char *url, const char *username, const char *password)
{
	long res_code = 0;

	if (strncmp(url, FILE_URI, strlen(FILE_URI)) == 0) {
		char dst_path[2046] = {0};
		char buff[BUFSIZ] = {0};
		FILE *sfp, *dfp;
		int n, count=0;

		sfp = fopen(file_path, "rb");
		if (sfp == NULL) {
			return -1;
		}

		snprintf(dst_path, sizeof(dst_path), "%s", url+strlen(FILE_URI));
		dfp = fopen(dst_path, "wb");
		if (dfp == NULL) {
			fclose(sfp);
			return -1;
		}

		while ((n = fread(buff, 1, BUFSIZ, sfp)) != 0) {
			fwrite(buff, 1, n, dfp);
			count+=n;
		}

		fclose(sfp);
		fclose(dfp);
	} else {
		CURL *curl = curl_easy_init();
		if (curl) {
			curl_easy_setopt(curl, CURLOPT_URL, url);
			curl_easy_setopt(curl, CURLOPT_USERNAME, username);
			curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
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
	unsigned char buffer[READ_BUF_SIZE] = {0};
	char hash[BUFSIZ] = {0};
	bool res = false;
	unsigned int bytes = 0;
	FILE *file;

#ifdef LMBEDTLS
	mbedtls_md_context_t enpctx;
	mbedtls_md_context_t *mdctx = &enpctx;
	const mbedtls_md_info_t *md;
	unsigned char md_value[MBEDTLS_MD_MAX_SIZE];
#else
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
#endif

	file = fopen(file_path, "rb");
	if (!file)
		return false;

#ifndef LMBEDTLS
	// makes all algorithms available to the EVP* routines
	OpenSSL_add_all_algorithms();
#endif

#ifdef LMBEDTLS
	md = mbedtls_md_info_from_string(algo);
	mbedtls_md_init(mdctx);
	mbedtls_md_init_ctx(mdctx, md);
#else
	md = EVP_get_digestbyname(algo);
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
#endif

	if (md == NULL)
		goto end;

	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
#ifdef LMBEDTLS
		mbedtls_md_update(mdctx, buffer, bytes);
#else
		EVP_DigestUpdate(mdctx, buffer, bytes);
#endif
	}

#ifdef LMBEDTLS
	mbedtls_md_finish(mdctx, md_value);
	bytes = mbedtls_md_get_size(md);
#else
	bytes = 0;
	EVP_DigestFinal_ex(mdctx, md_value, &bytes);
#endif

	for (int i = 0; i < bytes; i++)
		snprintf(&hash[i * 2], sizeof(hash) - (i * 2), "%02x", md_value[i]);

	if (DM_STRCMP(hash, checksum) == 0)
		res = true;

end:
#ifdef LMBEDTLS
	mbedtls_md_free(mdctx);
#else
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();
#endif

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

int bbf_upload_log(const char *url, const char *username, const char *password,
                char *config_name, const char *command, const char *obj_path)
{
	int res = 0;
	char fault_msg[128] = {0};

	// Upload the config file
	time_t start_time = time(NULL);
	long res_code = upload_file(config_name, url, username, password);
	time_t complete_time = time(NULL);

	// Check if the upload operation was successful
	if (!get_response_code_status(url, res_code)) {
		snprintf(fault_msg, sizeof(fault_msg), "Upload operation is failed, fault code (%ld)", res_code);
		res = -1;
	}

	// Send the transfer complete event
	send_transfer_complete_event(command, obj_path, url, fault_msg, start_time, complete_time, NULL, "Upload");
	return res;
}
int bbf_config_restore(const char *url, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *command, const char *obj_path)
{
	char config_restore[256] = "/tmp/bbf_config_restore";
	int res = 0;
	char fault_msg[128] = {0};
	time_t complete_time = 0;
	time_t start_time = time(NULL);

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

int bbf_fw_image_download(const char *url, const char *auto_activate, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *bank_id, const char *command, const char *obj_path, const char *commandKey)
{
	char fw_image_path[256] = "/tmp/firmware-XXXXXX";
	json_object *json_obj = NULL;
	bool activate = false, valid = false;
	int res = 0;
	char fault_msg[128] = {0};
	time_t complete_time = 0;
	time_t start_time = time(NULL);

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

	string_to_bool((char *)auto_activate, &activate);
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

	// Apply Firmware Image
	dmubus_call_blocking("fwbank", "upgrade", UBUS_ARGS{{"path", fw_image_path, String}, {"auto_activate", act, Boolean}, {"bank", bank_id, Integer}}, 3, &json_obj);
	if (json_obj == NULL) {
		res = 1;
		snprintf(fault_msg, sizeof(fault_msg), "Internal error occurred when applying the firmware");
		goto end;
	}

	struct sysupgrade_ev_data ev_data = {
		.bank_id = bank_id,
		.status = false,
	};

	dmubus_wait_for_event("sysupgrade", 120, &ev_data, dmubus_receive_sysupgrade);

	if (ev_data.status == false) {
		res = 1;
		snprintf(fault_msg, sizeof(fault_msg), "Failed to apply the downloaded image file");
		goto end;
	}

	// Reboot the device if auto activation is true
	if (activate) {
		// Send the transfer complete after image applied
		send_transfer_complete_event(command, obj_path, url, fault_msg, start_time, complete_time, commandKey, "Download");

		sleep(5); // added additional buffer for TransferComplete! event
		if (dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0) != 0)
			res = -1;
		sleep(10); // Wait for reboot to take action
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


void ppp___update_sections(struct uci_section *s_from, struct uci_section *s_to)
{
	char *proto = NULL;
	char *device = NULL;
	char *username = NULL;
	char *password = NULL;
	char *pppd_options = NULL;
	char *service = NULL;
	char *ac = NULL;

	dmuci_get_value_by_section_string(s_from, "proto", &proto);
	dmuci_get_value_by_section_string(s_from, "device", &device);
	dmuci_get_value_by_section_string(s_from, "username", &username);
	dmuci_get_value_by_section_string(s_from, "password", &password);
	dmuci_get_value_by_section_string(s_from, "pppd_options", &pppd_options);
	dmuci_get_value_by_section_string(s_from, "service", &service);
	dmuci_get_value_by_section_string(s_from, "ac", &ac);

	dmuci_set_value_by_section(s_to, "proto", proto);
	dmuci_set_value_by_section(s_to, "device", DM_STRLEN(device) ? device : section_name(s_to));
	dmuci_set_value_by_section(s_to, "username", username);
	dmuci_set_value_by_section(s_to, "password", password);
	dmuci_set_value_by_section(s_to, "pppd_options", pppd_options);
	dmuci_set_value_by_section(s_to, "service", service);
	dmuci_set_value_by_section(s_to, "ac", ac);
}

void ppp___reset_options(struct uci_section *ppp_s)
{
	dmuci_set_value_by_section(ppp_s, "device", section_name(ppp_s));
	dmuci_set_value_by_section(ppp_s, "username", "");
	dmuci_set_value_by_section(ppp_s, "password", "");
	dmuci_set_value_by_section(ppp_s, "pppd_options", "");
	dmuci_set_value_by_section(ppp_s, "service", "");
	dmuci_set_value_by_section(ppp_s, "ac", "");
}

void firewall__create_zone_section(char *s_name)
{
	struct uci_section *s = NULL;
	char *input = NULL;
	char *output = NULL;
	char *forward = NULL;

	dmuci_get_option_value_string("firewall", "@defaults[0]", "input", &input);
	dmuci_get_option_value_string("firewall", "@defaults[0]", "output", &output);
	dmuci_get_option_value_string("firewall", "@defaults[0]", "forward", &forward);

	dmuci_add_section("firewall", "zone", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "name", s_name);
	dmuci_set_value_by_section(s, "input", input);
	dmuci_set_value_by_section(s, "output", output);
	dmuci_set_value_by_section(s, "forward", forward);

	dmuci_add_list_value_by_section(s, "network", s_name);
}

bool ip___is_ip_interface_instance_exists(const char *sec_name, const char *device)
{
	struct uci_section *s = NULL;
	char *curr_dev = NULL;

	if (DM_STRLEN(sec_name) == 0 ||
		DM_STRLEN(device) == 0)
		return false;

	uci_foreach_sections("network", "interface", s) {

		dmuci_get_value_by_section_string(s, "device", &curr_dev);
		if (DM_STRLEN(curr_dev) == 0 ||
			DM_STRCMP(curr_dev, device) != 0)
			continue;

		struct uci_section *dmmap_s = NULL;
		char *ip_inst = NULL;

		if ((dmmap_s = get_dup_section_in_dmmap("dmmap_network", "interface", section_name(s))) != NULL) {
			dmuci_get_value_by_section_string(dmmap_s, "ip_int_instance", &ip_inst);

			if (strcmp(sec_name, section_name(s)) != 0 &&
				DM_STRLEN(ip_inst) != 0)
				return true;
		}
	}

	return false;
}

void ip___update_child_interfaces(char *device, char *option_name, char *option_value)
{
	struct uci_section *s = NULL;

	if (DM_STRLEN(device) == 0)
		return;

	uci_foreach_option_eq("network", "interface", "device", device, s) {
		dmuci_set_value_by_section(s, option_name, option_value);
	}
}

static void ip___Update_IP_Interface_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "LowerLayers", path, dmmap_s) {
		struct uci_section *iface_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char *curr_device = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "ip_int_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		iface_s = get_origin_section_from_config("network", "interface", sec_name);
		if (!iface_s)
			continue;

		dmuci_get_value_by_section_string(iface_s, "device", &curr_device);

		ip___update_child_interfaces(curr_device, "device", DM_STRLEN(linker) ? linker : section_name(iface_s));
	}
}

static void ppp___Update_PPP_Interface_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_ppp", "interface", "LowerLayers", path, dmmap_s) {
		struct uci_section *iface_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char curr_path[128] = {0};
		char proto[8] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "ppp_int_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "iface_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		iface_s = get_origin_section_from_config("network", "interface", sec_name);

		snprintf(proto, sizeof(proto), "ppp%s", (DM_STRLEN(linker)) ? (!DM_LSTRNCMP(linker, "atm", 3) || !DM_LSTRNCMP(linker, "ptm", 3)) ? "oa" : "oe" : "");

		// Update proto option
		dmuci_set_value_by_section(dmmap_s, "proto", proto);
		if (iface_s) dmuci_set_value_by_section(iface_s, "proto", proto);

		// Update device option
		dmuci_set_value_by_section(dmmap_s, "device", linker);
		if (iface_s) dmuci_set_value_by_section(iface_s, "device", linker);

		snprintf(curr_path, sizeof(curr_path), "Device.PPP.Interface.%s", instance);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, linker);
	}
}

void ppp___Update_PPP_Interface_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

static void ethernet___Update_MAC_VLAN_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "LowerLayers", path, dmmap_s) {
		struct uci_section *dev_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char curr_path[128] = {0};
		char name[32] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "mac_vlan_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		dev_s = get_origin_section_from_config("network", "device", sec_name);
		if (!dev_s)
			continue;

		if (DM_STRLEN(linker)) {
			char *dev_name = ethernet___get_ethernet_interface_name(linker);

			snprintf(name, sizeof(name), "%s_%s", dev_name, instance);
		}

		dmuci_set_value_by_section(dev_s, "ifname", linker);
		dmuci_set_value_by_section(dev_s, "name", name);

		snprintf(curr_path, sizeof(curr_path), "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN.%s", instance);

		// Update PPP Interface instance if exists
		ppp___Update_PPP_Interface_Layer(curr_path, name);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, name);
	}
}

void ethernet___Update_MAC_VLAN_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update PPP Interface instance if exists
	ppp___Update_PPP_Interface_Layer(path, linker);

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

static void ethernet___Update_VLAN_Termination_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "LowerLayers", path, dmmap_s) {
		struct uci_section *dev_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char curr_path[128] = {0};
		char name[32] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "vlan_term_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		dev_s = get_origin_section_from_config("network", "device", sec_name);
		if (!dev_s)
			continue;

		if (DM_STRLEN(linker)) {
			char *vid = NULL;

			dmuci_get_value_by_section_string(dev_s, "vid", &vid);

			snprintf(name, sizeof(name), "%s%s%s", linker, DM_STRLEN(vid) ? "." : "", DM_STRLEN(vid) ? vid : "");
		}

		dmuci_set_value_by_section(dev_s, "ifname", linker);
		dmuci_set_value_by_section(dev_s, "name", name);

		snprintf(curr_path, sizeof(curr_path), "Device.Ethernet.VLANTermination.%s", instance);

		// Update VLAN Termination instance if exists
		ethernet___Update_VLAN_Termination_Layer(curr_path, name);

		// Update MACVLAN instance if exists
		ethernet___Update_MAC_VLAN_Layer(curr_path, name);

		// Update PPP Interface instance if exists
		ppp___Update_PPP_Interface_Layer(curr_path, name);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, name);
	}
}

void ethernet___Update_VLAN_Termination_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update VLAN Termination instance if exists
	ethernet___Update_VLAN_Termination_Layer(path, linker);

	// Update MACVLAN instance if exists
	ethernet___Update_MAC_VLAN_Layer(path, linker);

	// Update PPP Interface instance if exists
	ppp___Update_PPP_Interface_Layer(path, linker);

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

void ethernet___Update_Link_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_ethernet", "link", "LowerLayers", path, dmmap_s) {
		char *instance = NULL;
		char curr_path[128] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "link_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_set_value_by_section(dmmap_s, "device", linker);

		if (match(path, "Device.Bridging.Bridge.*.Port.", 0, NULL)) {
			// Remove unused Interface section created by Bridge Object if it exists
			struct uci_section *s = get_dup_section_in_config_opt("network", "interface", "device", linker);
			dmuci_delete_by_section(s, NULL, NULL);
		}

		snprintf(curr_path, sizeof(curr_path), "Device.Ethernet.Link.%s", instance);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, linker);
	}
}

void ethernet___Update_Link_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update VLAN Termination instance if exists
	ethernet___Update_VLAN_Termination_Layer(path, linker);

	// Update MACVLAN instance if exists
	ethernet___Update_MAC_VLAN_Layer(path, linker);

	// Update PPP Interface instance if exists
	ppp___Update_PPP_Interface_Layer(path, linker);

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

void bridging___get_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char **value)
{
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;
	char uci_value[256] = {0};
	unsigned pos = 0;

	if (!data || !uci_opt_name)
		return;

	dmuci_get_value_by_section_list(device_sec, uci_opt_name, &uci_opt_list);
	if (uci_opt_list == NULL)
		return;

	uci_value[0] = '\0';
	/* traverse each list value and create comma separated output */
	uci_foreach_element(uci_opt_list, e) {

		//delimiting priority which is in the form of x:y where y is the priority
		char *priority = strchr(e->name, ':');
		if (priority)
			pos += snprintf(&uci_value[pos], sizeof(uci_value) - pos, "%s,", priority + 1);
	}

	if (pos)
		uci_value[pos - 1] = 0;

	dmasprintf(value, "%s", uci_value);
}

void bridging___set_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char *value)
{
	char *pch = NULL, *pchr = NULL;
	int idx = 0;

	if (!data || !uci_opt_name || !value)
		return;

	/* delete current list values */
	dmuci_set_value_by_section(device_sec, uci_opt_name, "");

	/* tokenize each value from received comma separated string and add it to uci file in the format x:y
	x being priority and y being priority to be mapped to */
	for (pch = strtok_r(value, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr), idx++) {
		char buf[16] = {0};

		/* convert values to uci format (x:y) and add */
		snprintf(buf, sizeof(buf), "%d%c%s", idx, ':', pch);
		dmuci_add_list_value_by_section(device_sec, uci_opt_name, buf);
	}
}

struct uci_section *ethernet___get_ethernet_interface_section(const char *device_name)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("network", "device", s) {
		char *name = NULL;

		if (!dmuci_is_option_value_empty(s, "type"))
			continue;

		dmuci_get_value_by_section_string(s, "name", &name);

		if (DM_STRCMP(name, device_name) == 0)
			return s;
	}

	return NULL;
}

char *ethernet___get_ethernet_interface_name(char *device_name)
{
	char *dev_name = dmstrdup(device_name);

	if (!ethernet___get_ethernet_interface_section(dev_name)) {
		struct uci_section *dev_s = NULL;

		dev_s = get_dup_section_in_config_opt("network", "device", "name", dev_name);

		char *has_vid = DM_STRRCHR(dev_name, '.');
		if (has_vid)
			*has_vid = '\0';

		if (dev_s) { // Verify if the device has dual tags
			char *type = NULL;

			dmuci_get_value_by_section_string(dev_s, "type", &type);
			if (DM_STRCMP(type, "8021ad") == 0) {
				char *has_vid = DM_STRRCHR(dev_name, '.');
				if (has_vid)
					*has_vid = '\0';
			}
		}
	}

	return dev_name;
}
