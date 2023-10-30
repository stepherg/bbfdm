/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include <stdlib.h>
#include <curl/curl.h>

#ifdef LOPENSSL
#include <openssl/sha.h>
#endif

#ifdef LWOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/sha.h>
#endif

#ifdef LMBEDTLS
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#endif

#include "dmdiagnostics.h"

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

	adm_entry_get_linker_value(ctx, value, &linker);
	return linker ? linker : "";
}

void set_diagnostics_interface_option(struct dmctx *ctx, char *sec_name, char *value)
{
	char *linker = NULL;

	if (!value || *value == 0)
		return;

	if (strncmp(value, "Device.IP.Interface.", 20) != 0)
		return;

	adm_entry_get_linker_value(ctx, value, &linker);
	set_diagnostics_option(sec_name, "interface", linker ? linker : "");
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
	long res_code, time_t start_t, time_t complete_t,const char *commandKey, const char *transfer_type)
{
	char start_time[32] = {0};
	char complete_time[32] = {0};
	char fault_string[128] = {0};
	unsigned fault_code = 0;

	strftime(start_time, sizeof(start_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&start_t));
	strftime(complete_time, sizeof(complete_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&complete_t));

	if (!get_response_code_status(transfer_url, res_code)) {
		fault_code = USP_FAULT_GENERAL_FAILURE;
		snprintf(fault_string, sizeof(fault_string), "%s operation is failed, fault code (%ld)", transfer_type, res_code);
	}

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
		snprintf(dst_path, sizeof(dst_path), "%s", url+strlen(FILE_URI));
		FILE *fp = fopen(file_path, "r");
		if (fp == NULL) {
			return -1;
		}

		fseek(fp, 0, SEEK_END);
		unsigned int length = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		fclose(fp);

		char buff[length];
		memset(buff, 0, length);

		if (dm_file_to_buf(file_path, buff, length) > 0) {
			if (dm_buf_to_file(buff, dst_path) < 0)
				res_code = -1;
		} else {
			res_code = -1;
		}
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

#if defined(LOPENSSL) || defined(LWOLFSSL)
#define SHA1_DLEN SHA_DIGEST_LENGTH
#define SHA1_CTX SHA_CTX
#define SHA1_UPDATE SHA1_Update
#define SHA1_FINAL SHA1_Final
#else
#define SHA1_DLEN (20)
#define SHA1_CTX mbedtls_sha1_context
#define SHA1_UPDATE mbedtls_sha1_update_ret
#define SHA1_FINAL(X, Y) mbedtls_sha1_finish_ret(Y, X)
#endif
const bool validate_sha1sum_value(const char *file_path, const char *checksum)
{
	unsigned char hash[SHA1_DLEN];
	unsigned char buffer[READ_BUF_SIZE];
	char sha1_res[1 + SHA1_DLEN * 2];
	bool res = false;
	int bytes = 0;
	SHA1_CTX ctx;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return false;

#if defined(LOPENSSL) || defined(LWOLFSSL)
	if (!SHA1_Init(&ctx))
		goto end;
#else
	mbedtls_sha1_init(&ctx);
#endif
	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
		if (!SHA1_UPDATE(&ctx, buffer, bytes))
			goto end;
	}

	if (!SHA1_FINAL(hash, &ctx))
		goto end;

	for (int i = 0; i < SHA1_DLEN; i++)
		snprintf(&sha1_res[i * 2], sizeof(sha1_res) - (i * 2), "%02x", hash[i]);

	if (DM_STRCMP(sha1_res, checksum) == 0)
		res = true;

end:
	fclose(file);
	return res;
}

#if defined(LOPENSSL)
#define SHA224_DLEN SHA256_DIGEST_LENGTH
#define SHA224_CTX_t SHA256_CTX
#define SHA224_INIT SHA224_Init
#define SHA224_UPDATE SHA224_Update
#define SHA224_FINAL SHA224_Final
#elif defined(LWOLFSSL)
#define SHA224_DLEN SHA256_DIGEST_LENGTH
#define SHA224_CTX_t SHA256_CTX
#define SHA224_INIT SHA256_Init
#define SHA224_UPDATE SHA256_Update
#define SHA224_FINAL SHA256_Final
#else
#define SHA224_DLEN (32)
#define SHA224_CTX_t mbedtls_sha256_context
#define SHA224_UPDATE mbedtls_sha256_update_ret
#define SHA224_FINAL(X, Y) mbedtls_sha256_finish_ret(Y, X)
#endif
const bool validate_sha224sum_value(const char *file_path, const char *checksum)
{
	unsigned char hash[SHA224_DLEN];
	unsigned char buffer[READ_BUF_SIZE];
	char sha224_res[1 + SHA224_DLEN * 2];
	bool res = false;
	int bytes = 0;
	SHA224_CTX_t ctx;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return false;

#if defined(LOPENSSL) || defined(LWOLFSSL)
	if (!SHA224_INIT(&ctx))
		goto end;
#else
	mbedtls_sha256_init(&ctx);
	if (!mbedtls_sha256_starts_ret(&ctx, 1))
		goto end;
#endif

	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
		if (!SHA224_UPDATE(&ctx, buffer, bytes))
			goto end;
	}

	if (!SHA224_FINAL(hash, &ctx))
		goto end;

	for (int i = 0; i < SHA224_DLEN; i++)
		snprintf(&sha224_res[i * 2], sizeof(sha224_res) - (i * 2), "%02x", hash[i]);

	if (DM_STRCMP(sha224_res, checksum) == 0)
		res = true;

end:
	fclose(file);
	return res;
}

#if defined(LOPENSSL) || defined(LWOLFSSL)
#define SHA256_DLEN SHA256_DIGEST_LENGTH
#define SHA256_CTX_t SHA256_CTX
#define SHA256_UPDATE SHA256_Update
#define SHA256_FINAL SHA256_Final
#else
#define SHA256_DLEN (32)
#define SHA256_CTX_t mbedtls_sha256_context
#define SHA256_UPDATE mbedtls_sha256_update_ret
#define SHA256_FINAL(X, Y) mbedtls_sha256_finish_ret(Y, X)
#endif
const bool validate_sha256sum_value(const char *file_path, const char *checksum)
{
	unsigned char hash[SHA256_DLEN];
	unsigned char buffer[READ_BUF_SIZE];
	char sha256_res[1 + SHA256_DLEN * 2];
	bool res = false;
	int bytes = 0;
	SHA256_CTX_t ctx;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return false;

#if defined(LOPENSSL) || defined(LWOLFSSL)
	if (!SHA256_Init(&ctx))
		goto end;
#else
	mbedtls_sha256_init(&ctx);
	if (!mbedtls_sha256_starts_ret(&ctx, 0))
		goto end;
#endif

	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
		if (!SHA256_UPDATE(&ctx, buffer, bytes))
			goto end;
	}

	if (!SHA256_FINAL(hash, &ctx))
		goto end;

	for (int i = 0; i < SHA256_DLEN; i++)
		snprintf(&sha256_res[i * 2], sizeof(sha256_res) - (i * 2), "%02x", hash[i]);

	if (DM_STRCMP(sha256_res, checksum) == 0)
		res = true;

end:
	fclose(file);
	return res;
}

#if defined(LOPENSSL)
#define SHA384_DLEN SHA384_DIGEST_LENGTH
#define SHA384_CTX_t SHA512_CTX
#define SHA384_UPDATE SHA384_Update
#define SHA384_FINAL SHA384_Final
#elif defined(LWOLFSSL)
#define SHA384_DLEN SHA384_DIGEST_LENGTH
#define SHA384_CTX_t SHA384_CTX
#define SHA384_UPDATE SHA384_Update
#define SHA384_FINAL SHA384_Final
#else
#define SHA384_DLEN (64)
#define SHA384_CTX_t mbedtls_sha512_context
#define SHA384_UPDATE mbedtls_sha512_update_ret
#define SHA384_FINAL(X, Y) mbedtls_sha512_finish_ret(Y, X)
#endif
const bool validate_sha384sum_value(const char *file_path, const char *checksum)
{
	unsigned char hash[SHA384_DLEN];
	unsigned char buffer[READ_BUF_SIZE];
	char sha384_res[1 + SHA384_DLEN * 2];
	bool res = false;
	int bytes = 0;
	SHA384_CTX_t ctx;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return false;

#if defined(LOPENSSL) || defined(LWOLFSSL)
	if (!SHA384_Init(&ctx))
		goto end;
#else
	mbedtls_sha512_init(&ctx);
	if (!mbedtls_sha512_starts_ret(&ctx, 1))
		goto end;
#endif

	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
		if (!SHA384_UPDATE(&ctx, buffer, bytes))
			goto end;
	}

	if (!SHA384_FINAL(hash, &ctx))
		goto end;

	for (int i = 0; i < SHA384_DLEN; i++)
		snprintf(&sha384_res[i * 2], sizeof(sha384_res) - (i * 2), "%02x", hash[i]);

	if (DM_STRCMP(sha384_res, checksum) == 0)
		res = true;

end:
	fclose(file);

	return res;
}

#if defined(LOPENSSL) || defined(LWOLFSSL)
#define SHA512_DLEN SHA512_DIGEST_LENGTH
#define SHA512_CTX_t SHA512_CTX
#define SHA512_UPDATE SHA512_Update
#define SHA512_FINAL SHA512_Final
#else
#define SHA512_DLEN (64)
#define SHA512_CTX_t mbedtls_sha512_context
#define SHA512_UPDATE mbedtls_sha512_update_ret
#define SHA512_FINAL(X, Y) mbedtls_sha512_finish_ret(Y, X)
#endif
const bool validate_sha512sum_value(const char *file_path, const char *checksum)
{
	unsigned char hash[SHA512_DLEN];
	unsigned char buffer[READ_BUF_SIZE];
	char sha512_res[1 + SHA512_DLEN * 2];
	bool res = false;
	int bytes = 0;
	SHA512_CTX_t ctx;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return false;

#if defined(LOPENSSL) || defined(LWOLFSSL)
	if (!SHA512_Init(&ctx))
		goto end;
#else
	mbedtls_sha512_init(&ctx);
	if (!mbedtls_sha512_starts_ret(&ctx, 0))
		goto end;
#endif

	while ((bytes = fread (buffer, 1, sizeof(buffer), file))) {
		if (!SHA512_UPDATE(&ctx, buffer, bytes))
			goto end;
	}

	if (!SHA512_FINAL(hash, &ctx))
		goto end;

	for (int i = 0; i < SHA512_DLEN; i++)
		snprintf(&sha512_res[i * 2], sizeof(sha512_res) - (i * 2), "%02x", hash[i]);

	if (DM_STRCMP(sha512_res, checksum) == 0)
		res = true;

end:
	fclose(file);
	return res;
}

const bool validate_checksum_value(const char *file_path, const char *checksum_algorithm, const char *checksum)
{
	if (checksum && *checksum) {

		if (strcmp(checksum_algorithm, "SHA-1") == 0)
			return validate_sha1sum_value(file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-224") == 0)
			return validate_sha224sum_value(file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-256") == 0)
			return validate_sha256sum_value(file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-384") == 0)
			return validate_sha384sum_value(file_path, checksum);
		else if (strcmp(checksum_algorithm, "SHA-512") == 0)
			return validate_sha512sum_value(file_path, checksum);
		else
			return false;
	}

	return true;
}

int bbf_config_backup(const char *url, const char *username, const char *password,
		char *config_name, const char *command, const char *obj_path)
{
	int res = 0;

	// Export config file to backup file
	if (dmuci_export_package(config_name, CONFIG_BACKUP)) {
		res = -1;
		goto end;
	}

	// Upload the config file
	time_t start_time = time(NULL);
	long res_code = upload_file(CONFIG_BACKUP, url, username, password);
	time_t complete_time = time(NULL);

	// Send Transfer Complete Event
	send_transfer_complete_event(command, obj_path, url, res_code, start_time, complete_time,NULL,"Upload");

	// Check if the upload operation was successful
	if (!get_response_code_status(url, res_code)) {
		res = -1;
		goto end;
	}

end:
	// Remove temporary file
	if (file_exists(CONFIG_BACKUP) && remove(CONFIG_BACKUP))
		res = -1;

	return res;
}

int bbf_upload_log(const char *url, const char *username, const char *password,
                char *config_name, const char *command, const char *obj_path)
{
	int res = 0;

        // Upload the config file
	time_t start_time = time(NULL);
	long res_code = upload_file(config_name, url, username, password);
	time_t complete_time = time(NULL);

	// Send Transfer Complete Event
	send_transfer_complete_event(command, obj_path, url, res_code, start_time, complete_time,NULL, "Upload");

	// Check if the upload operation was successful
	if (!get_response_code_status(url, res_code)) {
		res = -1;
	}

	return res;
}
int bbf_config_restore(const char *url, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *command, const char *obj_path)
{
	char config_restore[256] = "/tmp/bbf_config_restore";
	int res = 0;

	// Check the file system size if there is sufficient space for downloading the config file
	if (!validate_file_system_size(file_size)) {
		res = -1;
		goto end;
	}

	// Download the firmware image
	time_t start_time = time(NULL);
	long res_code = download_file(config_restore, url, username, password);
	time_t complete_time = time(NULL);

	// Send Transfer Complete Event
	send_transfer_complete_event(command, obj_path, url, res_code, start_time, complete_time, NULL, "Download");

	// Check if the download operation was successful
	if (!get_response_code_status(url, res_code)) {
		res = -1;
		goto end;
	}

	// Validate the CheckSum value according to its algorithm
	if (!validate_checksum_value(config_restore, checksum_algorithm, checksum)) {
		res = -1;
		goto end;
	}

	// Apply config file
	if (dmuci_import(NULL, config_restore))
		res = -1;

end:
	// Remove temporary file
	if (file_exists(config_restore) && strncmp(url, FILE_URI, strlen(FILE_URI)) && remove(config_restore))
		res = -1;

	return res;
}

int bbf_fw_image_download(const char *url, const char *auto_activate, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *bank_id, const char *command, const char *obj_path, const char *commandKey)
{
	char fw_image_path[256] = "/tmp/firmware-XXXXXX";
	json_object *json_obj = NULL;
	bool activate = false;
	int res = 0;

	// Check the file system size if there is sufficient space for downloading the firmware image
	if (!validate_file_system_size(file_size)) {
		res = -1;
		goto end;
	}

	res = mkstemp(fw_image_path);
	if (res == -1) {
		goto end;
	} else {
		close(res); // close the fd, as only filename required
		res = 0;
	}

	// Download the firmware image
	time_t start_time = time(NULL);
	long res_code = download_file(fw_image_path, url, username, password);
	time_t complete_time = time(NULL);

	// Check if the download operation was successful
	if (!get_response_code_status(url, res_code)) {
		res = -1;
		goto end;
	}

	// Validate the CheckSum value according to its algorithm
	if (!validate_checksum_value(fw_image_path, checksum_algorithm, checksum)) {
		res = -1;
		goto end;
	}

	string_to_bool((char *)auto_activate, &activate);
	char *act = (activate) ? "1" : "0";
	// Apply Firmware Image
	dmubus_call_blocking("fwbank", "upgrade", UBUS_ARGS{{"path", fw_image_path, String}, {"auto_activate", act, Boolean}, {"bank", bank_id, Integer}}, 3, &json_obj);

	if (json_obj == NULL) {
		res = -1;
		goto end;
	}

	sleep(60); // Wait for the image to become available

	// Send the transfer complete after image applied
	send_transfer_complete_event(command, obj_path, url, res_code, start_time, complete_time, commandKey, "Download");
	// Reboot the device if auto activation is true
	if (activate) {
		sleep(5); // added additional buffer for TransferComplete! event
		if (dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0) != 0)
			res = -1;
		sleep(10); // Wait for reboot to take action
	}

end:
	// Remove temporary file if ubus upgrade failed and file exists
	if (!json_obj && file_exists(fw_image_path) && strncmp(url, FILE_URI, strlen(FILE_URI))) {
		remove(fw_image_path);
		res = -1;
	}

	if (json_obj != NULL)
		json_object_put(json_obj);

	return res;
}
