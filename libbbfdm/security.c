/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "security.h"

#define DATE_LEN 128
#define CERT_PATH_LEN 512
#define MAX_CERT 256

#include <openssl/x509.h>
#include <openssl/pem.h>

#define SYSTEM_CERT_PATH "/etc/ssl/certs"

static char certifcates_paths[MAX_CERT][CERT_PATH_LEN];

struct certificate_profile {
	char *path;
	X509 *cert;
};

/*************************************************************
* INIT
**************************************************************/
void init_certificate(char *path, X509 *cert, struct certificate_profile *certprofile)
{
	certprofile->path = path;
	certprofile->cert = cert;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static char *get_certificate_sig_alg(int sig_nid)
{
	switch(sig_nid) {
	case NID_sha256WithRSAEncryption:
		return "sha256WithRSAEncryption";
	case NID_sha384WithRSAEncryption:
		return "sha384WithRSAEncryption";
	case NID_sha512WithRSAEncryption:
		return "sha512WithRSAEncryption";
	case NID_sha224WithRSAEncryption:
		return "sha224WithRSAEncryption";
	case NID_md5WithRSAEncryption:
		return "md5WithRSAEncryption";
	case NID_sha1WithRSAEncryption:
		return "sha1WithRSAEncryption";
	default:
		return "";
	}
	return "";
}

static char *generate_serial_number(const char *text, int length)
{
	unsigned pos = 0;
	char *hex = (char *)dmcalloc(100, sizeof(char));
	if (!hex)
		return dmstrdup("");

	for (int i = 0; i < length; i++) {
		pos += snprintf(&hex[pos], 100 - pos, "%02x:", text[i] & 0xff);
	}

	if (pos)
		hex[pos - 1] = 0;

	return hex;
}

static int fill_certificate_paths(const char *dir_path, int *cidx)
{
	struct dirent *d_file = NULL;
	DIR *dir = NULL;
	char cert_path[CERT_PATH_LEN];

	sysfs_foreach_file(dir_path, dir, d_file) {

		if (d_file->d_name[0] == '.' || !strstr(d_file->d_name, ".0"))
			continue;

		if (*cidx >= MAX_CERT)
			break;

		snprintf(cert_path, sizeof(cert_path), "%s/%s", dir_path, d_file->d_name);

		if (!file_exists(cert_path) || !is_regular_file(cert_path))
			continue;

		DM_STRNCPY(certifcates_paths[*cidx], cert_path, CERT_PATH_LEN);
		(*cidx)++;
	}

	if (dir)
		closedir (dir);

	return 0;
}

static int get_certificate_paths(void)
{
	char *cert = NULL;
	int cidx = 0;

	for (cidx = 0; cidx < MAX_CERT; cidx++)
		memset(certifcates_paths[cidx], '\0', CERT_PATH_LEN);

	cidx = 0;

	fill_certificate_paths(SYSTEM_CERT_PATH, &cidx);

	dmuci_get_option_value_string("cwmp", "acs", "ssl_capath", &cert);
	if (!DM_STRLEN(cert))
		return 0;

	if (strncmp(cert, SYSTEM_CERT_PATH, strlen(SYSTEM_CERT_PATH)) == 0)
		return 0;

	if (folder_exists(cert)) {
		fill_certificate_paths(cert, &cidx);
	} else {
		if (cidx >= MAX_CERT)
			return -1;

		if (!file_exists(cert) || !is_regular_file(cert))
			return -1;

		DM_STRNCPY(certifcates_paths[cidx], cert, CERT_PATH_LEN);
	}

	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseSecurityCertificateInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct certificate_profile certificateprofile = {0};
	struct uci_section *dmmap_sec = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int i, status;

	get_certificate_paths();

	for (i = 0, status = DM_OK; i < MAX_CERT && status != DM_STOP; i++) {

		if(!DM_STRLEN(certifcates_paths[i]))
			break;

		FILE *fp = fopen(certifcates_paths[i], "r");
		if (fp == NULL)
			continue;

		X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			fclose(fp);
			continue;
		}

		if ((dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_security", "security_certificate", "path", certifcates_paths[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_security", "security_certificate", &dmmap_sec);
			dmuci_set_value_by_section_bbfdm(dmmap_sec, "path", certifcates_paths[i]);
		}

		init_certificate(certifcates_paths[i], cert, &certificateprofile);

		curr_data.additional_data = (void *)&certificateprofile;

		inst = handle_instance(dmctx, parent_node, dmmap_sec, "security_certificate_instance", "security_certificate_alias");

		status = DM_LINK_INST_OBJ(dmctx, parent_node, &curr_data, inst);

		X509_free(cert);
		cert = NULL;
		fclose(fp);
		fp = NULL;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Security_CertificateNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseSecurityCertificateInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_SecurityCertificate_LastModif(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;
	char buf[sizeof("0001-01-01T00:00:00Z")] = {0};
	struct stat b;

	if (!stat(cert_profile->path, &b))
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&b.st_mtime));
	else
		DM_STRNCPY(buf, "0001-01-01T00:00:00Z", sizeof("0001-01-01T00:00:00Z"));

	*value = dmstrdup(buf);
	return 0;
}

static int get_SecurityCertificate_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;

	ASN1_INTEGER *serial = X509_get_serialNumber(cert_profile->cert);
	*value = generate_serial_number((char *)serial->data, serial->length);

	return 0;
}

static int get_SecurityCertificate_Issuer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;
	char buf[256] = {0};

	X509_NAME_oneline(X509_get_issuer_name(cert_profile->cert), buf, sizeof(buf));
	*value = dmstrdup(buf);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');

	return 0;
}

static int get_SecurityCertificate_NotBefore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;

	char not_before_str[DATE_LEN];
	struct tm tm;

	const ASN1_TIME *not_before = X509_get0_notBefore(cert_profile->cert);

	ASN1_TIME_to_tm(not_before, &tm);

	strftime(not_before_str, sizeof(not_before_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
	*value = dmstrdup(not_before_str);

	return 0;
}

static int get_SecurityCertificate_NotAfter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;

	char not_after_str[DATE_LEN];
	struct tm tm;

	const ASN1_TIME *not_after = X509_get0_notAfter(cert_profile->cert);

	ASN1_TIME_to_tm((ASN1_TIME *)not_after, &tm);

	strftime(not_after_str, sizeof(not_after_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
	*value = dmstrdup(not_after_str);

	return 0;
}

static int get_SecurityCertificate_Subject(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;
	char buf[256] = {0};

	X509_NAME_oneline(X509_get_subject_name(cert_profile->cert), buf, sizeof(buf));
	*value = dmstrdup(buf);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');

	return 0;
}

static int get_SecurityCertificate_SignatureAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)((struct dm_data *)data)->additional_data;

	*value = dmstrdup(get_certificate_sig_alg(X509_get_signature_nid(cert_profile->cert)));

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Security. *** */
DMOBJ tSecurityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Certificate", &DMREAD, NULL, NULL, NULL, browseSecurityCertificateInst, NULL, NULL, NULL, tSecurityCertificateParams, NULL, BBFDM_CWMP, NULL},
{0}
};

DMLEAF tSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"CertificateNumberOfEntries", &DMREAD, DMT_UNINT, get_Security_CertificateNumberOfEntries, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.Security.Certificate.{i}. *** */
DMLEAF tSecurityCertificateParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_SecurityCertificate_Enable, set_SecurityCertificate_Enable, BBFDM_CWMP},
{"LastModif", &DMREAD, DMT_TIME, get_SecurityCertificate_LastModif, NULL, BBFDM_CWMP},
{"SerialNumber", &DMREAD, DMT_STRING, get_SecurityCertificate_SerialNumber, NULL, BBFDM_CWMP, DM_FLAG_UNIQUE},
{"Issuer", &DMREAD, DMT_STRING, get_SecurityCertificate_Issuer, NULL, BBFDM_CWMP, DM_FLAG_UNIQUE},
{"NotBefore", &DMREAD, DMT_TIME, get_SecurityCertificate_NotBefore, NULL, BBFDM_CWMP},
{"NotAfter", &DMREAD, DMT_TIME, get_SecurityCertificate_NotAfter, NULL, BBFDM_CWMP},
{"Subject", &DMREAD, DMT_STRING, get_SecurityCertificate_Subject, NULL, BBFDM_CWMP},
//{"SubjectAlt", &DMREAD, DMT_STRING, get_SecurityCertificate_SubjectAlt, NULL, BBFDM_CWMP},
{"SignatureAlgorithm", &DMREAD, DMT_STRING, get_SecurityCertificate_SignatureAlgorithm, NULL, BBFDM_CWMP},
{0}
};
