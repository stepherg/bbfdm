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
#define MAX_CERT 32

#ifdef LOPENSSL
static char certifcates_paths[MAX_CERT][256];

struct certificate_profile {
	char *path;
	X509 *openssl_cert;
	struct uci_section *dmmap_sect;
};

/*************************************************************
* INIT
**************************************************************/
void init_certificate(char *path,
X509 *cert,
struct uci_section *dmsect, struct certificate_profile *certprofile)
{
	certprofile->path = path;
	certprofile->openssl_cert = cert;
	certprofile->dmmap_sect = dmsect;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static char *get_certificate_sig_alg(int sig_nid)
{
	switch(sig_nid) {
	case NID_sha256WithRSAEncryption:
		return LN_sha256WithRSAEncryption;
	case NID_sha384WithRSAEncryption:
		return LN_sha384WithRSAEncryption;
	case NID_sha512WithRSAEncryption:
		return LN_sha512WithRSAEncryption;
	case NID_sha224WithRSAEncryption:
		return LN_sha224WithRSAEncryption;
	case NID_sha512_224WithRSAEncryption:
		return LN_sha512_224WithRSAEncryption;
	case NID_sha512_256WithRSAEncryption:
		return LN_sha512_224WithRSAEncryption;
	case NID_pbeWithMD2AndDES_CBC:
		return LN_pbeWithMD2AndDES_CBC;
	case NID_pbeWithMD5AndDES_CBC:
		return LN_pbeWithMD5AndDES_CBC;
	case NID_pbeWithMD2AndRC2_CBC:
		return LN_pbeWithMD5AndDES_CBC;
	case NID_pbeWithMD5AndRC2_CBC:
		return LN_pbeWithMD5AndRC2_CBC;
	case NID_pbeWithSHA1AndDES_CBC:
		return LN_pbeWithSHA1AndDES_CBC;
	case NID_pbeWithSHA1AndRC2_CBC:
		return LN_pbeWithSHA1AndDES_CBC;
	case NID_pbe_WithSHA1And128BitRC4:
		return LN_pbe_WithSHA1And128BitRC4;
	case NID_pbe_WithSHA1And40BitRC4:
		return LN_pbe_WithSHA1And40BitRC4;
	case NID_pbe_WithSHA1And3_Key_TripleDES_CBC:
		return LN_pbe_WithSHA1And3_Key_TripleDES_CBC;
	case NID_pbe_WithSHA1And2_Key_TripleDES_CBC:
		return LN_pbe_WithSHA1And2_Key_TripleDES_CBC;
	case NID_pbe_WithSHA1And128BitRC2_CBC:
		return LN_pbe_WithSHA1And128BitRC2_CBC;
	case NID_pbe_WithSHA1And40BitRC2_CBC:
		return LN_pbe_WithSHA1And40BitRC2_CBC;
	case NID_sm3WithRSAEncryption:
		return LN_sm3WithRSAEncryption;
	case NID_shaWithRSAEncryption:
		return LN_shaWithRSAEncryption;
	case NID_md2WithRSAEncryption:
		return LN_md2WithRSAEncryption;
	case NID_md4WithRSAEncryption:
		return LN_md4WithRSAEncryption;
	case NID_md5WithRSAEncryption:
		return LN_md5WithRSAEncryption;
	case NID_sha1WithRSAEncryption:
		return LN_sha1WithRSAEncryption;
	default:
		return "";
	}
}

static char *generate_serial_number(char *text, int length)
{
	int i, j;
	char *hex = (char *)dmcalloc(100, sizeof(char));

	for (i = 0, j = 0; i < length; ++i, j += 3) {
		sprintf(hex + j, "%02x", text[i] & 0xff);
		if (i < length-1)
			sprintf(hex + j + 2, "%c", ':');
	}
	return hex;
}

static void get_certificate_paths(void)
{
	struct uci_section *s = NULL;
	int cidx;

	for (cidx=0; cidx<MAX_CERT; cidx++)
		memset(certifcates_paths[cidx], '\0', 256);

	cidx = 0;

	uci_foreach_sections("owsd", "owsd-listen", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "cert", &cert);
		if (*cert == '\0')
			continue;
		if (cidx >= MAX_CERT)
			break;
		if(!file_exists(cert) || !is_regular_file(cert))
			continue;
		DM_STRNCPY(certifcates_paths[cidx], cert, 256);
		cidx++;
	}

	uci_foreach_sections("openvpn", "openvpn", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "cert", &cert);
		if (*cert == '\0')
			continue;
		if (cidx >= MAX_CERT)
			break;
		if(!file_exists(cert) || !is_regular_file(cert))
			continue;
		DM_STRNCPY(certifcates_paths[cidx], cert, 256);
		cidx++;
	}

	uci_foreach_sections("obuspa", "obuspa", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "cert", &cert);
		if (*cert == '\0')
			continue;
		if (cidx >= MAX_CERT)
			break;
		if(!file_exists(cert) || !is_regular_file(cert))
			continue;
		DM_STRNCPY(certifcates_paths[cidx], cert, 256);
		cidx++;
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseSecurityCertificateInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct uci_section *dmmap_sect = NULL;
	struct certificate_profile certificateprofile = {};

	get_certificate_paths();
	int i;
	for (i = 0; i < MAX_CERT; i++) {
		if(!strlen(certifcates_paths[i]))
			break;
		FILE *fp = fopen(certifcates_paths[i], "r");
		if (fp == NULL)
			continue;
		X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			fclose(fp);
			continue;
		}

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_security", "security_certificate", "path", certifcates_paths[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_security", "security_certificate", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "path", certifcates_paths[i]);
		}
		init_certificate(certifcates_paths[i], cert, dmmap_sect, &certificateprofile);

		inst = handle_instance(dmctx, parent_node, dmmap_sect, "security_certificate_instance", "security_certificate_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&certificateprofile, inst) == DM_STOP)
			break;

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
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	struct stat b;
	char t[sizeof("AAAA-MM-JJTHH:MM:SSZ")] = "0001-01-01T00:00:00Z";
	if (!stat(cert_profile->path, &b))
		strftime(t, sizeof(t), "%Y-%m-%dT%H:%M:%SZ", gmtime(&b.st_mtime));
	*value = dmstrdup(t);
	return 0;
}

static int get_SecurityCertificate_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	ASN1_INTEGER *serial = X509_get_serialNumber(cert_profile->openssl_cert);
	*value = generate_serial_number((char *)serial->data, serial->length);
	return 0;
}

static int get_SecurityCertificate_Issuer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;
	char buf[256] = {0};

	X509_NAME_oneline(X509_get_issuer_name(cert_profile->openssl_cert), buf, sizeof(buf));
	*value = dmstrdup(buf);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');
	return 0;
}

static int get_SecurityCertificate_NotBefore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";
	struct tm not_before_time;
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	char not_before_str[DATE_LEN];
	const ASN1_TIME *not_before = X509_get0_notBefore(cert_profile->openssl_cert);
	ASN1_TIME_to_tm(not_before, &not_before_time);
	strftime(not_before_str, sizeof(not_before_str), "%Y-%m-%dT%H:%M:%SZ", &not_before_time);
	*value = dmstrdup(not_before_str);
	return 0;
}

static int get_SecurityCertificate_NotAfter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";
	struct tm not_after_time;
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	char not_after_str[DATE_LEN];
	const ASN1_TIME *not_after = X509_get0_notAfter(cert_profile->openssl_cert);
	ASN1_TIME_to_tm(not_after, &not_after_time);
	strftime(not_after_str, sizeof(not_after_str), "%Y-%m-%dT%H:%M:%SZ", &not_after_time);
	*value = dmstrdup(not_after_str);
	return 0;
}

static int get_SecurityCertificate_Subject(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;
	char buf[256] = {0};

	X509_NAME_oneline(X509_get_subject_name(cert_profile->openssl_cert), buf, sizeof(buf));
	*value = dmstrdup(buf);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');
	return 0;
}

static int get_SecurityCertificate_SignatureAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	*value = dmstrdup(get_certificate_sig_alg(X509_get_signature_nid(cert_profile->openssl_cert)));
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Security. *** */
DMOBJ tSecurityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Certificate", &DMREAD, NULL, NULL, NULL, browseSecurityCertificateInst, NULL, NULL, NULL, tSecurityCertificateParams, NULL, BBFDM_BOTH, LIST_KEY{"SerialNumber", "Issuer", NULL}},
{0}
};

DMLEAF tSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CertificateNumberOfEntries", &DMREAD, DMT_UNINT, get_Security_CertificateNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Security.Certificate.{i}. *** */
DMLEAF tSecurityCertificateParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_SecurityCertificate_Enable, set_SecurityCertificate_Enable, BBFDM_BOTH},
{"LastModif", &DMREAD, DMT_TIME, get_SecurityCertificate_LastModif, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_SecurityCertificate_SerialNumber, NULL, BBFDM_BOTH},
{"Issuer", &DMREAD, DMT_STRING, get_SecurityCertificate_Issuer, NULL, BBFDM_BOTH},
{"NotBefore", &DMREAD, DMT_TIME, get_SecurityCertificate_NotBefore, NULL, BBFDM_BOTH},
{"NotAfter", &DMREAD, DMT_TIME, get_SecurityCertificate_NotAfter, NULL, BBFDM_BOTH},
{"Subject", &DMREAD, DMT_STRING, get_SecurityCertificate_Subject, NULL, BBFDM_BOTH},
//{"SubjectAlt", &DMREAD, DMT_STRING, get_SecurityCertificate_SubjectAlt, NULL, BBFDM_BOTH},
{"SignatureAlgorithm", &DMREAD, DMT_STRING, get_SecurityCertificate_SignatureAlgorithm, NULL, BBFDM_BOTH},
{0}
};

#endif /* LOPENSSL */
