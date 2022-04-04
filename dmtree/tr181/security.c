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

#ifdef LSSL

#ifdef LMBEDTLS
#include <mbedtls/x509_crt.h>
#include <mbedtls/base64.h>
#else
#include <openssl/x509.h>
#include <openssl/pem.h>
#endif

static char certifcates_paths[MAX_CERT][256];

struct certificate_profile {
	char *path;
#ifdef LMBEDTLS
	mbedtls_x509_crt cert;
#else
	X509 *cert;
#endif
	struct uci_section *dmmap_sect;
};

/*************************************************************
* INIT
**************************************************************/
void init_certificate(char *path,
#ifdef LMBEDTLS
mbedtls_x509_crt cert,
#else
X509 *cert,
#endif
struct uci_section *dmsect, struct certificate_profile *certprofile)
{
	certprofile->path = path;
	certprofile->cert = cert;
	certprofile->dmmap_sect = dmsect;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
#ifdef LMBEDTLS
static char *get_certificate_md(mbedtls_md_type_t sig_md)
{
	switch(sig_md) {
	case MBEDTLS_MD_MD2:
		return "md2";
	case MBEDTLS_MD_MD4:
		return "md4";
	case MBEDTLS_MD_MD5:
		return "md5";
	case MBEDTLS_MD_SHA1:
		return "sha1";
	case MBEDTLS_MD_SHA224:
		return "sha224";
	case MBEDTLS_MD_SHA256:
		return "sha256";
	case MBEDTLS_MD_SHA384:
		return "sha384";
	case MBEDTLS_MD_SHA512:
		return "sha512";
	case MBEDTLS_MD_RIPEMD160:
		return "ripemd160";
	default:
		return "";
	}
	return "";
}

static char *get_certificate_pk(mbedtls_pk_type_t sig_pk)
{
	switch(sig_pk) {
	case MBEDTLS_PK_RSA:
		return "RSA";
	case MBEDTLS_PK_ECKEY:
		return "ECKEY";
	case MBEDTLS_PK_ECKEY_DH:
		return "ECKEYDH";
	case MBEDTLS_PK_ECDSA:
		return "ECDSA";
	case MBEDTLS_PK_RSA_ALT:
		return "RSAALT";
	case MBEDTLS_PK_RSASSA_PSS:
		return "RSASSAPSS";
	default:
		return "";
	}
	return "";
}
#else
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
#endif

static char *generate_serial_number(char *text, int length)
{
	char *hex = (char *)dmcalloc(100, sizeof(char));
	unsigned pos = 0;

	for (int i = 0; i < length; i++) {
		pos += snprintf(&hex[pos], 100 - pos, "%02x:", text[i] & 0xff);
	}

	if (pos)
		hex[pos - 1] = 0;

	return hex;
}

static void get_certificate_paths(void)
{
	struct uci_section *s = NULL;
	int cidx;

	for (cidx = 0; cidx < MAX_CERT; cidx++)
		memset(certifcates_paths[cidx], '\0', 256);

	cidx = 0;

	uci_foreach_sections("nginx", "server", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "ssl_certificate", &cert);
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
	int i, status;

	get_certificate_paths();

	for (i = 0, status = DM_OK; i < MAX_CERT && status != DM_STOP; i++) {

		if(!DM_STRLEN(certifcates_paths[i]))
			break;

#ifdef LMBEDTLS
		mbedtls_x509_crt cert;

		mbedtls_x509_crt_init(&cert);
		if (mbedtls_x509_crt_parse_file(&cert, certifcates_paths[i]) < 0)
			continue;
#else
		FILE *fp = fopen(certifcates_paths[i], "r");
		if (fp == NULL)
			continue;

		X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			fclose(fp);
			continue;
		}
#endif

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_security", "security_certificate", "path", certifcates_paths[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_security", "security_certificate", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "path", certifcates_paths[i]);
		}

		init_certificate(certifcates_paths[i], cert, dmmap_sect, &certificateprofile);

		inst = handle_instance(dmctx, parent_node, dmmap_sect, "security_certificate_instance", "security_certificate_alias");

		status = DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&certificateprofile, inst);

#ifdef LMBEDTLS
		mbedtls_x509_crt_free(&cert);
#else
		X509_free(cert);
		cert = NULL;
		fclose(fp);
		fp = NULL;
#endif
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
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;
	char buf[sizeof("AAAA-MM-JJTHH:MM:SSZ")] = "0001-01-01T00:00:00Z";
	struct stat b;

	if (!stat(cert_profile->path, &b))
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&b.st_mtime));

	*value = dmstrdup(buf);
	return 0;
}

static int get_SecurityCertificate_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;

#ifdef LMBEDTLS
	*value = generate_serial_number((char *)cert_profile->cert.serial.p, cert_profile->cert.serial.len);
#else
	ASN1_INTEGER *serial = X509_get_serialNumber(cert_profile->cert);
	*value = generate_serial_number((char *)serial->data, serial->length);
#endif

	return 0;
}

static int get_SecurityCertificate_Issuer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;
	char buf[256] = {0};

#ifdef LMBEDTLS
	if (mbedtls_x509_dn_gets(buf, sizeof(buf), &cert_profile->cert.issuer) < 0)
		return -1;

	*value = dmstrdup(buf);
#else
	X509_NAME_oneline(X509_get_issuer_name(cert_profile->cert), buf, sizeof(buf));
	*value = dmstrdup(buf);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');
#endif

	return 0;
}

static int get_SecurityCertificate_NotBefore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;

#ifdef LMBEDTLS
	dmasprintf(value, "%04d-%02d-%02dT%02d:%02d:%02dZ", cert_profile->cert.valid_from.year,
														cert_profile->cert.valid_from.mon,
														cert_profile->cert.valid_from.day,
														cert_profile->cert.valid_from.hour,
														cert_profile->cert.valid_from.min,
														cert_profile->cert.valid_from.sec);
#else
	char not_before_str[DATE_LEN];
	struct tm tm;

	const ASN1_TIME *not_before = X509_get0_notBefore(cert_profile->cert);

#ifdef LWOLFSSL
	ASN1_TIME_to_string((ASN1_TIME *)not_before, not_before_str, DATE_LEN);
	if (!strptime(not_before_str, "%b %d %H:%M:%S %Y", &tm))
		return -1;
#else
	ASN1_TIME_to_tm(not_before, &tm);
#endif

	strftime(not_before_str, sizeof(not_before_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
	*value = dmstrdup(not_before_str);
#endif

	return 0;
}

static int get_SecurityCertificate_NotAfter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;

#ifdef LMBEDTLS
	dmasprintf(value, "%04d-%02d-%02dT%02d:%02d:%02dZ", cert_profile->cert.valid_to.year,
														cert_profile->cert.valid_to.mon,
														cert_profile->cert.valid_to.day,
														cert_profile->cert.valid_to.hour,
														cert_profile->cert.valid_to.min,
														cert_profile->cert.valid_to.sec);
#else
	char not_after_str[DATE_LEN];
	struct tm tm;

	const ASN1_TIME *not_after = X509_get0_notAfter(cert_profile->cert);

#ifdef LWOLFSSL
	ASN1_TIME_to_string((ASN1_TIME *)not_after, not_after_str, DATE_LEN);
	if (!strptime(not_after_str, "%b %d %H:%M:%S %Y", &tm))
		return -1;
#else
	ASN1_TIME_to_tm((ASN1_TIME *)not_after, &tm);
#endif

	strftime(not_after_str, sizeof(not_after_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
	*value = dmstrdup(not_after_str);
#endif

	return 0;
}

static int get_SecurityCertificate_Subject(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;
	char buf[256] = {0};

#if LMBEDTLS
	if (mbedtls_x509_dn_gets(buf, sizeof(buf), &cert_profile->cert.subject) < 0)
		return -1;

	*value = dmstrdup(buf);
#else
	X509_NAME_oneline(X509_get_subject_name(cert_profile->cert), buf, sizeof(buf));
	*value = dmstrdup(buf);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');
#endif

	return 0;
}

static int get_SecurityCertificate_SignatureAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile *)data;

#ifdef LMBEDTLS
	dmasprintf(value, "%sWith%sEncryption", get_certificate_md(cert_profile->cert.sig_md), get_certificate_pk(cert_profile->cert.sig_pk));
#else
	*value = dmstrdup(get_certificate_sig_alg(X509_get_signature_nid(cert_profile->cert)));
#endif

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Security. *** */
DMOBJ tSecurityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Certificate", &DMREAD, NULL, NULL, NULL, browseSecurityCertificateInst, NULL, NULL, NULL, tSecurityCertificateParams, NULL, BBFDM_BOTH, LIST_KEY{"SerialNumber", "Issuer", NULL}, "2.4"},
{0}
};

DMLEAF tSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"CertificateNumberOfEntries", &DMREAD, DMT_UNINT, get_Security_CertificateNumberOfEntries, NULL, BBFDM_BOTH, "2.4"},
{0}
};

/* *** Device.Security.Certificate.{i}. *** */
DMLEAF tSecurityCertificateParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_SecurityCertificate_Enable, set_SecurityCertificate_Enable, BBFDM_BOTH, "2.4"},
{"LastModif", &DMREAD, DMT_TIME, get_SecurityCertificate_LastModif, NULL, BBFDM_BOTH, "2.4"},
{"SerialNumber", &DMREAD, DMT_STRING, get_SecurityCertificate_SerialNumber, NULL, BBFDM_BOTH, "2.4"},
{"Issuer", &DMREAD, DMT_STRING, get_SecurityCertificate_Issuer, NULL, BBFDM_BOTH, "2.4"},
{"NotBefore", &DMREAD, DMT_TIME, get_SecurityCertificate_NotBefore, NULL, BBFDM_BOTH, "2.4"},
{"NotAfter", &DMREAD, DMT_TIME, get_SecurityCertificate_NotAfter, NULL, BBFDM_BOTH, "2.4"},
{"Subject", &DMREAD, DMT_STRING, get_SecurityCertificate_Subject, NULL, BBFDM_BOTH, "2.4"},
//{"SubjectAlt", &DMREAD, DMT_STRING, get_SecurityCertificate_SubjectAlt, NULL, BBFDM_BOTH, "2.4"},
{"SignatureAlgorithm", &DMREAD, DMT_STRING, get_SecurityCertificate_SignatureAlgorithm, NULL, BBFDM_BOTH, "2.4"},
{0}
};

#endif /* LSSL */
