/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "userinterface.h"

/**************************************************************************
* GET & SET PARAMETERS
***************************************************************************/
static void add_default_rule(char *port, char *enable, char *owsd)
{
	struct uci_section *ss;

	dmuci_add_section("firewall", "rule", &ss);
	dmuci_set_value_by_section(ss, "name", "juci-remote-access");
	dmuci_set_value_by_section(ss, "src", "wan");
	dmuci_set_value_by_section(ss, "proto", "tcp");
	dmuci_set_value_by_section(ss, "target", "ACCEPT");
	dmuci_set_value_by_section(ss, "dest_port", port);
	dmuci_set_value_by_section(ss, "owsd", owsd);
	dmuci_set_value_by_section(ss, "enabled", enable);
}

static int get_userint_remoteaccesss_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss = NULL;
	char *rule_name, *rule_enabled;

	uci_foreach_sections("firewall", "rule", ss) {
		dmuci_get_value_by_section_string(ss, "name", &rule_name);
		if (strcmp(rule_name, "juci-remote-access") == 0) {
			dmuci_get_value_by_section_string(ss, "enabled", &rule_enabled);
			*value= (strcmp(rule_enabled, "0") == 0) ? "0": "1";
			return 0;
		}
	}
	*value = "0";
	return 0;
}

static int set_userint_remoteaccesss_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss;
	char *rule_name;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			uci_foreach_sections("firewall", "rule", ss) {
				dmuci_get_value_by_section_string(ss, "name", &rule_name);
				if (strcmp(rule_name, "juci-remote-access") == 0) {
					dmuci_set_value_by_section(ss, "enabled", b ? "" : "0");
					return 0;
				}
			}
			add_default_rule("80", value, "wan");
			return 0;
	}
	return 0;
}

static int get_userint_remoteaccesss_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss = NULL;
	char *rule_name, *dest_port;

	uci_foreach_sections("firewall", "rule", ss) {
		dmuci_get_value_by_section_string(ss, "name", &rule_name);
		if (strcmp(rule_name, "juci-remote-access") == 0) {
			dmuci_get_value_by_section_string(ss, "dest_port", &dest_port);
			*value= dest_port;
			return 0;
		}
	}
	*value = "80";
	return 0;
}

static int set_userint_remoteaccesss_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss;
	char *rule_name, *owsd;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			uci_foreach_sections("firewall", "rule", ss) {
				dmuci_get_value_by_section_string(ss, "name", &rule_name);
				if (strcmp(rule_name, "juci-remote-access") == 0) {
					dmuci_set_value_by_section(ss, "dest_port", value);
					dmuci_get_value_by_section_string(ss, "owsd", &owsd);
					dmuci_set_value("owsd", owsd, "port", value);
					return 0;
				}
			}

			add_default_rule(value, "0", "wan");
			dmuci_set_value("owsd", "wan", "port", value);
			return 0;
	}
	return 0;
}

static bool get_supportedprotocols(void)
{
	char *cert = NULL, *key = NULL, *ca = NULL;

	dmuci_get_option_value_string("owsd", "wan_https", "cert", &cert);
	dmuci_get_option_value_string("owsd", "wan_https", "key", &key);
	dmuci_get_option_value_string("owsd", "wan_https", "ca", &ca);

	if ((cert && *cert && file_exists(cert)) ||
		(key && *key && file_exists(key)) ||
		(ca && *ca && file_exists(ca)))
		return true;

	return false;
}

static int get_userint_remoteaccesss_supportedprotocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (get_supportedprotocols()) ? "HTTP,HTTPS" : "HTTP";
	return 0;
}

static int get_userint_remoteaccesss_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss = NULL;
	char *rule_name, *rule_owsd;

	uci_foreach_sections("firewall", "rule", ss) {
		dmuci_get_value_by_section_string(ss, "name", &rule_name);
		if (strcmp(rule_name, "juci-remote-access") == 0) {
			dmuci_get_value_by_section_string(ss, "owsd", &rule_owsd);
			if (strcmp(rule_owsd, "wan") == 0)
				*value = "HTTP";
			else
				*value = "HTTPS";
			return 0;
		}
	}
	*value = "HTTP";
	return 0;
}

static int set_userint_remoteaccesss_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedProtocols, NULL))
				return FAULT_9007;

			if (get_supportedprotocols()) {
				if ((strcmp(value, "HTTP") != 0) && (strcmp(value, "HTTPS") != 0))
					return FAULT_9007;
			} else {
				if (strcmp(value, "HTTP") != 0)
					return FAULT_9007;
			}
			return 0;
		case VALUESET:
			uci_foreach_sections("firewall", "rule", ss) {
				char *rule_name;

				dmuci_get_value_by_section_string(ss, "name", &rule_name);
				if (strcmp(rule_name, "juci-remote-access") == 0) {
					dmuci_set_value_by_section(ss, "owsd", (strcmp(value, "HTTPS") == 0) ? "wan_https" : "wan");
					return 0;
				}
			}

			add_default_rule("80", "0", (strcmp(value, "HTTPS") == 0) ? "wan_https" : "wan");
			return 0;
	}
	return 0;
}

/* *** Device.UserInterface. *** */
DMOBJ tUserInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"RemoteAccess", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUserInterfaceRemoteAccessParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UserInterface.RemoteAccess. *** */
DMLEAF tUserInterfaceRemoteAccessParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_userint_remoteaccesss_enable, set_userint_remoteaccesss_enable, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_userint_remoteaccesss_port, set_userint_remoteaccesss_port, BBFDM_BOTH},
{"SupportedProtocols", &DMREAD, DMT_STRING, get_userint_remoteaccesss_supportedprotocols, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_userint_remoteaccesss_protocol, set_userint_remoteaccesss_protocol, BBFDM_BOTH},
{0}
};
