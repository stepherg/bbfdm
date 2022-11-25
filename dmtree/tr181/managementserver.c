/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "managementserver.h"
#include "dmbbfcommon.h"

#define DU_STATE_CHANGE_SEC_NAME "du_state_change"
#define TRANSFER_COMPL_SEC_NAME "transfer_complete"

static char *CWMP_EVENTS[] = {"0 BOOTSTRAP", "1 BOOT", "2 PERIODIC", "3 SCHEDULED", "5 KICKED", "6 CONNECTION REQUEST", "7 TRANSFER COMPLETE", "8 DIAGNOSTICS COMPLETE", "9 REQUEST DOWNLOAD", "10 AUTONOMOUS TRANSFER COMPLETE", "11 DU STATE CHANGE COMPLETE", "M Reboot", "M ScheduleInform", "M Download", "M ScheduleDownload", "M Upload", "M ChangeDUState", "14 HEARTBEAT", NULL};
static char *DUStateOperationType[] = {"Install", "Update", "Uninstall", NULL};
static char *DUStateResultType[] = {"Success", "Failure", "Both", NULL};
static char *DUStateFaultCode[] = {"9001", "9003", "9012", "9013", "9015", "9016", "9017", "9018","9022", "9023", "9024", "9025", "9026", "9027", "9028", "9029", "9030", "9031", "9032", NULL};


static char *TCTransferType[] = {"Upload", "Download", "Both", NULL};
static char *TCResultType[] = {"Success", "Failure", "Both", NULL};
static char *TCFileType[] = {"1 Firmware Upgrade Image", "2 Web Content", "3 Vendor Configuration File", "4 Vendor Log File", NULL};

enum suboption_125 {
	OPT_OUI,
	OPT_SERIAL,
	OPT_CLASS
};

struct manageable_device_args {
	char mac[18];
	char oui[7];
	char serial[65];
	char class[65];
	char host[1025];
};

struct manageable_device_node
{
	struct list_head list;
	struct manageable_device_args dev;
};

static struct uci_section* get_autonomous_notify_section(char *sec_name)
{
	struct uci_section *s = NULL;
	uci_foreach_sections("cwmp", "autonomous_notify", s) {
		if (strcmp(section_name(s), sec_name) == 0) {
			return s;
		}
	}

	dmuci_add_section("cwmp", "autonomous_notify", &s);
	if (s != NULL)
		dmuci_rename_section_by_section(s, sec_name);

	return s;
}

static void get_option125_suboption(char *data, int option, char *dst, int dst_len)
{
	int data_len = 0, len = 0;
	char *pos = NULL;

	data_len = DM_STRLEN(data);

	if (data_len == 0)
		return;

	switch (option) {
	case OPT_OUI:
		pos = strstr(data, "oui_len");
		if (pos == NULL)
			return;

		sscanf(pos, "oui_len=%d", &len);
		pos = strstr(data, "device_oui=");
		if (pos == NULL)
			return;

		pos = pos + 11;
		if (pos >= (data + data_len))
			return;

		if (len >= dst_len)
			len = dst_len;
		else
			len = len + 1;

		snprintf(dst, len, "%s", pos);
		break;
	case OPT_SERIAL:
		pos = strstr(data, "serial_len");
		if (pos == NULL)
			return;

		sscanf(pos, "serial_len=%d", &len);
		pos = strstr(data, "device_serial=");
		if (pos == NULL)
			return;

		pos = pos + 14;
		if (pos >= (data + data_len))
			return;

		if (len >= dst_len)
			len = dst_len;
		else
			len = len + 1;

		snprintf(dst, len, "%s", pos);
		break;
	case OPT_CLASS:
		pos = strstr(data, "class_len");
		if (pos == NULL)
			return;

		sscanf(pos, "class_len=%d", &len);
		pos = strstr(data, "device_class=");
		if (pos == NULL)
			return;

		pos = pos + 13;
		if (pos >= (data + data_len))
			return;

		if (len >= dst_len)
			len = dst_len;
		else
			len = len + 1;

		snprintf(dst, len, "%s", pos);
		break;
	default:
		return;
	}
}

static bool is_active_host(const char *mac, json_object *res)
{
	json_object *host_obj = NULL, *arrobj = NULL;
	int i = 0;
	bool active = false;

	dmjson_foreach_obj_in_array(res, arrobj, host_obj, i, 1, "hosts") {
		if (strcmp(dmjson_get_value(host_obj, 1, "macaddr"), mac) == 0) {
			char *val = dmjson_get_value(host_obj, 1, "active");
			string_to_bool(val, &active);
			break;
		}
	}

	return active;
}

static int browseManageableDevice(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	FILE *f = fopen(DHCP_CLIENT_OPTIONS_FILE, "r");
	if (f == NULL)
		return 0;

	struct manageable_device_args device;
	struct manageable_device_node *dev_p = NULL;
	char line[2048];
	char *inst = NULL;
	int id = 0;
	json_object *res = NULL;
	LIST_HEAD(dev_list);

	dmubus_call("topology", "hosts", UBUS_ARGS{0}, 0, &res);

	while (fgets(line, sizeof(line), f) != NULL) {
		remove_new_line(line);

		memset(&device, 0, sizeof(device));

		sscanf(line, "%17s", device.mac);

		if (DM_STRLEN(device.mac) < 17)
			continue;

		char *linker = NULL;
		adm_entry_get_linker_param(dmctx, "Device.Hosts.Host.", device.mac, &linker);
		if (DM_STRLEN(linker) == 0)
			continue;

		/* check that the host is still active or not */
		if (!is_active_host(device.mac, res))
			continue;

		strncpy(device.host, linker, 1024);
		get_option125_suboption(line, OPT_OUI, device.oui, sizeof(device.oui));
		get_option125_suboption(line, OPT_SERIAL, device.serial, sizeof(device.serial));
		get_option125_suboption(line, OPT_CLASS, device.class, sizeof(device.class));

		if (DM_STRCMP(device.oui, "-") == 0 || DM_STRCMP(device.serial, "-") == 0)
			continue;

		/* check if already added in the list */
		bool found = false;
		list_for_each_entry(dev_p, &dev_list, list) {
			if (strcmp(dev_p->dev.oui, device.oui) == 0 && strcmp(dev_p->dev.serial, device.serial) == 0 &&
			    strcmp(dev_p->dev.class, device.class) == 0) {
				found = true;
				break;
			}
		}

		if (found == true)
			continue;

		/* add device in device list */
		struct manageable_device_node *node = dmcalloc(1, sizeof(struct manageable_device_node));
		if (node == NULL)
			continue;

		list_add_tail(&node->list, &dev_list);
		snprintf(node->dev.class, sizeof(node->dev.class), "%s", device.class);
		snprintf(node->dev.serial, sizeof(node->dev.serial), "%s", device.serial);
		snprintf(node->dev.oui, sizeof(node->dev.oui), "%s", device.oui);

		/* add device instance */
		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&device, inst) == DM_STOP)
			break;
	}

	/* free device list */
	dev_p = NULL;
	while (dev_list.next != &dev_list) {
		dev_p = list_entry(dev_list.next, struct manageable_device_node, list);
		list_del(&dev_p->list);
	}

	fclose(f);
	return 0;

}

/*#Device.ManagementServer.URL!UCI:cwmp/acs,acs/url*/
static int get_management_server_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp = NULL, *url = NULL, *dhcp_url = NULL;
	bool discovery = false;

	dmuci_get_option_value_string("cwmp", "acs", "dhcp_discovery", &dhcp);
	dmuci_get_option_value_string("cwmp", "acs", "url", &url);
	dmuci_get_option_value_string("cwmp", "acs", "dhcp_url", &dhcp_url);

	discovery = dmuci_string_to_boolean(dhcp);

	if ((discovery == true) && (DM_STRLEN(dhcp_url) != 0))
		*value = dhcp_url;
	else if (DM_STRLEN(url) != 0)
		*value = url;
	else
		*value = "";

	return 0;
}

static int set_management_server_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "dhcp_discovery", "disable");
			dmuci_set_value("cwmp", "acs", "url", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.Username!UCI:cwmp/acs,acs/userid*/
static int get_management_server_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "userid", value);
	return 0;	
}

static int set_management_server_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "userid", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.Password!UCI:cwmp/acs,acs/passwd*/
static int set_management_server_passwd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "passwd", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.ScheduleReboot!UCI:cwmp/cpe,cpe/schedule_reboot*/
static int get_management_server_schedule_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "schedule_reboot", value);
	return 0;
}

static int set_management_server_schedule_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "schedule_reboot", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.DelayReboot!UCI:cwmp/cpe,cpe/delay_reboot*/
static int get_management_server_delay_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "cpe", "delay_reboot", "-1");
	return 0;
}

static int set_management_server_delay_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "delay_reboot", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.ParameterKey!UCI:cwmp/acs,acs/ParameterKey*/
static int get_management_server_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_varstate("cwmp", "cpe", "ParameterKey", value);
	return 0;	
}

/*#Device.ManagementServer.PeriodicInformEnable!UCI:cwmp/acs,acs/periodic_inform_enable*/
static int get_management_server_periodic_inform_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "periodic_inform_enable", "1");
	return 0;	
}

static int set_management_server_periodic_inform_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:			
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp", "acs", "periodic_inform_enable", b ? "1" : "0");
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.PeriodicInformInterval!UCI:cwmp/acs,acs/periodic_inform_interval*/
static int get_management_server_periodic_inform_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "periodic_inform_interval", "1800");
	return 0;
}

static int set_management_server_periodic_inform_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "periodic_inform_interval", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.PeriodicInformTime!UCI:cwmp/acs,acs/periodic_inform_time*/
static int get_management_server_periodic_inform_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "periodic_inform_time", value);
	return 0;	
}

static int set_management_server_periodic_inform_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "periodic_inform_time", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

static int network_get_ipaddr(char *iface, int ipver, char **value)
{
	json_object *res = NULL, *jobj = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", iface, String}}, 1, &res);
	DM_ASSERT(res, *value = "");


	if (ipver == 6)
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
	else
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");

	*value = dmjson_get_value(jobj, 1, "address");

	if ((*value)[0] == '\0')
		return -1;

	return 0;
}

static void get_management_ip_port(char **listen_addr)
{
	char *ip = NULL, *port = NULL, *interface = NULL, *if_name = NULL, *version = NULL;

	dmuci_get_option_value_string("cwmp", "cpe", "default_wan_interface", &interface);
	dmuci_get_option_value_string("cwmp", "cpe", "interface", &if_name);
	dmuci_get_option_value_string("cwmp", "acs", "ip_version", &version);
	dmuci_get_option_value_string("cwmp", "cpe", "port", &port);

	if (network_get_ipaddr(interface, *version == '6' ? 6 : 4, &ip) == -1) {
		if (if_name[0] == '\0')
			return;

		ip = (*version == '6') ? get_ipv6(if_name) : ioctl_get_ipv4(if_name);
	}

	if (ip[0] != '\0' && port[0] != '\0') {
		dmasprintf(listen_addr, "%s:%s", ip, port);
	}
}

/*#Device.ManagementServer.ConnectionRequestURL!UCI:cwmp/cpe,cpe/port*/
static int get_management_server_connection_request_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mgmt_addr = NULL;
	get_management_ip_port(&mgmt_addr);

	if (mgmt_addr != NULL) {
		char *path;
		dmuci_get_option_value_string("cwmp", "cpe", "path", &path);
		dmasprintf(value, "http://%s/%s", mgmt_addr, path ? path : "");
	}

	return 0;
}

static int get_upd_cr_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *stunc_enabled;
	bool enabled;

	dmuci_get_option_value_string("stunc", "stunc", "enabled", &stunc_enabled);
	enabled = dmuci_string_to_boolean(stunc_enabled);

	if (enabled == true)
		dmuci_get_option_value_string_varstate("stunc", "stunc", "crudp_address", value);
	else
		get_management_ip_port(value);

	return 0;
}

/*#Device.ManagementServer.ConnectionRequestUsername!UCI:cwmp/cpe,cpe/userid*/
static int get_management_server_connection_request_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "userid", value);
	return 0;
}

static int set_management_server_connection_request_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "userid", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.ConnectionRequestPassword!UCI:cwmp/cpe,cpe/passwd*/
static int set_management_server_connection_request_passwd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "passwd", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UpgradesManaged!UCI:cwmp/cpe,cpe/upgrades_managed*/
static int get_upgrades_managed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "cpe", "upgrades_managed", "false");
	return 0;
}

static int set_upgrades_managed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "upgrades_managed", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_lwn_protocol_supported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "UDP";
	return 0;
}

/*#Device.ManagementServer.LightweightNotificationProtocolsUsed!UCI:cwmp/lwn,lwn/enable*/
static int get_lwn_protocol_used(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	char *tmp;
	
	dmuci_get_option_value_string("cwmp", "lwn", "enable", &tmp);
	string_to_bool(tmp, &b);
	*value = b ? "UDP" : "";
	return 0;
}

static int set_lwn_protocol_used(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value,"UDP") == 0)
				dmuci_set_value("cwmp", "lwn", "enable", "1");
			else
				dmuci_set_value("cwmp", "lwn", "enable", "0");
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UDPLightweightNotificationHost!UCI:cwmp/lwn,lwn/hostname*/
static int get_lwn_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{	
	dmuci_get_option_value_string("cwmp", "lwn", "hostname", value);
	return 0;
}

static int set_lwn_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "lwn", "hostname", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UDPLightweightNotificationPort!UCI:cwmp/lwn,lwn/port*/
static int get_lwn_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "lwn", "port", "7547");
	return 0;
}

static int set_lwn_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "lwn", "port", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_management_server_http_compression_supportted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "GZIP,Deflate";
	return 0;
}

/*#Device.ManagementServer.HTTPCompression!UCI:cwmp/acs,acs/compression*/
static int get_management_server_http_compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "compression", value);
	return 0;
}

static int set_management_server_http_compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcasecmp(value, "gzip") == 0 || strcasecmp(value, "deflate") == 0 || strncasecmp(value, "disable", 7) == 0) {
				dmuci_set_value("cwmp", "acs", "compression", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			}
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.CWMPRetryMinimumWaitInterval!UCI:cwmp/acs,acs/retry_min_wait_interval*/
static int get_management_server_retry_min_wait_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp = NULL, *dhcp_retry_min_wait_interval = NULL;
	bool discovery = false;

	dmuci_get_option_value_string("cwmp", "acs", "dhcp_discovery", &dhcp);
	dmuci_get_option_value_string("cwmp", "acs", "dhcp_retry_min_wait_interval", &dhcp_retry_min_wait_interval);

	discovery = dmuci_string_to_boolean(dhcp);

	if ((discovery == true) && (DM_STRLEN(dhcp_retry_min_wait_interval) != 0))
		*value = dhcp_retry_min_wait_interval;
	else
		*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "retry_min_wait_interval", "5");

	return 0;
}

static int set_management_server_retry_min_wait_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "retry_min_wait_interval", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.CWMPRetryIntervalMultiplier!UCI:cwmp/acs,acs/retry_interval_multiplier*/
static int get_management_server_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp = NULL, *dhcp_retry_interval_multiplier = NULL;
	bool discovery = false;

	dmuci_get_option_value_string("cwmp", "acs", "dhcp_discovery", &dhcp);
	dmuci_get_option_value_string("cwmp", "acs", "dhcp_retry_interval_multiplier", &dhcp_retry_interval_multiplier);

	discovery = dmuci_string_to_boolean(dhcp);

	if ((discovery == true) && (DM_STRLEN(dhcp_retry_interval_multiplier) != 0))
		*value = dhcp_retry_interval_multiplier;
	else
		*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "retry_interval_multiplier", "2000");

	return 0;
}

static int set_management_server_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1000","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "retry_interval_multiplier", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.AliasBasedAddressing!UCI:cwmp/cpe,cpe/amd_version*/
static int get_alias_based_addressing(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_option_value_fallback_def("cwmp", "cpe", "amd_version", "5");
	*value = (DM_STRTOL(res) <= AMD_4) ? "false" : "true";
	return 0;
}

/*#Device.ManagementServer.InstanceMode!UCI:cwmp/cpe,cpe/instance_mode*/
static int get_instance_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "cpe", "instance_mode", "InstanceNumber");
	return 0;
}

static int set_instance_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, InstanceMode, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "instance_mode", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_management_server_supported_conn_req_methods(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,XMPP,STUN";
	return 0;
}

static int get_management_server_instance_wildcard_supported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int get_management_server_enable_cwmp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "enable", value);
	if ((*value)[0] == '\0')
		*value = "1";
	return 0;
}

static int set_management_server_enable_cwmp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp", "cpe", "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_nat_detected(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	bool en = 0;

	dmuci_get_option_value_string("stunc", "stunc", "enabled", &v);
	en = dmuci_string_to_boolean(v);

	if (en == true) { //stunc is enabled
		dmuci_get_option_value_string_varstate("stunc", "stunc", "nat_detected", &v);
		en = dmuci_string_to_boolean(v);
		*value = (en == true) ? "1" : "0";
	} else {
		*value = "0";
	}
	return 0;
}

static int get_manageable_device_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseManageableDevice);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_heart_beat_policy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "heartbeat_enable", "0");
	return 0;
}

static int set_heart_beat_policy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "heartbeat_enable", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}


static int get_heart_beat_policy_reporting_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "heartbeat_interval", "30");
	return 0;
}

static int set_heart_beat_policy_reporting_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"20",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "heartbeat_interval", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_heart_beat_policy_initiation_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "heartbeat_time", value);
	return 0;
}

static int set_heart_beat_policy_initiation_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "heartbeat_time", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int browseInformParameterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *dmmap_sect = NULL;
	char *inst = NULL;
	uci_path_foreach_sections(varstate, "cwmp", "inform_parameter", s) {
		if ((dmmap_sect = get_dup_section_in_dmmap("dmmap_mgt_server", "inform_parameter", section_name(s))) == NULL) {
			dmuci_add_section_bbfdm("dmmap_mgt_server", "inform_parameter", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(s));
		}
		inst = handle_instance(dmctx, parent_node, dmmap_sect, "informparam_instance", "informparam_alias");
		struct dmmap_dup inform_param_afgs = { .config_section = s, .dmmap_section = dmmap_sect };
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&inform_param_afgs, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int add_inform_parameter(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_sect = NULL;
	char inf_param[32] = {0};

	snprintf(inf_param, sizeof(inf_param), "inf_param_%s", *instance);

	dmuci_add_section_varstate("cwmp", "inform_parameter", &s);
	dmuci_rename_section_by_section(s, inf_param);
	dmuci_set_value_by_section(s, "enable", "0");

	dmuci_add_section_bbfdm("dmmap_mgt_server", "inform_parameter", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_sect, "informparam_instance", *instance);
	return 0;
}

static int delete_inform_parameter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(varstate, "cwmp", "inform_parameter", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_mgt_server", "inform_parameter", section_name(s), &dmmap_section);

				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section_varstate(s, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int get_inform_parameter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	dmuci_get_value_by_section_string(inform_param_args->config_section, "enable", value);
	return 0;
}

static int set_inform_parameter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section_varstate(inform_param_args->config_section, "enable", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_inform_parameter_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	dmuci_get_value_by_section_string(inform_param_args->dmmap_section, "informparam_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_inform_parameter_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section_varstate(inform_param_args->dmmap_section, "informparam_alias", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_inform_parameter_parameter_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	dmuci_get_value_by_section_string(inform_param_args->config_section, "parameter_name", value);
	return 0;
}

static int set_inform_parameter_parameter_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section_varstate(inform_param_args->config_section, "parameter_name", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_inform_parameter_event_list(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	dmuci_get_value_by_section_string(inform_param_args->config_section, "events_list", value);	return 0;
}

static int set_inform_parameter_event_list(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *inform_param_args = (struct dmmap_dup *)data;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, CWMP_EVENTS, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section_varstate(inform_param_args->config_section, "events_list", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_inform_parameter_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseInformParameterInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_manageable_device_oui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct manageable_device_args *device = (struct manageable_device_args *)data;
	*value = dmstrdup(device->oui);
	return 0;
}

static int get_manageable_device_serial(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct manageable_device_args *device = (struct manageable_device_args *)data;
	*value = dmstrdup(device->serial);
	return 0;
}

static int get_manageable_device_class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct manageable_device_args *device = (struct manageable_device_args *)data;
	*value = (DM_STRCMP(device->class, "-") != 0) ? dmstrdup(device->class) : "";
	return 0;
}

static int get_manageable_device_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct manageable_device_args *device = (struct manageable_device_args *)data;
	*value = dmstrdup(device->host);
	return 0;
}

static int get_transfer_compl_policy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", TRANSFER_COMPL_SEC_NAME, "enable", value);
	if (DM_STRLEN(*value) == 0)
		*value = "0";

	return 0;
}

static int get_transfer_compl_policy_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", TRANSFER_COMPL_SEC_NAME, "transfer_type", value);
	if (DM_STRLEN(*value) == 0)
		*value = dmstrdup("Both");
	return 0;
}

static int get_transfer_compl_policy_result_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", TRANSFER_COMPL_SEC_NAME, "result_type", value);
	if (DM_STRLEN(*value) == 0)
		*value = dmstrdup("Both");

	return 0;
}

static int get_transfer_compl_policy_file_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", TRANSFER_COMPL_SEC_NAME, "file_type", value);
	return 0;
}

static int set_transfer_compl_policy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			s = get_autonomous_notify_section(TRANSFER_COMPL_SEC_NAME);
			dmuci_set_value_by_section(s, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int set_transfer_compl_policy_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, TCTransferType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			s = get_autonomous_notify_section(TRANSFER_COMPL_SEC_NAME);
			dmuci_set_value_by_section(s, "transfer_type", value);
			return 0;
	}
	return 0;
}

static int set_transfer_compl_policy_result_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, TCResultType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			s = get_autonomous_notify_section(TRANSFER_COMPL_SEC_NAME);
			dmuci_set_value_by_section(s, "result_type", value);
			return 0;
	}
	return 0;
}

static int set_transfer_compl_policy_file_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, TCFileType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			s = get_autonomous_notify_section(TRANSFER_COMPL_SEC_NAME);
			dmuci_set_value_by_section(s, "file_type", value);
			return 0;
	}
	return 0;
}

static int get_du_state_change_compl_policy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", DU_STATE_CHANGE_SEC_NAME, "enable", value);
	if (DM_STRLEN(*value) == 0)
		*value = "0";

	return 0;
}

static int get_du_state_change_compl_policy_operation_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", DU_STATE_CHANGE_SEC_NAME, "operation_type", value);
	return 0;
}

static int get_du_state_change_compl_policy_result_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", DU_STATE_CHANGE_SEC_NAME, "result_type", value);
	if (DM_STRLEN(*value) == 0)
		*value = dmstrdup("Both");

	return 0;
}

static int get_du_state_change_compl_policy_fault_code_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", DU_STATE_CHANGE_SEC_NAME, "fault_code", value);
	return 0;
}

static int set_du_state_change_compl_policy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			s = get_autonomous_notify_section(DU_STATE_CHANGE_SEC_NAME);
			dmuci_set_value_by_section(s, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int set_du_state_change_compl_policy_operation_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, DUStateOperationType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			s = get_autonomous_notify_section(DU_STATE_CHANGE_SEC_NAME);
			dmuci_set_value_by_section(s, "operation_type", value);
			return 0;
	}
	return 0;
}

static int set_du_state_change_compl_policy_result_type_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DUStateResultType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			s = get_autonomous_notify_section(DU_STATE_CHANGE_SEC_NAME);
			dmuci_set_value_by_section(s, "result_type", value);
			return 0;
	}
	return 0;
}

static int set_du_state_change_compl_policy_fault_code_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, DUStateFaultCode, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			s = get_autonomous_notify_section(DU_STATE_CHANGE_SEC_NAME);
			dmuci_set_value_by_section(s, "fault_code", value);
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMOBJ tManagementServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"HeartbeatPolicy", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tHeartbeatPolicyParams, NULL, BBFDM_CWMP, NULL, "2.12"},
{"ManageableDevice", &DMREAD, NULL, NULL, NULL, browseManageableDevice, NULL, NULL, NULL, tManageableDeviceParams, NULL, BBFDM_CWMP, NULL, "2.12"},
{"InformParameter", &DMWRITE, add_inform_parameter, delete_inform_parameter, NULL, browseInformParameterInst, NULL, NULL, NULL, tInformParameterParams, NULL, BBFDM_CWMP, NULL, "2.8"},
{"AutonomousTransferCompletePolicy", &DMREAD, NULL, NULL, "file:/etc/config/cwmp", NULL, NULL, NULL, NULL, tTransferComplPolicyParams, NULL, BBFDM_CWMP, NULL, "2.0"},
{"DUStateChangeComplPolicy", &DMREAD, NULL, NULL, "file:/etc/config/swmodd", NULL, NULL, NULL, NULL, tDUStateChangeComplPolicyParams, NULL, BBFDM_CWMP, NULL, "2.1"},
{0}
};

/*** ManagementServer. ***/
DMLEAF tManagementServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"URL", &DMWRITE, DMT_STRING, get_management_server_url, set_management_server_url, BBFDM_CWMP},
{"Username", &DMWRITE, DMT_STRING, get_management_server_username, set_management_server_username, BBFDM_CWMP, "2.0"},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_management_server_passwd, BBFDM_CWMP, "2.0"},
{"ScheduleReboot", &DMWRITE, DMT_TIME, get_management_server_schedule_reboot, set_management_server_schedule_reboot, BBFDM_CWMP, "2.10"},
{"DelayReboot", &DMWRITE, DMT_INT, get_management_server_delay_reboot, set_management_server_delay_reboot, BBFDM_CWMP, "2.10"},
{"PeriodicInformEnable", &DMWRITE, DMT_BOOL, get_management_server_periodic_inform_enable, set_management_server_periodic_inform_enable,  BBFDM_CWMP, "2.0"},
{"PeriodicInformInterval", &DMWRITE, DMT_UNINT, get_management_server_periodic_inform_interval, set_management_server_periodic_inform_interval, BBFDM_CWMP, "2.0"},
{"PeriodicInformTime", &DMWRITE, DMT_TIME, get_management_server_periodic_inform_time, set_management_server_periodic_inform_time, BBFDM_CWMP, "2.0"},
{"ParameterKey", &DMREAD, DMT_STRING, get_management_server_key, NULL, BBFDM_CWMP, "2.0"},
{"ConnectionRequestURL", &DMREAD, DMT_STRING, get_management_server_connection_request_url, NULL, BBFDM_CWMP, "2.0"},
{"ConnectionRequestUsername", &DMWRITE, DMT_STRING, get_management_server_connection_request_username, set_management_server_connection_request_username, BBFDM_CWMP, "2.0"},
{"ConnectionRequestPassword", &DMWRITE, DMT_STRING, get_empty, set_management_server_connection_request_passwd,  BBFDM_CWMP, "2.0"},
{"UpgradesManaged", &DMWRITE, DMT_BOOL, get_upgrades_managed, set_upgrades_managed, BBFDM_CWMP, "2.0"},
{"HTTPCompressionSupported", &DMREAD, DMT_STRING, get_management_server_http_compression_supportted, NULL, BBFDM_CWMP, "2.7"},
{"HTTPCompression", &DMWRITE, DMT_STRING, get_management_server_http_compression, set_management_server_http_compression, BBFDM_CWMP, "2.7"},
{"LightweightNotificationProtocolsSupported", &DMREAD, DMT_STRING, get_lwn_protocol_supported, NULL, BBFDM_CWMP, "2.7"},
{"LightweightNotificationProtocolsUsed", &DMWRITE, DMT_STRING, get_lwn_protocol_used, set_lwn_protocol_used, BBFDM_CWMP, "2.7"},
{"UDPLightweightNotificationHost", &DMWRITE, DMT_STRING, get_lwn_host, set_lwn_host, BBFDM_CWMP, "2.7"},
{"UDPLightweightNotificationPort", &DMWRITE, DMT_UNINT, get_lwn_port, set_lwn_port, BBFDM_CWMP, "2.7"},
{"CWMPRetryMinimumWaitInterval", &DMWRITE, DMT_UNINT, get_management_server_retry_min_wait_interval, set_management_server_retry_min_wait_interval, BBFDM_CWMP, "2.0"},
{"CWMPRetryIntervalMultiplier", &DMWRITE, DMT_UNINT, get_management_server_retry_interval_multiplier, set_management_server_retry_interval_multiplier, BBFDM_CWMP, "2.0"},
{"AliasBasedAddressing", &DMREAD, DMT_BOOL, get_alias_based_addressing, NULL, BBFDM_CWMP, "2.3"},
{"InstanceMode", &DMWRITE, DMT_STRING, get_instance_mode, set_instance_mode, BBFDM_CWMP, "2.3"},
{"SupportedConnReqMethods", &DMREAD, DMT_STRING, get_management_server_supported_conn_req_methods, NULL, BBFDM_CWMP, "2.7"},
{"InstanceWildcardsSupported", &DMREAD, DMT_BOOL, get_management_server_instance_wildcard_supported, NULL, BBFDM_CWMP, "2.12"},
{"EnableCWMP", &DMWRITE, DMT_BOOL, get_management_server_enable_cwmp, set_management_server_enable_cwmp, BBFDM_CWMP, "2.12"},
{"UDPConnectionRequestAddress", &DMREAD, DMT_STRING, get_upd_cr_address, NULL, BBFDM_CWMP, "2.0"},
{"NATDetected", &DMREAD, DMT_BOOL, get_nat_detected, NULL, BBFDM_CWMP, "2.0"},
{"InformParameterNumberOfEntries", &DMREAD, DMT_UNINT, get_inform_parameter_number_of_entries, NULL, BBFDM_CWMP, "2.0"},
{"ManageableDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_manageable_device_number_of_entries, NULL, BBFDM_CWMP, "2.0"},
{0}
};

DMLEAF tHeartbeatPolicyParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_heart_beat_policy_enable, set_heart_beat_policy_enable, BBFDM_CWMP, "2.12"},
{"ReportingInterval", &DMWRITE, DMT_UNINT, get_heart_beat_policy_reporting_interval, set_heart_beat_policy_reporting_interval, BBFDM_CWMP, "2.12"},
{"InitiationTime", &DMWRITE, DMT_TIME, get_heart_beat_policy_initiation_time, set_heart_beat_policy_initiation_time, BBFDM_CWMP, "2.12"},
{0}
};

DMLEAF tInformParameterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_inform_parameter_enable, set_inform_parameter_enable, BBFDM_CWMP, "2.8"},
{"Alias", &DMWRITE, DMT_STRING, get_inform_parameter_alias, set_inform_parameter_alias, BBFDM_CWMP, "2.8"},
{"ParameterName", &DMWRITE, DMT_STRING, get_inform_parameter_parameter_name, set_inform_parameter_parameter_name, BBFDM_CWMP, "2.8"},
{"EventList", &DMWRITE, DMT_STRING, get_inform_parameter_event_list, set_inform_parameter_event_list, BBFDM_CWMP, "2.8"},
{0}
};

DMLEAF tManageableDeviceParams[] = {
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_manageable_device_oui, NULL, BBFDM_CWMP, "2.0"},
{"SerialNumber", &DMREAD, DMT_STRING, get_manageable_device_serial, NULL, BBFDM_CWMP, "2.0"},
{"ProductClass", &DMREAD, DMT_STRING, get_manageable_device_class, NULL, BBFDM_CWMP, "2.0"},
{"Host", &DMREAD, DMT_STRING, get_manageable_device_host, NULL, BBFDM_CWMP, "2.0"},
{0}
};

DMLEAF tTransferComplPolicyParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_transfer_compl_policy_enable, set_transfer_compl_policy_enable, BBFDM_CWMP, "2.0"},
{"TransferTypeFilter", &DMWRITE, DMT_STRING, get_transfer_compl_policy_type_filter, set_transfer_compl_policy_type_filter, BBFDM_CWMP, "2.0"},
{"ResultTypeFilter", &DMWRITE, DMT_STRING, get_transfer_compl_policy_result_type_filter, set_transfer_compl_policy_result_type_filter, BBFDM_CWMP, "2.0"},
{"FileTypeFilter", &DMWRITE, DMT_STRING, get_transfer_compl_policy_file_type_filter, set_transfer_compl_policy_file_type_filter, BBFDM_CWMP, "2.0"},
{0}
};

DMLEAF tDUStateChangeComplPolicyParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_du_state_change_compl_policy_enable, set_du_state_change_compl_policy_enable, BBFDM_CWMP, "2.1"},
{"OperationTypeFilter", &DMWRITE, DMT_STRING, get_du_state_change_compl_policy_operation_type_filter, set_du_state_change_compl_policy_operation_type_filter, BBFDM_CWMP, "2.1"},
{"ResultTypeFilter", &DMWRITE, DMT_STRING, get_du_state_change_compl_policy_result_type_filter, set_du_state_change_compl_policy_result_type_filter, BBFDM_CWMP, "2.1"},
{"FaultCodeFilter", &DMWRITE, DMT_STRING, get_du_state_change_compl_policy_fault_code_filter, set_du_state_change_compl_policy_fault_code_filter, BBFDM_CWMP, "2.1"},
{0}
};
