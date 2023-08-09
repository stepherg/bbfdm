/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "usb.h"

#define SYSFS_USB_DEVICES_PATH "/sys/bus/usb/devices"

struct usb_port
{
	struct uci_section *dm_usb_port;
	char *folder_name;
	char *folder_path;
	struct uci_section *dmsect;
};

struct usb_interface
{
	struct uci_section *dm_usb_iface;
	char *iface_name;
	char *iface_path;
	char *statistics_path;
	char *portlink;
};


/*************************************************************
* INIT
*************************************************************/
static void init_usb_port(struct uci_section *dm, char *folder_name, char *folder_path, struct usb_port *port)
{
	port->dm_usb_port = dm;
	port->folder_name = dmstrdup(folder_name);
	port->folder_path = dmstrdup(folder_path);
}

static void init_usb_interface(struct uci_section *dm, char *iface_name, char *iface_path, char *statistics_path, char *portlink, struct usb_interface *iface)
{
	iface->dm_usb_iface = dm;
	iface->iface_name = dmstrdup(iface_name);
	iface->iface_path = dmstrdup(iface_path);
	iface->portlink = dmstrdup(portlink);
	iface->statistics_path = dmstrdup(statistics_path);
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
static int read_sysfs_file(const char *file, char **value)
{
	char buf[128];
	int rc;

	rc =  dm_read_sysfs_file(file, buf, sizeof(buf));
	*value = dmstrdup(buf);

	return rc;
}

static int read_sysfs(const char *path, const char *name, char **value)
{
	char file[256];

	snprintf(file, sizeof(file), "%s/%s", path, name);
	return read_sysfs_file(file, value);
}

static int __read_sysfs(const char *path, const char *name, char *dst, unsigned len)
{
	char file[256];

	snprintf(file, sizeof(file), "%s/%s", path, name);
	return dm_read_sysfs_file(file, dst, len);
}

static int read_sysfs_usb_port(const struct usb_port *port, const char *name, char **value)
{
	return read_sysfs(port->folder_path, name, value);
}

static int read_sysfs_usb_iface(const struct usb_interface *iface, const char *name, char **value)
{
	return read_sysfs(iface->iface_path, name, value);
}

static int read_sysfs_usb_net_iface(const struct usb_interface *iface, const char *name, char **value)
{
	return get_net_device_sysfs(iface->iface_name, name, value);
}

static int __read_sysfs_usb_port(const struct usb_port *port, const char *name, char *dst, unsigned len)
{
	return __read_sysfs(port->folder_path, name, dst, len);
}

static int __read_sysfs_usb_iface(const struct usb_interface *iface, const char *name, char *dst, unsigned len)
{
	return __read_sysfs(iface->iface_path, name, dst, len);
}

static void writeFileContent(const char *filepath, const char *data)
{
	FILE *fp = fopen(filepath, "ab");

	if (fp != NULL) {
		fputs(data, fp);
		fclose(fp);
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseUSBInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir = NULL;
	struct dirent *ent = NULL;
	char *inst = NULL;
	size_t length;
	char **foldersplit;
	struct usb_interface iface = {0};
	LIST_HEAD(dup_list);
	struct sysfs_dmsection *p = NULL;

	synchronize_system_folders_with_dmmap_opt(SYSFS_USB_DEVICES_PATH, "dmmap_usb", "dmmap_interface", "usb_iface_link", "usb_iface_instance", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char statistics_path[652] = {0};
		char iface_path[620] = {0};
		char netfolderpath[256] = {0};
		char iface_name[260] = {0};
		char port_link[128] = {0};

		snprintf(netfolderpath, sizeof(netfolderpath), "%s/%s/net", SYSFS_USB_DEVICES_PATH, p->sysfs_folder_name);
		if (!folder_exists(netfolderpath))
			continue;

		if (p->dmmap_section) {
			foldersplit= strsplit(p->sysfs_folder_name, ":", &length);
			snprintf(port_link, sizeof(port_link), "%s", foldersplit[0]);
		}
		sysfs_foreach_file(netfolderpath, dir, ent) {
			if(DM_LSTRCMP(ent->d_name, ".")==0 || DM_LSTRCMP(ent->d_name, "..")==0)
				continue;

			snprintf(iface_name, sizeof(iface_name), "%s", ent->d_name);
			break;
		}
		if (dir)
			closedir(dir);

		snprintf(iface_path, sizeof(iface_path), "%s/%s", netfolderpath, iface_name);
		if (p->dmmap_section)
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "usb_iface_path", iface_path);

		snprintf(statistics_path, sizeof(statistics_path), "%s/statistics", iface_path);
		init_usb_interface(p->dmmap_section, iface_name, iface_path, statistics_path, port_link, &iface);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "usb_iface_instance", "usb_iface_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &iface, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseUSBPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct usb_port port = {0};
	struct sysfs_dmsection *p = NULL;
	LIST_HEAD(dup_list);
	regex_t regex1 = {};
	regex_t regex2 = {};

	regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
	regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);

	synchronize_system_folders_with_dmmap_opt(SYSFS_USB_DEVICES_PATH, "dmmap_usb", "dmmap_port", "port_link", "usb_port_instance", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		if (regexec(&regex1, p->sysfs_folder_name, 0, NULL, 0) != 0 &&
			regexec(&regex2, p->sysfs_folder_name, 0, NULL, 0) !=0 &&
			DM_LSTRSTR(p->sysfs_folder_name, "usb") != p->sysfs_folder_name)
			continue;

		init_usb_port(p->dmmap_section, p->sysfs_folder_name, p->sysfs_folder_path, &port);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "usb_port_instance", "usb_port_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	regfree(&regex1);
	regfree(&regex2);
	return 0;
}

static int browseUSBUSBHostsHostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct sysfs_dmsection *p = NULL;
	char *inst = NULL;
	struct usb_port port = {0};
	LIST_HEAD(dup_list);

	synchronize_system_folders_with_dmmap_opt(SYSFS_USB_DEVICES_PATH, "dmmap_usb", "dmmap_host", "port_link", "usb_host_instance", &dup_list);

	list_for_each_entry(p, &dup_list, list) {

		if(!DM_LSTRSTR(p->sysfs_folder_name, "usb"))
			continue;

		init_usb_port(p->dmmap_section, p->sysfs_folder_name, p->sysfs_folder_path, &port);
		port.dmsect= p->dmmap_section;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "usb_host_instance", "usb_host_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int synchronize_usb_devices_with_dmmap_opt_recursively(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, char* inst_opt, int is_root, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_sect = NULL;
	DIR *dir = NULL;
	struct dirent *ent = NULL;
	char *v, *sysfs_repo_path, *instance = NULL;
	struct sysfs_dmsection *p = NULL;
	regex_t regex1 = {}, regex2 = {};

	regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
	regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);

	LIST_HEAD(dup_list_no_inst);

	sysfs_foreach_file(sysfsrep, dir, ent) {
		if (DM_LSTRCMP(ent->d_name, ".") == 0 || DM_LSTRCMP(ent->d_name, "..") == 0)
			continue;

		if (regexec(&regex1, ent->d_name, 0, NULL, 0) == 0 || regexec(&regex2, ent->d_name, 0, NULL, 0) ==0) {
			char deviceClassFile[270];
			char deviceClass[16];

			snprintf(deviceClassFile, sizeof(deviceClassFile), "%s/%s/bDeviceClass", sysfsrep, ent->d_name);
			dm_read_sysfs_file(deviceClassFile, deviceClass, sizeof(deviceClass));

			if (DM_LSTRNCMP(deviceClass, "09", 2) == 0) {
				char hubpath[270];

				snprintf(hubpath, sizeof(hubpath), "%s/%s", sysfsrep, ent->d_name);
				synchronize_usb_devices_with_dmmap_opt_recursively(hubpath, dmmap_package, dmmap_section, opt_name, inst_opt, 0, dup_list);
			}
			/*
			 * create/update corresponding dmmap section that have same config_section link and using param_value_array
			 */
			dmasprintf(&sysfs_repo_path, "%s/%s", sysfsrep, ent->d_name);
			if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, dmmap_section, opt_name, sysfs_repo_path)) == NULL) {
				dmuci_add_section_bbfdm(dmmap_package, dmmap_section, &dmmap_sect);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, opt_name, sysfs_repo_path);
			}
			dmuci_get_value_by_section_string(dmmap_sect, inst_opt, &instance);
			/*
			 * Add system and dmmap sections to the list
			 */
			if (instance == NULL || *instance == '\0')
				add_sysfs_section_list(&dup_list_no_inst, dmmap_sect, ent->d_name, sysfs_repo_path);
			else
				add_sysfs_section_list(dup_list, dmmap_sect, ent->d_name, sysfs_repo_path);
		}
	}
	if (dir)
		closedir(dir);
	regfree(&regex1);
	regfree(&regex2);
	/*
	 * fusion two lists
	 */
	list_for_each_entry(p, &dup_list_no_inst, list) {
		add_sysfs_section_list(dup_list, p->dmmap_section, p->sysfs_folder_name, p->sysfs_folder_path);
	}
	/*
	 * Delete unused dmmap sections
	 */
	if (is_root) {
		uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_section, stmp, s) {
			dmuci_get_value_by_section_string(s, opt_name, &v);
			if (!folder_exists(v)) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
		}
	}
	return 0;
}

static int browseUSBUSBHostsHostDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct sysfs_dmsection *p = NULL;
	char *inst = NULL, *parent_host_instance = NULL;
	struct usb_port port= {};
	struct usb_port *prev_port = (struct usb_port *)prev_data;
	LIST_HEAD(dup_list);


	synchronize_usb_devices_with_dmmap_opt_recursively(prev_port->folder_path,
		"dmmap_usb", "dmmap_host_device", "port_link", "usb_host_device_instance", 1, &dup_list);

	list_for_each_entry(p, &dup_list, list) {

		init_usb_port(p->dmmap_section, p->sysfs_folder_name, p->sysfs_folder_path, &port);

		if (p->dmmap_section && prev_port->dmsect ) {
			dmuci_get_value_by_section_string(prev_port->dmsect, "usb_host_instance", &parent_host_instance);
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "usb_host_device_parent_host_instance", parent_host_instance);
		}

		port.dmsect = prev_port->dmsect;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "usb_host_device_instance", "usb_host_device_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, inst) == DM_STOP)
			break;
	}
    free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseUSBUSBHostsHostDeviceConfigurationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	const struct usb_port *usb_dev = prev_data;
	struct usb_port port = {};
	struct uci_section *s = NULL;
	char nbre[16];

	__read_sysfs_usb_port(usb_dev, "bNumConfigurations", nbre, sizeof(nbre));
	if(nbre[0] == '0')
		return 0;

	s = is_dmmap_section_exist("dmmap_usb", "usb_device_conf");
	if (!s)
		dmuci_add_section_bbfdm("dmmap_usb", "usb_device_conf", &s);
	dmuci_set_value_by_section_bbfdm(s, "usb_parent_device", usb_dev->folder_path);

	init_usb_port(s, usb_dev->folder_name, usb_dev->folder_path, &port);

	handle_instance(dmctx, parent_node, s, "usb_device_conf_instance", "usb_device_conf_alias");

	DM_LINK_INST_OBJ(dmctx, parent_node, &port, "1");
	return 0;
}

static int browseUSBUSBHostsHostDeviceConfigurationInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir = NULL;
	struct dirent *ent = NULL;
	struct usb_port *usb_dev = (struct usb_port*)prev_data;
	struct usb_port port = {0};
	char *sysfs_rep_path, *inst = NULL;
	struct uci_section *dmmap_sect = NULL;
	regex_t regex1 = {};
	regex_t regex2 = {};

	regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]:[0-9][0-9]*\\.[0-9]*[0-9]$", 0);
	regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]:[0-9][0-9]*\\.[0-9]*[0-9]$", 0);

	sysfs_foreach_file(usb_dev->folder_path, dir, ent) {

		if (DM_LSTRCMP(ent->d_name, ".") == 0 || DM_LSTRCMP(ent->d_name, "..") == 0)
			continue;

		if (regexec(&regex1, ent->d_name, 0, NULL, 0) == 0 || regexec(&regex2, ent->d_name, 0, NULL, 0) == 0) {
			dmasprintf(&sysfs_rep_path, "%s/%s", usb_dev->folder_path, ent->d_name);
			if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_usb", "usb_device_conf_interface", "port_link", sysfs_rep_path)) == NULL) {
				dmuci_add_section_bbfdm("dmmap_usb", "usb_device_conf_interface", &dmmap_sect);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "port_link", sysfs_rep_path);
			}

			init_usb_port(dmmap_sect, ent->d_name, sysfs_rep_path, &port);

			inst = handle_instance(dmctx, parent_node, dmmap_sect, "usb_device_conf_iface_instance", "usb_device_conf_iface_alias");

			if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, inst) == DM_STOP)
				break;
		}
	}
	if (dir)
		closedir(dir);
	regfree(&regex1);
	regfree(&regex2);
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_USB_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUSBInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_USB_PortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUSBPortInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_USBInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char carrier[8];

	__read_sysfs_usb_iface(data, "carrier", carrier, sizeof(carrier));

	if (carrier[0] == '1')
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_USBInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_USBInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char carrier[8];

	__read_sysfs_usb_iface(data, "carrier", carrier, sizeof(carrier));

	if (carrier[0] == '1')
		*value = "Up";
	else
		*value = "Down";
	return 0;
}

static int get_USBInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct usb_interface *)data)->dm_usb_iface, "usb_iface_alias", instance, value);
}

static int set_USBInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct usb_interface *)data)->dm_usb_iface, "usb_iface_alias", instance, value);
}

static int get_USBInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%s", usbiface->iface_name);
	return 0;
}

static int get_USBInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct usb_interface *iface = (struct usb_interface *)data;

	adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", iface->iface_name, value);
	return 0;
}

static int set_USBInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_USBInterface_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_iface(data, "address", value);
}

static int get_USBInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_iface(data, "queues/tx-0/tx_maxrate", value);
}

static int get_USBInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/tx_bytes", value);
}

static int get_USBInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/rx_bytes", value);
}

static int get_USBInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/tx_packets", value);
}

static int get_USBInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/rx_packets", value);
}

static int get_USBInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/tx_errors", value);
}

static int get_USBInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/rx_errors", value);
}

static int get_USBInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/tx_dropped", value);
}

static int get_USBInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/rx_dropped", value);
}

static int get_USBInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_net_iface(data, "statistics/multicast", value);
}

static int get_USBPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct usb_port *)data)->dm_usb_port, "usb_port_alias", instance, value);
}

static int set_USBPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct usb_port *)data)->dm_usb_port, "usb_port_alias", instance, value);
}

static int get_USBPort_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct usb_port *port = data;
	*value = dmstrdup(port->folder_name);
	return 0;
}

static int get_USBPort_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[16];

	__read_sysfs_usb_port(data, "bcdDevice", buf, sizeof(buf));
	dmasprintf(value, "%c.%c", buf[0], buf[0]);
	return 0;
}

static int get_USBPort_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct usb_port *port = data;
	char deviceclass[32];

	__read_sysfs_usb_port(port, "bDeviceClass", deviceclass, sizeof(deviceclass));

	if(DM_LSTRSTR(port->folder_name, "usb") == port->folder_name)
		*value= "Host";
	else if (DM_LSTRCMP(deviceclass, "09") == 0)
		*value= "Hub";
	else
		*value= "Device";
	return 0;
}

static int get_USBPort_Rate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char speed[16];

	__read_sysfs_usb_port(data, "speed", speed, sizeof(speed));

	if(DM_LSTRCMP(speed, "1.5") == 0)
		*value= "Low";
	else if(DM_LSTRCMP(speed, "12") == 0)
		*value= "Full";
	else if(DM_LSTRCMP(speed, "480") == 0)
		*value= "High";
	else
		*value= "Super";
	return 0;
}

static int get_USBPort_Power(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char pwrctl[16];

	__read_sysfs_usb_port(data, "power/control", pwrctl, sizeof(pwrctl));

	if (pwrctl[0] == 0)
		*value = "Unknown";
	else if (!DM_LSTRCMP(pwrctl, "auto"))
		*value ="Self";
	else
		*value ="Bus";

	return 0;
}

static int get_USBUSBHosts_HostNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUSBUSBHostsHostInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_USBUSBHostsHost_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct usb_port *)data)->dm_usb_port, "usb_host_alias", instance, value);
}

static int set_USBUSBHostsHost_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct usb_port *)data)->dm_usb_port, "usb_host_alias", instance, value);
}

static int get_USBUSBHostsHost_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char up[32];

	__read_sysfs_usb_port(data, "power/wakeup", up, sizeof(up));
	*value = DM_LSTRCMP(up, "enabled") == 0 ? "1" : "0";
	return 0;
}

static int set_USBUSBHostsHost_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_port *usbhost= (struct usb_port *)data;
	bool b;
	char *filepath;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmasprintf(&filepath, "%s/power/wakeup", usbhost->folder_path);
			if(b)
				writeFileContent(filepath, "enabled");
			else
				writeFileContent(filepath, "disabled");
			break;
	}
	return 0;
}

static int get_USBUSBHostsHost_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* port=(struct usb_port *)data;
	dmasprintf(value, "%s", port->folder_name);
	return 0;
}

static int get_USBUSBHostsHost_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char serial[64];

	__read_sysfs_usb_port(data, "serial", serial, sizeof(serial));

	if(strcasestr(serial, "ohci")!=NULL)
		*value= "OHCI";
	else if(strcasestr(serial, "ehci")!=NULL)
		*value= "EHCI";
	else if(strcasestr(serial, "uhci")!=NULL)
		*value= "UHCI";
	else
		*value= "xHCI";
	return 0;
}

static int get_USBUSBHostsHost_PowerManagementEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char power[64] = {0};

	__read_sysfs_usb_port(data, "power/level", power, sizeof(power));

	if(power[0] == 0 || DM_LSTRCMP(power, "suspend") == 0)
		*value= "false";
	else
		*value= "true";

	return 0;
}

static int set_USBUSBHostsHost_PowerManagementEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_port *host= (struct usb_port *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			char *filepath;
			dmasprintf(&filepath, "%s/power/level", host->folder_path);
			if (!file_exists(filepath))
				break;
			writeFileContent(filepath, b?"on":"suspend");
			break;
	}
	return 0;
}

static int get_USBUSBHostsHost_USBVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct usb_port *port = data;
	char file[256];
	char buf[16] = { 0, 0 };

	snprintf(file, sizeof(file), "%s/bcdDevice", port->folder_path);
	dm_read_sysfs_file(file, buf, sizeof(buf));

	dmasprintf(value, "%c.%c", buf[1], buf[2]);
	return 0;
}

static int get_USBUSBHostsHost_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUSBUSBHostsHostDeviceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_USBUSBHostsHostDevice_DeviceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *usbdev = (struct usb_port *)data;
	size_t length;
	char **filename = strsplit(usbdev->folder_name, "-", &length);
	char **port = strsplit(filename[1], ".", &length);
	dmasprintf(value ,"%s", port[0]);
	return 0;
}

static int get_USBUSBHostsHostDevice_USBVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bcdDevice", value);
}

static int get_USBUSBHostsHostDevice_DeviceClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bDeviceClass", value);
}

static int get_USBUSBHostsHostDevice_DeviceSubClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bDeviceSubClass", value);
}

static int get_USBUSBHostsHostDevice_DeviceProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bDeviceProtocol", value);
}

static int get_USBUSBHostsHostDevice_ProductID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *idproduct = NULL;
	unsigned int ui_idproduct;

	*value = "0";
	int rc = read_sysfs_usb_port(data, "idProduct", &idproduct);

	if (rc != -1 && idproduct != NULL) {
		sscanf(idproduct, "%x", &ui_idproduct);
		dmasprintf(value, "%u", ui_idproduct);
	}
	return rc;
}

static int get_USBUSBHostsHostDevice_VendorID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *idvendor = NULL;
	unsigned int ui_idvendor;

	*value = "0";
	int rc = read_sysfs_usb_port(data, "idVendor", &idvendor);

	if (rc != -1 && idvendor != NULL) {
		sscanf(idvendor, "%x", &ui_idvendor);
		dmasprintf(value, "%u", ui_idvendor);
	}
	return rc;
}

static int get_USBUSBHostsHostDevice_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "manufacturer", value);
}

static int get_USBUSBHostsHostDevice_ProductClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "product", value);
}

static int get_USBUSBHostsHostDevice_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "urbnum", value);
}

static int get_USBUSBHostsHostDevice_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	size_t length;
	char **busname, **portname;
	regex_t regex1 = {};
	regex_t regex2 = {};

	regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
	regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);
	if (regexec(&regex1, port->folder_name, 0, NULL, 0) == 0 || regexec(&regex2, port->folder_name, 0, NULL, 0) == 0) {
		busname = strsplit(port->folder_name, "-", &length);
		portname = strsplit(busname[1], ".", &length);
		*value = dmstrdup(portname[0]);
		goto out;
	}
	*value = "0";
out:
	regfree(&regex1);
	regfree(&regex2);
	return 0;
}

static int get_USBUSBHostsHostDevice_USBPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port = (struct usb_port *)data;
	adm_entry_get_linker_param(ctx, "Device.USB.Port.", port->folder_name, value);
	return 0;
}

static int get_USBUSBHostsHostDevice_Rate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_USBPort_Rate(refparam, ctx, data, instance, value);
}

static int get_USBUSBHostsHostDevice_Parent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port = (struct usb_port*)data;
	char *host_inst, usb_host_path[128] = {0};
	regex_t regex1 = {};

	regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);
	if (regexec(&regex1, port->folder_name, 0, NULL, 0) != 0 || port->dmsect == NULL) {
		*value = "";
		goto out;
	}

	dmuci_get_value_by_section_string(port->dmsect, "usb_host_instance", &host_inst);
	snprintf(usb_host_path, sizeof(usb_host_path), "Device.USB.USBHosts.Host.%s.Device.", host_inst);
	adm_entry_get_linker_param(ctx, usb_host_path, port->folder_name, value);

out:
	regfree(&regex1);
	return 0;
}

static int get_USBUSBHostsHostDevice_MaxChildren(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "maxchild", value);
}

static int get_USBUSBHostsHostDevice_IsSuspended(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char status[16] = {0};

	__read_sysfs_usb_port(data, "power/runtime_status", status, sizeof(status));
	if(DM_LSTRNCMP(status, "suspended", 9) == 0)
		*value= "1";
	else
		*value = "0";
	return 0;
}

static int get_USBUSBHostsHostDevice_ConfigurationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bNumConfigurations", value);
}

static int get_USBUSBHostsHostDeviceConfiguration_ConfigurationNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bConfigurationValue", value);
}

static int get_USBUSBHostsHostDeviceConfiguration_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bNumInterfaces", value);
}

static int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bInterfaceNumber", value);
}

static int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bInterfaceClass", value);
}

static int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceSubClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bInterfaceSubClass", value);
}

static int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_usb_port(data, "bInterfaceProtocol", value);
}

static int get_linker_usb_port(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	struct usb_port *port = (struct usb_port *)data;
	if (port && port->folder_name) {
		*linker = dmstrdup(port->folder_name);
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

static int get_linker_usb_host_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	struct usb_port *port = (struct usb_port *)data;
	if(port && port->folder_name) {
		*linker = dmstrdup(port->folder_name);
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.USB. *** */
DMOBJ tUSBObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseUSBInterfaceInst, NULL, NULL, tUSBInterfaceObj, tUSBInterfaceParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"Port", &DMREAD, NULL, NULL, NULL, browseUSBPortInst, NULL, NULL, NULL, tUSBPortParams, get_linker_usb_port, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"USBHosts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUSBUSBHostsObj, tUSBUSBHostsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUSBParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_USB_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_USB_PortNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.Interface.{i}. *** */
DMOBJ tUSBInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUSBInterfaceStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tUSBInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_USBInterface_Enable, set_USBInterface_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_USBInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_USBInterface_Alias, set_USBInterface_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_USBInterface_Name, NULL, BBFDM_BOTH},
//{"LastChange", &DMREAD, DMT_UNINT, get_USBInterface_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_USBInterface_LowerLayers, set_USBInterface_LowerLayers, BBFDM_BOTH},
//{"Upstream", &DMREAD, DMT_BOOL, get_USBInterface_Upstream, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_USBInterface_MACAddress, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMREAD, DMT_UNINT, get_USBInterface_MaxBitRate, NULL, BBFDM_BOTH},
//{"Port", &DMREAD, DMT_STRING, get_USBInterface_Port, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.Interface.{i}.Stats. *** */
DMLEAF tUSBInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_USBInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.Port.{i}. *** */
DMLEAF tUSBPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_USBPort_Alias, set_USBPort_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_USBPort_Name, NULL, BBFDM_BOTH},
{"Standard", &DMREAD, DMT_STRING, get_USBPort_Standard, NULL, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_USBPort_Type, NULL, BBFDM_BOTH},
//{"Receptacle", &DMREAD, DMT_STRING, get_USBPort_Receptacle, NULL, BBFDM_BOTH},
{"Rate", &DMREAD, DMT_STRING, get_USBPort_Rate, NULL, BBFDM_BOTH},
{"Power", &DMREAD, DMT_STRING, get_USBPort_Power, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts. *** */
DMOBJ tUSBUSBHostsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Host", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostInst, NULL, NULL, tUSBUSBHostsHostObj, tUSBUSBHostsHostParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

DMLEAF tUSBUSBHostsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HostNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHosts_HostNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}. *** */
DMOBJ tUSBUSBHostsHostObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Device", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostDeviceInst, NULL, NULL, tUSBUSBHostsHostDeviceObj, tUSBUSBHostsHostDeviceParams, get_linker_usb_host_device, BBFDM_BOTH, LIST_KEY{"DeviceNumber", NULL}},
{0}
};

DMLEAF tUSBUSBHostsHostParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_USBUSBHostsHost_Alias, set_USBUSBHostsHost_Alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_USBUSBHostsHost_Enable, set_USBUSBHostsHost_Enable, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_USBUSBHostsHost_Name, NULL, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_USBUSBHostsHost_Type, NULL, BBFDM_BOTH},
//{"Reset", &DMWRITE, DMT_BOOL, get_USBUSBHostsHost_Reset, set_USBUSBHostsHost_Reset, BBFDM_BOTH},
{"PowerManagementEnable", &DMWRITE, DMT_BOOL, get_USBUSBHostsHost_PowerManagementEnable, set_USBUSBHostsHost_PowerManagementEnable, BBFDM_BOTH},
{"USBVersion", &DMREAD, DMT_STRING, get_USBUSBHostsHost_USBVersion, NULL, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHostsHost_DeviceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}.Device.{i}. *** */
DMOBJ tUSBUSBHostsHostDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Configuration", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostDeviceConfigurationInst, NULL, NULL, tUSBUSBHostsHostDeviceConfigurationObj, tUSBUSBHostsHostDeviceConfigurationParams, NULL, BBFDM_BOTH, LIST_KEY{"ConfigurationNumber", NULL}},
{0}
};

DMLEAF tUSBUSBHostsHostDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"DeviceNumber", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_DeviceNumber, NULL, BBFDM_BOTH},
{"USBVersion", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_USBVersion, NULL, BBFDM_BOTH},
{"DeviceClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDevice_DeviceClass, NULL, BBFDM_BOTH},
{"DeviceSubClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDevice_DeviceSubClass, NULL, BBFDM_BOTH},
//{"DeviceVersion", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_DeviceVersion, NULL, BBFDM_BOTH},
{"DeviceProtocol", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDevice_DeviceProtocol, NULL, BBFDM_BOTH},
{"ProductID", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_ProductID, NULL, BBFDM_BOTH},
{"VendorID", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_VendorID, NULL, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_Manufacturer, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_ProductClass, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_SerialNumber, NULL, BBFDM_BOTH},
{"Port", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_Port, NULL, BBFDM_BOTH},
{"USBPort", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_USBPort, NULL, BBFDM_BOTH},
{"Rate", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_Rate, NULL, BBFDM_BOTH},
{"Parent", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_Parent, NULL, BBFDM_BOTH},
{"MaxChildren", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_MaxChildren, NULL, BBFDM_BOTH},
{"IsSuspended", &DMREAD, DMT_BOOL, get_USBUSBHostsHostDevice_IsSuspended, NULL, BBFDM_BOTH},
//{"IsSelfPowered", &DMREAD, DMT_BOOL, get_USBUSBHostsHostDevice_IsSelfPowered, NULL, BBFDM_BOTH},
{"ConfigurationNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_ConfigurationNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}. *** */
DMOBJ tUSBUSBHostsHostDeviceConfigurationObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostDeviceConfigurationInterfaceInst, NULL, NULL, NULL, tUSBUSBHostsHostDeviceConfigurationInterfaceParams, NULL, BBFDM_BOTH, LIST_KEY{"InterfaceNumber", NULL}},
{0}
};

DMLEAF tUSBUSBHostsHostDeviceConfigurationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ConfigurationNumber", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDeviceConfiguration_ConfigurationNumber, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDeviceConfiguration_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.Interface.{i}. *** */
DMLEAF tUSBUSBHostsHostDeviceConfigurationInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceNumber", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceNumber, NULL, BBFDM_BOTH},
{"InterfaceClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceClass, NULL, BBFDM_BOTH},
{"InterfaceSubClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceSubClass, NULL, BBFDM_BOTH},
{"InterfaceProtocol", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceProtocol, NULL, BBFDM_BOTH},
{0}
};
