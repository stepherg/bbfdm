/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 */

#include "upnp.h"

struct upnpdiscovery {
	char *st;
	char *usn;
	char *uuid;
	char *urn;
	char *descurl;
	struct uci_section *dmmap_sect;
};

struct upnp_device_inst {
	char *device_type;
	char *friendly_name;
	char *manufacturer;
	char *manufacturer_url;
	char *model_description;
	char *model_name;
	char *model_number;
	char *model_url;
	char *serial_number;
	char *udn;
	char *uuid;
	char *preentation_url;
	char *parentudn;
	char *upc;
	struct uci_section *dmmap_sect;
};

struct upnp_service_inst {
	char *parentudn;
	char *serviceid;
	char *servicetype;
	char *scpdurl;
	char *controlurl;
	char *eventsuburl;
	struct uci_section *dmmap_sect;
};

struct upnp_description_file_info {
	char *desc_url;
	struct uci_section *dmmap_sect;
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseUPnPDiscoveryRootDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *root_devices = NULL, *device = NULL;
	struct upnpdiscovery upnp_dev = {0};
	char *descurl = NULL, *st = NULL, *usn = NULL, *inst = NULL;
	struct uci_section *dmmap_sect = NULL;
	char buf[512] = {0};
	int root_inst = 0;

	dmubus_call("upnp", "discovery", UBUS_ARGS{{}}, 0, &res);
	if (res == NULL)
		return 0;

	json_object_object_get_ex(res, "root_devices", &root_devices);
	size_t nbre_devices = (root_devices) ? json_object_array_length(root_devices) : 0;

	for (int i = 0; i < nbre_devices; i++) {
		device = json_object_array_get_idx(root_devices, i);

		descurl = dmjson_get_value(device, 1, "descurl");
		st = dmjson_get_value(device, 1, "st");
		usn = dmjson_get_value(device, 1, "usn");

		snprintf(buf, sizeof(buf), "%s", usn);

		char *p = strstr(buf, "::");
		char *urn_p = NULL;

		if (p) {
			urn_p = p + 2;
			*p = 0;
			char *uuid = strchr(buf, ':');
			upnp_dev.uuid = uuid ? dmstrdup(uuid + 1) : "";
		}

		if (urn_p) {
			char *urn = strchr(urn_p, ':');
			upnp_dev.urn = urn ? dmstrdup(urn + 1) : "";
		}

		upnp_dev.descurl = dmstrdup(descurl);
		upnp_dev.st = dmstrdup(st);
		upnp_dev.usn = dmstrdup(usn);

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_upnp", "upnp_root_device", "uuid", upnp_dev.urn)) == NULL) {
			dmuci_add_section_bbfdm("dmmap_upnp", "upnp_root_device", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "uuid", upnp_dev.urn);
		}

		upnp_dev.dmmap_sect = dmmap_sect;

		inst = handle_instance_without_section(dmctx, parent_node, ++root_inst);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &upnp_dev, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseUPnPDiscoveryDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *devices = NULL, *device = NULL;
	struct upnpdiscovery upnp_dev = {0};
	char *dev_descurl = NULL, *dev_st = NULL, *dev_usn = NULL, *inst = NULL;
	struct uci_section *dmmap_sect = NULL;
	char buf[512] = {0};

	dmubus_call("upnp", "discovery", UBUS_ARGS{{}}, 0, &res);
	if (res == NULL)
		return 0;

	json_object_object_get_ex(res, "devices", &devices);
	size_t nbre_devices = (devices) ? json_object_array_length(devices) : 0;

	for (int i = 0; i < nbre_devices; i++) {
		device = json_object_array_get_idx(devices, i);

		dev_descurl = dmjson_get_value(device, 1, "descurl");
		dev_st = dmjson_get_value(device, 1, "st");
		dev_usn = dmjson_get_value(device, 1, "usn");

		snprintf(buf, sizeof(buf), "%s", dev_usn);

		char *p = strstr(buf, "::");
		char *urn_p = NULL;

		if (p) {
			urn_p = p + 2;
			*p = 0;
			char *uuid = strchr(buf, ':');
			upnp_dev.uuid = uuid ? dmstrdup(uuid + 1) : "";
		}

		if (urn_p) {
			char *urn = strchr(urn_p, ':');
			upnp_dev.urn = urn ? dmstrdup(urn + 1) : "";
		}

		upnp_dev.descurl = dmstrdup(dev_descurl);
		upnp_dev.st = dmstrdup(dev_st);
		upnp_dev.usn = dmstrdup(dev_usn);

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_upnp", "upnp_device", "uuid", upnp_dev.uuid)) == NULL) {
			dmuci_add_section_bbfdm("dmmap_upnp", "upnp_device", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "uuid", upnp_dev.uuid);
		}

		upnp_dev.dmmap_sect = dmmap_sect;

		inst = handle_instance_without_section(dmctx, parent_node, i+1);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &upnp_dev, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseUPnPDiscoveryServiceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL,  *services = NULL, *service = NULL;
	struct upnpdiscovery upnp_dev = {0};
	char *srv_descurl = NULL, *srv_st = NULL, *srv_usn = NULL, *inst = NULL;
	struct uci_section* dmmap_sect = NULL;
	char buf[512] = {0};

	dmubus_call("upnp", "discovery", UBUS_ARGS{{}}, 0, &res);
	if (res == NULL)
		return 0;

	json_object_object_get_ex(res, "services", &services);
	size_t nbre_services = (services) ? json_object_array_length(services) : 0;

	for (int i = 0; i < nbre_services; i++){
		service = json_object_array_get_idx(services, i);

		srv_descurl = dmjson_get_value(service, 1, "descurl");
		srv_st = dmjson_get_value(service, 1, "st");
		srv_usn = dmjson_get_value(service, 1, "usn");


		snprintf(buf, sizeof(buf), "%s", srv_usn);

		char *p = strstr(buf, "::");
		char *urn_p = NULL;

		if (p) {
			urn_p = p + 2;
			*p = 0;
			char *uuid = strchr(buf, ':');
			upnp_dev.uuid = uuid ? dmstrdup(uuid + 1) : "";
		}

		if (urn_p) {
			char *urn = strchr(urn_p, ':');
			upnp_dev.urn = urn ? dmstrdup(urn + 1) : "";
		}

		upnp_dev.descurl = dmstrdup(srv_descurl);
		upnp_dev.st = dmstrdup(srv_st);
		upnp_dev.usn = dmstrdup(srv_usn);

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_upnp", "upnp_service", "usn", srv_usn)) == NULL) {
			dmuci_add_section_bbfdm("dmmap_upnp", "upnp_service", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "usn", srv_usn);
		}

		upnp_dev.dmmap_sect = dmmap_sect;

		inst = handle_instance_without_section(dmctx, parent_node, i+1);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &upnp_dev, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseUPnPDescriptionDeviceDescriptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *descriptions = NULL, *description = NULL;
	struct upnp_description_file_info upnp_desc = {0};
	char *descurl = NULL, *inst = NULL;
	struct uci_section* dmmap_sect = NULL;

	dmubus_call("upnp", "description", UBUS_ARGS{{}}, 0, &res);
	if (res == NULL)
		return 0;

	json_object_object_get_ex(res, "descriptions", &descriptions);
	size_t nbre_descriptions = (descriptions) ? json_object_array_length(descriptions) : 0;

	for (int i = 0; i < nbre_descriptions; i++) {
		description = json_object_array_get_idx(descriptions, i);

		descurl = dmjson_get_value(description, 1, "desc_url");
		upnp_desc.desc_url = dmstrdup(descurl);

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_upnp", "upnp_description", "descurl", descurl)) == NULL) {
			dmuci_add_section_bbfdm("dmmap_upnp", "upnp_description", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "descurl", descurl);
		}
		upnp_desc.dmmap_sect = dmmap_sect;

		inst = handle_instance_without_section(dmctx, parent_node, i+1);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &upnp_desc, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseUPnPDescriptionDeviceInstanceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL,  *devices_instances = NULL, *device_inst = NULL;
	struct upnp_device_inst upnp_dev_inst = {};
	char *inst = NULL;
	struct uci_section* dmmap_sect = NULL;
	int i;

	dmubus_call("upnp", "description", UBUS_ARGS{{}}, 0, &res);
	if (res == NULL)
		return 0;

	json_object_object_get_ex(res, "devices", &devices_instances);
	size_t nbre_devices_inst = (devices_instances) ? json_object_array_length(devices_instances) : 0;

	for (i = 0; i < nbre_devices_inst; i++){
		device_inst = json_object_array_get_idx(devices_instances, i);

		dmasprintf(&upnp_dev_inst.parentudn, "%s", dmjson_get_value(device_inst, 1, "parent_dev"));
		dmasprintf(&upnp_dev_inst.device_type, "%s", dmjson_get_value(device_inst, 1, "deviceType"));
		dmasprintf(&upnp_dev_inst.friendly_name, "%s", dmjson_get_value(device_inst, 1, "friendlyName"));
		dmasprintf(&upnp_dev_inst.manufacturer, "%s", dmjson_get_value(device_inst, 1, "manufacturer"));
		dmasprintf(&upnp_dev_inst.manufacturer_url, "%s", dmjson_get_value(device_inst, 1, "manufacturerURL"));
		dmasprintf(&upnp_dev_inst.model_description, "%s", dmjson_get_value(device_inst, 1, "modelDescription"));
		dmasprintf(&upnp_dev_inst.model_name, "%s", dmjson_get_value(device_inst, 1, "modelName"));
		dmasprintf(&upnp_dev_inst.model_number, "%s", dmjson_get_value(device_inst, 1, "modelNumber"));
		dmasprintf(&upnp_dev_inst.model_url, "%s", dmjson_get_value(device_inst, 1, "modelURL"));
		dmasprintf(&upnp_dev_inst.serial_number, "%s", dmjson_get_value(device_inst, 1, "serialNumber"));
		dmasprintf(&upnp_dev_inst.udn, "%s", dmjson_get_value(device_inst, 1, "UDN"));
		dmasprintf(&upnp_dev_inst.upc, "%s", dmjson_get_value(device_inst, 1, "UPC"));

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_upnp", "upnp_device_inst", "udn", dmjson_get_value(device_inst, 1, "UDN"))) == NULL) {
			dmuci_add_section_bbfdm("dmmap_upnp", "upnp_device_inst", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "udn", dmjson_get_value(device_inst, 1, "UDN"));
		}

		upnp_dev_inst.dmmap_sect = dmmap_sect;

		inst = handle_instance_without_section(dmctx, parent_node, i+1);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &upnp_dev_inst, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseUPnPDescriptionServiceInstanceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *services_instances = NULL, *service_inst = NULL;
	struct upnp_service_inst upnp_services_inst = {};
	char *inst = NULL;
	struct uci_section* dmmap_sect = NULL;
	int i;

	dmubus_call("upnp", "description", UBUS_ARGS{{}}, 0, &res);
	if (res == NULL)
		return 0;

	json_object_object_get_ex(res, "services", &services_instances);
	size_t nbre_devices_inst = (services_instances) ? json_object_array_length(services_instances) : 0;

	for (i = 0; i < nbre_devices_inst; i++) {
		service_inst = json_object_array_get_idx(services_instances, i);
		dmasprintf(&upnp_services_inst.parentudn, "%s", dmjson_get_value(service_inst, 1, "parent_dev"));
		dmasprintf(&upnp_services_inst.serviceid, "%s", dmjson_get_value(service_inst, 1, "serviceId"));
		dmasprintf(&upnp_services_inst.servicetype, "%s", dmjson_get_value(service_inst, 1, "serviceType"));
		dmasprintf(&upnp_services_inst.scpdurl, "%s", dmjson_get_value(service_inst, 1, "SCPDURL"));
		dmasprintf(&upnp_services_inst.controlurl, "%s", dmjson_get_value(service_inst, 1, "controlURL"));
		dmasprintf(&upnp_services_inst.eventsuburl, "%s", dmjson_get_value(service_inst, 1, "eventSubURL"));

		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_upnp", "upnp_service_inst", "serviceid", dmjson_get_value(service_inst, 1, "serviceId"))) == NULL) {
			dmuci_add_section_bbfdm("dmmap_upnp", "upnp_service_inst", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "serviceid", dmjson_get_value(service_inst, 1, "serviceId"));
		}

		upnp_services_inst.dmmap_sect = dmmap_sect;

		inst = handle_instance_without_section(dmctx, parent_node, i+1);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &upnp_services_inst, inst) == DM_STOP)
			break;
	}
	return 0;
}
/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.UPnP.Device.Enable!UCI:upnpd/upnpd,config/enabled*/
static int get_UPnPDevice_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("upnpd", "config", "enabled", "1");
	return 0;
}

static int set_UPnPDevice_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("upnpd", "config", "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_UPnPDeviceCapabilities_UPnPArchitecture(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_UPnPDeviceCapabilities_UPnPArchitectureMinorVer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_UPnPDeviceCapabilities_UPnPIGD(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("upnpd", "config", "igdv1", value);
	*value = (DM_STRLEN(*value) && *value[0] == '1') ? "1" : "2";
	return 0;
}

static int get_UPnPDiscovery_RootDeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUPnPDiscoveryRootDeviceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_UPnPDiscovery_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUPnPDiscoveryDeviceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_UPnPDiscovery_ServiceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUPnPDiscoveryServiceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.UPnP.Discovery.RootDevice.{i}.UUID!UBUS:upnpc/discovery//devices[i-1].st*/
static int get_UPnPDiscoveryRootDevice_UUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->uuid;
	return 0;
}

/*#Device.UPnP.Discovery.RootDevice.{i}.USN!UBUS:upnpc/discovery//devices[i-1].usn*/
static int get_UPnPDiscoveryRootDevice_USN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->usn;
	return 0;
}

/*#Device.UPnP.Discovery.RootDevice.{i}.Location!UBUS:upnpc/discovery//devices[i-1].descurl*/
static int get_UPnPDiscoveryRootDevice_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->descurl;
	return 0;
}

/*#Device.UPnP.Discovery.Device.{i}.UUID!UBUS:upnpc/discovery//devices[i-1].st*/
static int get_UPnPDiscoveryDevice_UUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->uuid;
	return 0;
}

/*#Device.UPnP.Discovery.Device.{i}.USN!UBUS:upnpc/discovery//devices[i-1].usn*/
static int get_UPnPDiscoveryDevice_USN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->usn;
	return 0;
}

/*#Device.UPnP.Discovery.Device.{i}.Location!UBUS:upnpc/discovery//devices[i-1].descurl*/
static int get_UPnPDiscoveryDevice_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->descurl;
	return 0;
}

/*#Device.UPnP.Discovery.Service.{i}.USN!UBUS:upnpc/discovery//services[i-1].usn*/
static int get_UPnPDiscoveryService_USN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->usn;
	return 0;
}

/*#Device.UPnP.Discovery.Service.{i}.Location!UBUS:upnpc/discovery//services[i-1].descurl*/
static int get_UPnPDiscoveryService_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnpdiscovery *)data)->descurl;
	return 0;
}

static int get_UPnPDiscoveryService_ParentDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_reference_param(ctx, "Device.UPnP.Discovery.Device.*.UUID", ((struct upnpdiscovery *)data)->uuid, value);

	if (!DM_STRLEN(*value))
		adm_entry_get_reference_param(ctx, "Device.UPnP.Discovery.RootDevice.*.UUID", ((struct upnpdiscovery *)data)->uuid, value);

	return 0;
}

static int get_UPnPDescription_DeviceDescriptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUPnPDescriptionDeviceDescriptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_UPnPDescription_DeviceInstanceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUPnPDescriptionDeviceInstanceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_UPnPDescription_ServiceInstanceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUPnPDescriptionServiceInstanceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.UPnP.Description.DeviceDescription.{i}.URLBase!UBUS:upnpc/description//descriptions[i-1].descurl*/
static int get_UPnPDescriptionDeviceDescription_URLBase(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_description_file_info *)data)->desc_url;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.UDN!UBUS:upnpc/description//devicesinstances[i-1].UDN*/
static int get_UPnPDescriptionDeviceInstance_UDN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->udn;
	return 0;
}

static int get_UPnPDescriptionDeviceInstance_ParentDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_reference_param(ctx, "Device.UPnP.Description.DeviceInstance.*.UDN", ((struct upnp_device_inst *)data)->parentudn, value);
	return 0;
}

static int get_UPnPDescriptionDeviceInstance_DiscoveryDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct upnp_device_inst *upnpdevinst = (struct upnp_device_inst *)data;

	if (upnpdevinst->udn && upnpdevinst->udn[0]) {
		size_t length = 0;

		char **udnarray = strsplit(upnpdevinst->udn, ":", &length);

		if (length != 2)
			return 0;

		adm_entry_get_reference_param(ctx, "Device.UPnP.Discovery.Device.*.UUID", udnarray[1], value);

		if (!DM_STRLEN(*value))
			adm_entry_get_reference_param(ctx, "Device.UPnP.Discovery.RootDevice.*.UUID", udnarray[1], value);
	}

	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.DeviceType!UBUS:upnpc/description//devicesinstances[i-1].deviceType*/
static int get_UPnPDescriptionDeviceInstance_DeviceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->device_type;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.FriendlyName!UBUS:upnpc/description//devicesinstances[i-1].friendlyName*/
static int get_UPnPDescriptionDeviceInstance_FriendlyName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->friendly_name;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.Manufacturer!UBUS:upnpc/description//devicesinstances[i-1].manufacturer*/
static int get_UPnPDescriptionDeviceInstance_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->manufacturer;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.ManufacturerURL!UBUS:upnpc/description//devicesinstances[i-1].manufacturerURL*/
static int get_UPnPDescriptionDeviceInstance_ManufacturerURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->manufacturer_url;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.ModelDescription!UBUS:upnpc/description//devicesinstances[i-1].modelDescription*/
static int get_UPnPDescriptionDeviceInstance_ModelDescription(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->model_description;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.ModelName!UBUS:upnpc/description//devicesinstances[i-1].modelName*/
static int get_UPnPDescriptionDeviceInstance_ModelName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->model_name;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.ModelNumber!UBUS:upnpc/description//devicesinstances[i-1].modelNumber*/
static int get_UPnPDescriptionDeviceInstance_ModelNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->model_number;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.ModelURL!UBUS:upnpc/description//devicesinstances[i-1].modelURL*/
static int get_UPnPDescriptionDeviceInstance_ModelURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->model_url;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.SerialNumber!UBUS:upnpc/description//devicesinstances[i-1].serialNumber*/
static int get_UPnPDescriptionDeviceInstance_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->serial_number;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.UPC!UBUS:upnpc/description//devicesinstances[i-1].UPC*/
static int get_UPnPDescriptionDeviceInstance_UPC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->upc;
	return 0;
}

/*#Device.UPnP.Description.DeviceInstance.{i}.PresentationURL!UBUS:upnpc/description//devicesinstances[i-1].preentation_url*/
static int get_UPnPDescriptionDeviceInstance_PresentationURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_device_inst *)data)->preentation_url;
	return 0;
}

static int get_UPnPDescriptionServiceInstance_ParentDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_reference_param(ctx, "Device.UPnP.Description.DeviceInstance.*.UDN", ((struct upnp_service_inst *)data)->parentudn, value);
	return 0;
}

/*#Device.UPnP.Description.ServiceInstance.{i}.ServiceId!UBUS:upnpc/description//servicesinstances[i-1].serviceId*/
static int get_UPnPDescriptionServiceInstance_ServiceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_service_inst *)data)->serviceid;
	return 0;
}

static int get_UPnPDescriptionServiceInstance_ServiceDiscovery(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char usn[512] = {0};

	snprintf(usn, sizeof(usn), "%s::%s", ((struct upnp_service_inst *)data)->parentudn, ((struct upnp_service_inst *)data)->servicetype);

	adm_entry_get_reference_param(ctx, "Device.UPnP.Discovery.Service.*.USN", usn, value);
	return 0;
}

/*#Device.UPnP.Description.ServiceInstance.{i}.ServiceType!UBUS:upnpc/description//servicesinstances[i-1].serviceType*/
static int get_UPnPDescriptionServiceInstance_ServiceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_service_inst *)data)->servicetype;
	return 0;
}

/*#Device.UPnP.Description.ServiceInstance.{i}.SCPDURL!UBUS:upnpc/description//servicesinstances[i-1].SCPDURL*/
static int get_UPnPDescriptionServiceInstance_SCPDURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_service_inst *)data)->scpdurl;
	return 0;
}

/*#Device.UPnP.Description.ServiceInstance.{i}.ControlURL!UBUS:upnpc/description//servicesinstances[i-1].controlURL*/
static int get_UPnPDescriptionServiceInstance_ControlURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_service_inst *)data)->controlurl;
	return 0;
}

/*#Device.UPnP.Description.ServiceInstance.{i}.EventSubURL!UBUS:upnpc/description//servicesinstances[i-1].eventSubURL*/
static int get_UPnPDescriptionServiceInstance_EventSubURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct upnp_service_inst *)data)->eventsuburl;
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.UPnP. *** */
DMOBJ tUPnPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Device", &DMREAD, NULL, NULL, "file:/etc/config/upnpd", NULL, NULL, NULL, tUPnPDeviceObj, tUPnPDeviceParams, NULL, BBFDM_BOTH, NULL},
{"Discovery", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUPnPDiscoveryObj, tUPnPDiscoveryParams, NULL, BBFDM_BOTH, NULL},
{"Description", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUPnPDescriptionObj, tUPnPDescriptionParams, NULL, BBFDM_BOTH, NULL},
{0}
};

/* *** Device.UPnP.Device. *** */
DMOBJ tUPnPDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUPnPDeviceCapabilitiesParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tUPnPDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_UPnPDevice_Enable, set_UPnPDevice_Enable, BBFDM_BOTH},
//{"UPnPMediaServer", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPMediaServer, set_UPnPDevice_UPnPMediaServer, BBFDM_BOTH},
//{"UPnPMediaRenderer", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPMediaRenderer, set_UPnPDevice_UPnPMediaRenderer, BBFDM_BOTH},
//{"UPnPWLANAccessPoint", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPWLANAccessPoint, set_UPnPDevice_UPnPWLANAccessPoint, BBFDM_BOTH},
//{"UPnPQoSDevice ", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPQoSDevice , set_UPnPDevice_UPnPQoSDevice , BBFDM_BOTH},
//{"UPnPQoSPolicyHolder", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPQoSPolicyHolder, set_UPnPDevice_UPnPQoSPolicyHolder, BBFDM_BOTH},
//{"UPnPIGD", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPIGD, set_UPnPDevice_UPnPIGD, BBFDM_BOTH},
//{"UPnPDMBasicMgmt", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPDMBasicMgmt, set_UPnPDevice_UPnPDMBasicMgmt, BBFDM_BOTH},
//{"UPnPDMConfigurationMgmt", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPDMConfigurationMgmt, set_UPnPDevice_UPnPDMConfigurationMgmt, BBFDM_BOTH},
//{"UPnPDMSoftwareMgmt", &DMWRITE, DMT_BOOL, get_UPnPDevice_UPnPDMSoftwareMgmt, set_UPnPDevice_UPnPDMSoftwareMgmt, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Device.Capabilities. *** */
DMLEAF tUPnPDeviceCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"UPnPArchitecture", &DMREAD, DMT_UNINT, get_UPnPDeviceCapabilities_UPnPArchitecture, NULL, BBFDM_BOTH},
{"UPnPArchitectureMinorVer", &DMREAD, DMT_UNINT, get_UPnPDeviceCapabilities_UPnPArchitectureMinorVer, NULL, BBFDM_BOTH},
{"UPnPIGD", &DMREAD, DMT_UNINT, get_UPnPDeviceCapabilities_UPnPIGD, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Discovery. *** */
DMOBJ tUPnPDiscoveryObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"RootDevice", &DMREAD, NULL, NULL, NULL, browseUPnPDiscoveryRootDeviceInst, NULL, NULL, NULL, tUPnPDiscoveryRootDeviceParams, NULL, BBFDM_BOTH, NULL},
{"Device", &DMREAD, NULL, NULL, NULL, browseUPnPDiscoveryDeviceInst, NULL, NULL, NULL, tUPnPDiscoveryDeviceParams, NULL, BBFDM_BOTH, NULL},
{"Service", &DMREAD, NULL, NULL, NULL, browseUPnPDiscoveryServiceInst, NULL, NULL, NULL, tUPnPDiscoveryServiceParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tUPnPDiscoveryParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"RootDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_UPnPDiscovery_RootDeviceNumberOfEntries, NULL, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_UPnPDiscovery_DeviceNumberOfEntries, NULL, BBFDM_BOTH},
{"ServiceNumberOfEntries", &DMREAD, DMT_UNINT, get_UPnPDiscovery_ServiceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Discovery.RootDevice.{i}. *** */
DMLEAF tUPnPDiscoveryRootDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Status", &DMREAD, DMT_STRING, get_UPnPDiscoveryRootDevice_Status, NULL, BBFDM_BOTH},
{"UUID", &DMREAD, DMT_STRING, get_UPnPDiscoveryRootDevice_UUID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"USN", &DMREAD, DMT_STRING, get_UPnPDiscoveryRootDevice_USN, NULL, BBFDM_BOTH},
//{"LeaseTime", &DMREAD, DMT_UNINT, get_UPnPDiscoveryRootDevice_LeaseTime, NULL, BBFDM_BOTH},
{"Location", &DMREAD, DMT_STRING, get_UPnPDiscoveryRootDevice_Location, NULL, BBFDM_BOTH},
//{"Server", &DMREAD, DMT_STRING, get_UPnPDiscoveryRootDevice_Server, NULL, BBFDM_BOTH},
//{"Host", &DMREAD, DMT_STRING, get_UPnPDiscoveryRootDevice_Host, NULL, BBFDM_BOTH},
//{"LastUpdate", &DMREAD, DMT_TIME, get_UPnPDiscoveryRootDevice_LastUpdate, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Discovery.Device.{i}. *** */
DMLEAF tUPnPDiscoveryDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Status", &DMREAD, DMT_STRING, get_UPnPDiscoveryDevice_Status, NULL, BBFDM_BOTH},
{"UUID", &DMREAD, DMT_STRING, get_UPnPDiscoveryDevice_UUID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"USN", &DMREAD, DMT_STRING, get_UPnPDiscoveryDevice_USN, NULL, BBFDM_BOTH},
//{"LeaseTime", &DMREAD, DMT_UNINT, get_UPnPDiscoveryDevice_LeaseTime, NULL, BBFDM_BOTH},
{"Location", &DMREAD, DMT_STRING, get_UPnPDiscoveryDevice_Location, NULL, BBFDM_BOTH},
//{"Server", &DMREAD, DMT_STRING, get_UPnPDiscoveryDevice_Server, NULL, BBFDM_BOTH},
//{"Host", &DMREAD, DMT_STRING, get_UPnPDiscoveryDevice_Host, NULL, BBFDM_BOTH},
//{"LastUpdate", &DMREAD, DMT_TIME, get_UPnPDiscoveryDevice_LastUpdate, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Discovery.Service.{i}. *** */
DMLEAF tUPnPDiscoveryServiceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Status", &DMREAD, DMT_STRING, get_UPnPDiscoveryService_Status, NULL, BBFDM_BOTH},
{"USN", &DMREAD, DMT_STRING, get_UPnPDiscoveryService_USN, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
//{"LeaseTime", &DMREAD, DMT_UNINT, get_UPnPDiscoveryService_LeaseTime, NULL, BBFDM_BOTH},
{"Location", &DMREAD, DMT_STRING, get_UPnPDiscoveryService_Location, NULL, BBFDM_BOTH},
//{"Server", &DMREAD, DMT_STRING, get_UPnPDiscoveryService_Server, NULL, BBFDM_BOTH},
//{"Host", &DMREAD, DMT_STRING, get_UPnPDiscoveryService_Host, NULL, BBFDM_BOTH},
//{"LastUpdate", &DMREAD, DMT_TIME, get_UPnPDiscoveryService_LastUpdate, NULL, BBFDM_BOTH},
{"ParentDevice", &DMREAD, DMT_STRING, get_UPnPDiscoveryService_ParentDevice, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Description. *** */
DMOBJ tUPnPDescriptionObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DeviceDescription", &DMREAD, NULL, NULL, NULL, browseUPnPDescriptionDeviceDescriptionInst, NULL, NULL, NULL, tUPnPDescriptionDeviceDescriptionParams, NULL, BBFDM_BOTH, NULL},
{"DeviceInstance", &DMREAD, NULL, NULL, NULL, browseUPnPDescriptionDeviceInstanceInst, NULL, NULL, NULL, tUPnPDescriptionDeviceInstanceParams, NULL, BBFDM_BOTH, NULL},
{"ServiceInstance", &DMREAD, NULL, NULL, NULL, browseUPnPDescriptionServiceInstanceInst, NULL, NULL, NULL, tUPnPDescriptionServiceInstanceParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tUPnPDescriptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"DeviceDescriptionNumberOfEntries", &DMREAD, DMT_UNINT, get_UPnPDescription_DeviceDescriptionNumberOfEntries, NULL, BBFDM_BOTH},
{"DeviceInstanceNumberOfEntries", &DMREAD, DMT_UNINT, get_UPnPDescription_DeviceInstanceNumberOfEntries, NULL, BBFDM_BOTH},
{"ServiceInstanceNumberOfEntries", &DMREAD, DMT_UNINT, get_UPnPDescription_ServiceInstanceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Description.DeviceDescription.{i}. *** */
DMLEAF tUPnPDescriptionDeviceDescriptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"URLBase", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceDescription_URLBase, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
//{"SpecVersion", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceDescription_SpecVersion, NULL, BBFDM_BOTH},
//{"Host", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceDescription_Host, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Description.DeviceInstance.{i}. *** */
DMLEAF tUPnPDescriptionDeviceInstanceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"UDN", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_UDN, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ParentDevice", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ParentDevice, NULL, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"DiscoveryDevice", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_DiscoveryDevice, NULL, BBFDM_BOTH},
{"DeviceType", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_DeviceType, NULL, BBFDM_BOTH},
{"FriendlyName", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_FriendlyName, NULL, BBFDM_BOTH},
//{"DeviceCategory", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_DeviceCategory, NULL, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_Manufacturer, NULL, BBFDM_BOTH},
//{"ManufacturerOUI", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ManufacturerOUI, NULL, BBFDM_BOTH},
{"ManufacturerURL", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ManufacturerURL, NULL, BBFDM_BOTH},
{"ModelDescription", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ModelDescription, NULL, BBFDM_BOTH},
{"ModelName", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ModelName, NULL, BBFDM_BOTH},
{"ModelNumber", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ModelNumber, NULL, BBFDM_BOTH},
{"ModelURL", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_ModelURL, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_SerialNumber, NULL, BBFDM_BOTH},
{"UPC", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_UPC, NULL, BBFDM_BOTH},
{"PresentationURL", &DMREAD, DMT_STRING, get_UPnPDescriptionDeviceInstance_PresentationURL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Description.ServiceInstance.{i}. *** */
DMLEAF tUPnPDescriptionServiceInstanceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ParentDevice", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_ParentDevice, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_REFERENCE},
{"ServiceId", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_ServiceId, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ServiceDiscovery", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_ServiceDiscovery, NULL, BBFDM_BOTH},
{"ServiceType", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_ServiceType, NULL, BBFDM_BOTH},
{"SCPDURL", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_SCPDURL, NULL, BBFDM_BOTH},
{"ControlURL", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_ControlURL, NULL, BBFDM_BOTH},
{"EventSubURL", &DMREAD, DMT_STRING, get_UPnPDescriptionServiceInstance_EventSubURL, NULL, BBFDM_BOTH},
{0}
};
