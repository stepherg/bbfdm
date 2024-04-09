/*
 * Copyright (C) 2024 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *		Author: Mohd Husaam Mehdi <husaam.mehdi@iopsys.eu>
 */

#include "gre.h"
#include "dmlayer.h"

/*************************************************************
* UTILITY METHODS
**************************************************************/
/* wrapper to avoid long lines */
static char *get_tunnel_name(struct uci_section *tunnel_section)
{
	return dmuci_get_value_by_section_fallback_def(tunnel_section, "name", "");
}


/* different family tunnels have different option proto */
static char *get_tunnel_dev_proto_family(struct uci_section *tunnel_section)
{
	if (!tunnel_section) {
		return "";
	}

	char *tunnel_dev_mode = dmuci_get_value_by_section_fallback_def(tunnel_section, "mode", "");

	if (!DM_LSTRCMP(tunnel_dev_mode, "greip6")) {
		return "grev6";
	} else {
		return "gre";
	}
}

/* delete sections from both main UCI and dmmap UCI */
static void delete_all_sections_with_opt_eq(char *package, char *section_type, char *option, char *value)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_section = NULL;

	if (!package || !section_type || !option || !value) {
		return;
	}

	uci_foreach_option_eq_safe(package, section_type, option, value, stmp, s) {
		dmmap_section = NULL;

		get_dmmap_section_of_config_section("dmmap_gre", section_type, section_name(s), &dmmap_section);

		dmuci_delete_by_section(dmmap_section, NULL, NULL);
		dmuci_delete_by_section(s, NULL, NULL);
	}
}

/* set value in all sections in main UCI */
static void set_all_sections_with_opt_eq(char *package, char *section_type, char *option, char *value, char *set_option, char *set_value)
{
	struct uci_section *s = NULL;

	if (!package || !section_type || !option || !value || !set_option || !set_value) {
		return;
	}

	uci_foreach_option_eq(package, section_type, option, value, s) {
		// do not remove device of interface section
		if (!DM_LSTRCMP(set_option, "device") && !DM_LSTRCMP(set_value, "")) {
			dmuci_set_value_by_section(s, set_option, section_name(s));
		} else {
			dmuci_set_value_by_section(s, set_option, set_value);
		}
	}
}

/* update interface sections corresponding to Tunnel.Interface.LowerLayer, as changed proto leads to changed dev name*/
static void update_all_interface_upper_layers(char *tunnel_dev_name, bool is_current_ipv6)
{
	struct uci_section *s = NULL, *s_lower = NULL;

	if (!tunnel_dev_name || !DM_STRLEN(tunnel_dev_name)) {
		return;
	}

	// for all interfaces that have this tunnel_dev
	uci_foreach_option_eq("network", "interface", "device", tunnel_dev_name, s) {
		s_lower = NULL;
		// get the interface name
		char *if_section_name = section_name(s);
		char current_lower_layer_device[32] = {0};
		char new_lower_layer_device[32] = {0};

		if (is_current_ipv6) {
			snprintf(current_lower_layer_device, sizeof(current_lower_layer_device), "gre6-%s", if_section_name);
			snprintf(new_lower_layer_device, sizeof(new_lower_layer_device), "gre4-%s", if_section_name);
		} else {
			snprintf(current_lower_layer_device, sizeof(current_lower_layer_device), "gre4-%s", if_section_name);
			snprintf(new_lower_layer_device, sizeof(new_lower_layer_device), "gre6-%s", if_section_name);
		}

		// for all interfaces that have device set to the name generated from current tunnel.interface
		uci_foreach_option_eq("network", "interface", "device", current_lower_layer_device, s_lower) {
			// update device
			dmuci_set_value_by_section(s_lower, "device", new_lower_layer_device);
		}
	}
}

static char *get_gre_tunnel_interface_statistics(json_object *json_stats, char *key)
{
	char *value = NULL;
	if (!json_stats || !key) {
		return "0";
	}

	value = dmjson_get_value(json_stats, 2, "statistics", key);
	return value ? value : "0";
}

/* remove device section of interface sections corresponding to lowerlayer */
static void empty_all_upper_layers_of_interface(struct uci_section *iface_section)
{
	char tunnel_system_name[32] = {0};

	if (!iface_section)
		return;

	gre___get_tunnel_system_name(iface_section, &tunnel_system_name[0], sizeof(tunnel_system_name));

	// remove tunnel system name from option device of the interface section of lower layers
	// otherwise tunnel interface is not removed from the system
	set_all_sections_with_opt_eq("network", "interface", "device", tunnel_system_name, "device", "");
}

static void remove_all_interfaces_of_tunnel(char *tunnel_dev_name)
{
	if (!tunnel_dev_name || !DM_STRLEN(tunnel_dev_name)) {
		return;
	}

	struct uci_section *s = NULL;

	// for all interfaces of this tunnel
	uci_foreach_option_eq("network", "interface", "device", tunnel_dev_name, s) {
		empty_all_upper_layers_of_interface(s);
	}

	// delete all sections corresponding to tunnel.interface
	delete_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name);
}

static void remove_tunnel(struct uci_section *tunnel_section, struct uci_section *tunnel_dmmap_section)
{
	if (!tunnel_section)
		return;

	char *tunnel_dev_name = NULL;

	tunnel_dev_name = dmuci_get_value_by_section_fallback_def(tunnel_section, "name", "");

	// delete all sections corresponding to Tunnel.Interface
	remove_all_interfaces_of_tunnel(tunnel_dev_name);

	// remove the tunnel dmmap section
	if (tunnel_dmmap_section == NULL) {
		struct uci_section *dmmap_section = NULL;
		get_dmmap_section_of_config_section("dmmap_gre", "interface", section_name(tunnel_section), &dmmap_section);
		dmuci_delete_by_section(dmmap_section, NULL, NULL);
	} else {
		dmuci_delete_by_section(tunnel_dmmap_section, NULL, NULL);
	}

	// remove tunnel network UCI section
	dmuci_delete_by_section(tunnel_section, NULL, NULL);
}

static void remove_all_tunnels(void)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_foreach_option_eq_safe("network", "device", "mode", "greip", stmp, s) {
		remove_tunnel(s, NULL);
	}

	s = NULL, stmp = NULL;
	uci_foreach_option_eq_safe("network", "device", "mode", "greip6", stmp, s) {
		remove_tunnel(s, NULL);
	}
}
/*************************************************************
* ENTRY METHOD
*************************************************************/
static int browseGRETunnelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dm_data *curr_data = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("network", "device", "dmmap_gre", "mode", "greip", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "gre_tunnel_instance", "gre_tunnel_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseGRETunnelInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL;
	char *inst = NULL;
	struct dm_data *curr_data = NULL;
	char *tunnel_dev_name = NULL;
	char *tunnel_instance = NULL;
	LIST_HEAD(dup_list);

	tunnel_dev_name = dmuci_get_value_by_section_fallback_def(((struct dm_data *)prev_data)->config_section, "name", "");
	if (!DM_STRLEN(tunnel_dev_name))
		return 0;

	tunnel_instance = dmuci_get_value_by_section_fallback_def(((struct dm_data *)prev_data)->dmmap_section, "gre_tunnel_instance", "");

	dmubus_call("network.device", "status", UBUS_ARGS{0}, 0, &res);

	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_gre", "device", tunnel_dev_name, &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {
		// get system name for this interface
		char tunnel_system_name[32] = {0};
		gre___get_tunnel_system_name(curr_data->config_section, &tunnel_system_name[0], sizeof(tunnel_system_name));

		// loop over all objects of network.device status
		json_object_object_foreach(res, key, val) {
			if (DM_LSTRCMP(key, tunnel_system_name) == 0) {
				curr_data->json_object = json_object_get(val);
				break;
			}
		}

		// set tunnel instance in dmmap gre interface section, needed for interfacestack
		dmuci_set_value_by_section(curr_data->dmmap_section, "tunnel_instance", tunnel_instance);

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "gre_iface_instance", "gre_iface_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);

	return 0;
}

/*************************************************************
* ADD & DEL OBJ
*************************************************************/
static int addObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dev_sec = NULL, *dmmap_sec = NULL;
	char buf[32] = {0};

	snprintf(buf, sizeof(buf), "gre_dev_%s", *instance);

	dmuci_add_section("network", "device", &dev_sec);
	dmuci_rename_section_by_section(dev_sec, buf);
	dmuci_set_value_by_section(dev_sec, "name", buf);
	dmuci_set_value_by_section(dev_sec, "type", "tunnel");
	dmuci_set_value_by_section(dev_sec, "mode", "greip");

	dmuci_add_section_bbfdm("dmmap_gre", "device", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", buf);
	dmuci_set_value_by_section(dmmap_sec, "gre_tunnel_instance", *instance);
	return 0;
}

static int delObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			remove_tunnel(((struct dm_data *)data)->config_section, ((struct dm_data *)data)->dmmap_section);
			break;
		case DEL_ALL:
			remove_all_tunnels();
			break;
	}
	return 0;
}

static int addObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *if_sec = NULL, *dmmap_sec = NULL;
	char buf[32] = {0};
	struct uci_section *tunnel_section = ((struct dm_data *)data)->config_section;
	char *tunnel_instance = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->dmmap_section, "gre_tunnel_instance", "");

	char *proto = get_tunnel_dev_proto_family(tunnel_section);
	char *disabled = dmuci_get_value_by_section_fallback_def(tunnel_section, "disabled", "0");
	char *remote = dmuci_get_value_by_section_fallback_def(tunnel_section, "remote", "");

	// name is derived from tunnel number and intf number
	snprintf(buf, sizeof(buf), "gre_d%si%s", tunnel_instance, *instance);

	dmuci_add_section("network", "interface", &if_sec);
	dmuci_rename_section_by_section(if_sec, buf);
	dmuci_set_value_by_section(if_sec, "proto", proto);
	dmuci_set_value_by_section(if_sec, "device", get_tunnel_name(tunnel_section));
	dmuci_set_value_by_section(if_sec, "disabled", disabled);

	if (DM_STRLEN(remote)) {
		if (!DM_LSTRCMP(proto, "grev6")) {
			dmuci_set_value_by_section(if_sec, "peer6addr", remote);
		} else {
			dmuci_set_value_by_section(if_sec, "peeraddr", remote);
		}
	}

	dmuci_add_section_bbfdm("dmmap_gre", "interface", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", buf);
	dmuci_set_value_by_section(dmmap_sec, "gre_iface_instance", *instance);
	return 0;
}

static int delObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	char *tunnel_dev_name = NULL;

	switch (del_action) {
		case DEL_INST:
			empty_all_upper_layers_of_interface(((struct dm_data *)data)->config_section);
			// Remove interface section in network UCI
			dmuci_delete_by_section(((struct dm_data *)data)->config_section, NULL, NULL);
			// Remove interface section in dmmap_gre
			dmuci_delete_by_section(((struct dm_data *)data)->dmmap_section, NULL, NULL);

			break;
		case DEL_ALL:
			tunnel_dev_name = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "name", "");
			remove_all_interfaces_of_tunnel(tunnel_dev_name);
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
*************************************************************/

static int get_GRE_TunnelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseGRETunnelInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_GRETunnel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "disabled", "0");

	if (!DM_STRCMP(disabled, "0") || !DM_STRCMP(disabled, "false"))
		*value = "1";
	else
		*value = "0";

	return 0;
}

static int set_GRETunnel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *tunnel_section = ((struct dm_data *)data)->config_section;
	bool b = true;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			char *disabled = b ? "0" : "1";

			dmuci_set_value_by_section(tunnel_section, "disabled", disabled);
			// disabling the device will have no effect so apply to all interfaces
			set_all_sections_with_opt_eq("network", "interface", "device", get_tunnel_name(tunnel_section), "disabled", disabled );
			break;
	}
	return 0;
}

static int get_GRETunnel_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "disabled", "0");

	if (!DM_STRCMP(disabled, "0") || !DM_STRCMP(disabled, "false")) {
		*value = "Enabled";
	} else {
		*value = "Disabled";
	}

	return 0;
}

/*#Device.GRE.Tunnel.{i}.Alias!UCI:dmmap_gre/interface,@i-1/gre_tunnel_alias*/
static int get_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "gre_tunnel_alias", instance, value);
}

static int set_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "gre_tunnel_alias", instance, value);
}

static int get_GRETunnel_DeliveryHeaderProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "mode", &proto);

	if (proto && !DM_LSTRCMP(proto, "greip6")) {
		*value = "IPv6";
	} else {
		*value = "IPv4";
	}
	return 0;
}

static int set_GRETunnel_DeliveryHeaderProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *DeliveryHeaderProtocol[] = {"IPv4", "IPv6", NULL};
	char *current_delivery_header = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, DeliveryHeaderProtocol, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			get_GRETunnel_DeliveryHeaderProtocol(refparam, ctx, data, instance, &current_delivery_header);

			// if current delivery header and new delivery header are same, do nothing
			// if different, find the device name for this tunnel
			// for every interface that has device as this device name, update device name there
			// delete current peeraddr or peer6addr as applicable
			// and set a new empty one
			// finally update the proto
			if (DM_LSTRCMP(current_delivery_header, value)) {
				struct uci_section *tunnel_section = ((struct dm_data *)data)->config_section;
				char *current_proto = get_tunnel_dev_proto_family(tunnel_section);
				char *tunnel_dev_name = get_tunnel_name(tunnel_section);

				// changing from grev6 to gre
				if (!DM_LSTRCMP(current_proto, "grev6")) {
					// update mode in tunnel device section
					dmuci_set_value_by_section(tunnel_section, "mode", "greip");
					// remove remote because now we need different family's address
					dmuci_set_value_by_section(tunnel_section, "remote", "");

					// update proto to gre in all sections belonging to tunnel.interface
					set_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name, "proto", "gre");
					// remove peer6addr because now we need peeraddr
					set_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name, "peer6addr", "");
					// update device in all sections which have this tunnel.interface as lower layer
					bool is_current_ipv6 = true;
					update_all_interface_upper_layers(tunnel_dev_name, is_current_ipv6);
				// changing from gre to grev6
				} else {
					// current is greip, new is greip6
					// update mode in tunnel device section
					dmuci_set_value_by_section(tunnel_section, "mode", "greip6");
					// remove remote because now we need different family's address
					dmuci_set_value_by_section(tunnel_section, "remote", "");

					// update proto to grev6 in all sections belonging to tunnel.interface
					set_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name, "proto", "grev6");
					// remove peeraddr because now we need peer6addr
					set_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name, "peeraddr", "");
					// update device in all sections which have this tunnel.interface as lower layer
					bool is_current_ipv6 = false;
					update_all_interface_upper_layers(tunnel_dev_name, is_current_ipv6);
				}
			}
			break;
	}
	return 0;
}

static int get_GRETunnel_RemoteEndpoints(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *tunnel_section = ((struct dm_data *)data)->config_section;

	*value = dmuci_get_value_by_section_fallback_def(tunnel_section, "remote", "");

	return 0;
}

static int set_GRETunnel_RemoteEndpoints(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *tunnel_section = ((struct dm_data *)data)->config_section;
	char *proto = NULL, *tunnel_dev_name = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			proto = get_tunnel_dev_proto_family(tunnel_section);
			tunnel_dev_name = get_tunnel_name(tunnel_section);

			// set the option remote in tunnel device section
			dmuci_set_value_by_section(tunnel_section, "remote", value);

			if (!DM_LSTRCMP(proto, "grev6")) {
				// set the peer6addr in all interfaces of this tunnel
				set_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name, "peer6addr", value);
			} else {
				set_all_sections_with_opt_eq("network", "interface", "device", tunnel_dev_name, "peeraddr", value);
			}

			break;
	}
	return 0;
}

static int get_GRETunnel_ConnectedRemoteEndpoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	// current implementation restricts us to only have one possible value for peer address
	// ConnectedRemoteEndpoint is same as RemoteEndpoint
	get_GRETunnel_RemoteEndpoints(refparam, ctx, data, instance, value);
	return 0;
}

static int get_GRETunnel_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseGRETunnelInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_GRETunnelInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "disabled", "0");

	if (!DM_STRCMP(disabled, "0") || !DM_STRCMP(disabled, "false")) {
		*value = "1";
	} else {
		*value = "0";
	}

	return 0;
}

static int set_GRETunnelInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *tunnel_intf_section = ((struct dm_data *)data)->config_section;
	bool b = true;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			char *disabled = b ? "0" : "1";

			dmuci_set_value_by_section(tunnel_intf_section, "disabled", disabled);
			break;
	}
	return 0;
}

static int get_GRETunnelInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "disabled", "0");

	if (!DM_STRCMP(disabled, "1") || !DM_STRCMP(disabled, "true")) {
		*value = "Down";
		return 0;
	}

	char tunnel_system_name[32] = {0};
	gre___get_tunnel_system_name(((struct dm_data *)data)->config_section, &tunnel_system_name[0], sizeof(tunnel_system_name));

	return get_net_device_status(tunnel_system_name, value);
}

/*#Device.GRE.Tunnel.{i}.Interface.{i}.Alias!UCI:dmmap_gre/interface,@i-1/gre_iface_alias*/
static int get_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "gre_iface_alias", instance, value);
}

static int set_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "gre_iface_alias", instance, value);
}

static int get_GRETunnelInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct dm_data *)data)->config_section));
	return 0;
}

static int get_GRETunnelInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	char *if_name = section_name(((struct dm_data *)data)->config_section);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}


static int get_GRETunnelInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->dmmap_section, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		char *tunlink = NULL;

		dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "tunlink", &tunlink);

		adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", tunlink, value);

		// Store LowerLayers value
		dmuci_set_value_by_section(((struct dm_data *)data)->dmmap_section, "LowerLayers", *value);
	} else {
		if (!adm_entry_object_exists(ctx, *value))
			*value = "";
	}

	return 0;
}

static int set_GRETunnelInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;
			break;
		case VALUESET:
			// Store LowerLayers value under dmmap section
			dmuci_set_value_by_section(((struct dm_data *)data)->dmmap_section, "LowerLayers", reference.path);

			// Update tunlink option
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "tunlink", reference.value);
			break;
	}
	return 0;
}

static int get_GRETunnelInterface_UseChecksum(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *iface_section = ((struct dm_data *)data)->config_section;
	char *ocsum = NULL;

	dmuci_get_value_by_section_string(iface_section, "ocsum", &ocsum);
	if (ocsum) {
		if (!DM_STRCMP(ocsum, "1") || !DM_STRCMP(ocsum, "true"))
			*value = "1";
		else
			*value = "0";
	}

	return 0;
}

static int set_GRETunnelInterface_UseChecksum(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *iface_section = ((struct dm_data *)data)->config_section;
	bool b = true;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(iface_section, "ocsum", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_GRETunnelInterface_UseSequenceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *iface_section = ((struct dm_data *)data)->config_section;
	char *oseqno = NULL;

	dmuci_get_value_by_section_string(iface_section, "oseqno", &oseqno);
	if (oseqno) {
		if (!DM_STRCMP(oseqno, "1") || !DM_STRCMP(oseqno, "true"))
			*value = "1";
		else
			*value = "0";
	}

	return 0;
}

static int set_GRETunnelInterface_UseSequenceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *iface_section = ((struct dm_data *)data)->config_section;
	bool b = false;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(iface_section, "oseqno", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_GRETunnelInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(((struct dm_data *)data)->json_object, "tx_bytes");
	return 0;
}

static int get_GRETunnelInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(((struct dm_data *)data)->json_object, "rx_bytes");
	return 0;
}

static int get_GRETunnelInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(((struct dm_data *)data)->json_object, "tx_packets");
	return 0;
}

static int get_GRETunnelInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(((struct dm_data *)data)->json_object, "rx_packets");
	return 0;
}

static int get_GRETunnelInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(((struct dm_data *)data)->json_object, "tx_errors");
	return 0;
}

static int get_GRETunnelInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(((struct dm_data *)data)->json_object, "rx_errors");
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.GRE. *** */
DMOBJ tGREObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Tunnel", &DMWRITE, addObjGRETunnel, delObjGRETunnel, NULL, browseGRETunnelInst, NULL, NULL, tGRETunnelObj, tGRETunnelParams, NULL, BBFDM_BOTH, NULL},
//{"Filter", &DMWRITE, addObjGREFilter, delObjGREFilter, NULL, browseGREFilterInst, NULL, NULL, NULL, tGREFilterParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tGREParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version, version*/
{"TunnelNumberOfEntries", &DMREAD, DMT_UNINT, get_GRE_TunnelNumberOfEntries, NULL, BBFDM_BOTH},
//{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_GRE_FilterNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}. *** */
DMOBJ tGRETunnelObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGRETunnelStatsParams, NULL, BBFDM_BOTH, NULL},
{"Interface", &DMWRITE, addObjGRETunnelInterface, delObjGRETunnelInterface, NULL, browseGRETunnelInterfaceInst, NULL, NULL, tGRETunnelInterfaceObj, tGRETunnelInterfaceParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tGRETunnelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_GRETunnel_Enable, set_GRETunnel_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_GRETunnel_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_GRETunnel_Alias, set_GRETunnel_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"RemoteEndpoints", &DMWRITE, DMT_STRING, get_GRETunnel_RemoteEndpoints, set_GRETunnel_RemoteEndpoints, BBFDM_BOTH},
//{"KeepAlivePolicy", &DMWRITE, DMT_STRING, get_GRETunnel_KeepAlivePolicy, set_GRETunnel_KeepAlivePolicy, BBFDM_BOTH},
//{"KeepAliveTimeout", &DMWRITE, DMT_UNINT, get_GRETunnel_KeepAliveTimeout, set_GRETunnel_KeepAliveTimeout, BBFDM_BOTH},
//{"KeepAliveThreshold", &DMWRITE, DMT_UNINT, get_GRETunnel_KeepAliveThreshold, set_GRETunnel_KeepAliveThreshold, BBFDM_BOTH},
{"DeliveryHeaderProtocol", &DMWRITE, DMT_STRING, get_GRETunnel_DeliveryHeaderProtocol, set_GRETunnel_DeliveryHeaderProtocol, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_UNINT, get_GRETunnel_DefaultDSCPMark, set_GRETunnel_DefaultDSCPMark, BBFDM_BOTH},
{"ConnectedRemoteEndpoint", &DMREAD, DMT_STRING, get_GRETunnel_ConnectedRemoteEndpoint, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_GRETunnel_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/*
 * no tunnel stats because there is no separate device section for tunnel
 * and currently we only support only one interface per tunnel at a time
 */
/* *** Device.GRE.Tunnel.{i}.Stats. *** */
DMLEAF tGRETunnelStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"KeepAliveSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_KeepAliveSent, NULL, BBFDM_BOTH},
//{"KeepAliveReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_KeepAliveReceived, NULL, BBFDM_BOTH},
//{"BytesSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_BytesSent, NULL, BBFDM_BOTH},
//{"BytesReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_BytesReceived, NULL, BBFDM_BOTH},
//{"PacketsSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_PacketsSent, NULL, BBFDM_BOTH},
//{"PacketsReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_PacketsReceived, NULL, BBFDM_BOTH},
//{"ErrorsSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_ErrorsSent, NULL, BBFDM_BOTH},
//{"ErrorsReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_ErrorsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Interface.{i}. *** */
DMOBJ tGRETunnelInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGRETunnelInterfaceStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tGRETunnelInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_Enable, set_GRETunnelInterface_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_GRETunnelInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_GRETunnelInterface_Alias, set_GRETunnelInterface_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_GRETunnelInterface_Name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"LastChange", &DMREAD, DMT_UNINT, get_GRETunnelInterface_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_GRETunnelInterface_LowerLayers, set_GRETunnelInterface_LowerLayers, BBFDM_BOTH, DM_FLAG_REFERENCE},
//{"ProtocolIdOverride", &DMWRITE, DMT_UNINT, get_GRETunnelInterface_ProtocolIdOverride, set_GRETunnelInterface_ProtocolIdOverride, BBFDM_BOTH},
{"UseChecksum", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_UseChecksum, set_GRETunnelInterface_UseChecksum, BBFDM_BOTH},
//{"KeyIdentifierGenerationPolicy", &DMWRITE, DMT_STRING, get_GRETunnelInterface_KeyIdentifierGenerationPolicy, set_GRETunnelInterface_KeyIdentifierGenerationPolicy, BBFDM_BOTH},
//{"KeyIdentifier", &DMWRITE, DMT_UNINT, get_GRETunnelInterface_KeyIdentifier, set_GRETunnelInterface_KeyIdentifier, BBFDM_BOTH},
{"UseSequenceNumber", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_UseSequenceNumber, set_GRETunnelInterface_UseSequenceNumber, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Interface.{i}.Stats. *** */
DMLEAF tGRETunnelInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"DiscardChecksumReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_DiscardChecksumReceived, NULL, BBFDM_BOTH},
//{"DiscardSequenceNumberReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_DiscardSequenceNumberReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Filter.{i}. *** */
DMLEAF tGREFilterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_GREFilter_Enable, set_GREFilter_Enable, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_GREFilter_Status, NULL, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_GREFilter_Order, set_GREFilter_Order, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_GREFilter_Alias, set_GREFilter_Alias, BBFDM_BOTH},
//{"Interface", &DMWRITE, DMT_STRING, get_GREFilter_Interface, set_GREFilter_Interface, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_GREFilter_AllInterfaces, set_GREFilter_AllInterfaces, BBFDM_BOTH},
//{"VLANIDCheck", &DMWRITE, DMT_INT, get_GREFilter_VLANIDCheck, set_GREFilter_VLANIDCheck, BBFDM_BOTH},
//{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_GREFilter_VLANIDExclude, set_GREFilter_VLANIDExclude, BBFDM_BOTH},
//{"DSCPMarkPolicy", &DMWRITE, DMT_INT, get_GREFilter_DSCPMarkPolicy, set_GREFilter_DSCPMarkPolicy, BBFDM_BOTH},
{0}
};
