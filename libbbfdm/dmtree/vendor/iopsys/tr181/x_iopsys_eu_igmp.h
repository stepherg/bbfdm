/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Rahul Thakur <rahul.thakur@iopsys.eu>
 *
 */ 

#ifndef __IOPSYS_IGMP_H
#define __IOPSYS_IGMP_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ X_IOPSYS_EU_IGMPObj[];
extern DMLEAF X_IOPSYS_EU_IGMPParams[];

extern DMOBJ X_IOPSYS_EU_IGMPSnoopingObj[];
extern DMLEAF X_IOPSYS_EU_IGMPSnoopingParams[];
extern DMOBJ IGMPSnoopingCLientGroupObj[];
extern DMLEAF IGMPSnoopingClientGroupParams[];
extern DMLEAF IGMPSnoopingClientGroupStatsParams[];
extern DMLEAF IGMPSnoopingClientGroupAssociatedDeviceParams[];
extern DMLEAF IGMPSnoopingFilterParams[];

extern DMOBJ X_IOPSYS_EU_IGMPProxyObj[];
extern DMLEAF X_IOPSYS_EU_IGMPProxyParams[];
extern DMLEAF IGMPProxyInterfaceParams[];
extern DMOBJ IGMPProxyCLientGroupObj[];
extern DMLEAF IGMPProxyClientGroupParams[];
extern DMLEAF IGMPProxyClientGroupStatsParams[];
extern DMLEAF IGMPProxyClientGroupAssociatedDeviceParams[];
extern DMLEAF IGMPProxyFilterParams[];

int get_mcast_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcast_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcast_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcasts_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcasts_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcasts_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcasts_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_mcastp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcastp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcastp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcastp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcastp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcastp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcastp_iface_snoop_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcastp_iface_snoop_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcastp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcastp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int del_mcastp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int get_mcastp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_mcastp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_mcastp_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_mcastp_interface_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int get_mcasts_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcasts_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcasts_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_mcasts_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_mcasts_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int del_mcasts_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

void update_snooping_mode(struct uci_section *s);
int get_mcast_snooping_interface_val(struct dmctx *ctx, char *value, char *ifname, size_t s_ifname);
int del_proxy_obj(void *data, char *proto, unsigned char del_action);
void del_dmmap_sec_with_opt_eq(char *dmmap_file, char *section, char *option, char *value);
void sync_dmmap_bool_to_uci_list(struct uci_section *s, char *section, char *value, bool b);
int del_snooping_obj(void *data, char *proto, unsigned char del_action);
int browse_proxy_interface_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *proto);
int browse_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *section_type,
		char *option_name, char *option_value);
void synchronize_specific_config_sections_with_dmmap_mcast_iface(char *package, char *section_type,
		void *data, char *dmmap_package, char *dmmap_sec, char *proto,
		struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_mcast_filter(char *package, char *section_type,
		void *data, char *dmmap_package, char *dmmap_sec, char *proto,
		struct list_head *dup_list);

#endif //__IOPSYS_IGMP_H
