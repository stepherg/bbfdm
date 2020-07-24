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

#ifndef __SE_IGMP_H
#define __SE_IGMP_H

#include <libbbf_api/dmcommon.h>

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

extern void synchronize_specific_config_sections_with_dmmap_mcast_iface(char *package, char *section_type,
                                       void *data, char *dmmap_package, char *dmmap_sec, char *proto,
                                       struct list_head *dup_list);

extern int get_mcast_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcast_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcast_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

extern int get_mcastp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcastp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcastp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcastp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcastp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcastp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcastp_iface_snoop_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcastp_iface_snoop_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcastp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcastp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int del_mcastp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
extern int get_mcastp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int get_mcastp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int get_mcastp_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int get_mcastp_interface_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

extern int get_mcasts_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcasts_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcasts_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int set_mcasts_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
extern int get_mcasts_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
extern int del_mcasts_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

extern void update_snooping_mode(struct uci_section *s);
#endif
