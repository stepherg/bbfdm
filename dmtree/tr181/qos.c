/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "qos.h"
#include "os.h"

/* *** Device.QoS. *** */
DMOBJ tQoSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Classification", &DMWRITE, os_addObjQoSClassification, os_delObjQoSClassification, NULL, os_browseQoSClassificationInst, NULL, NULL, tQoSClassificationParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"QueueStats", &DMWRITE, os_addObjQoSQueueStats, os_delObjQoSQueueStats, NULL, os_browseQoSQueueStatsInst, NULL, NULL, tQoSQueueStatsParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Queue", "Interface", NULL}},
//{"App", &DMWRITE, addObjQoSApp, delObjQoSApp, NULL, browseQoSAppInst, NULL, NULL, tQoSAppParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
//{"Flow", &DMWRITE, addObjQoSFlow, delObjQoSFlow, NULL, browseQoSFlowInst, NULL, NULL, tQoSFlowParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"Policer", &DMWRITE, os_addObjQoSPolicer, os_delObjQoSPolicer, NULL, os_browseQoSPolicerInst, NULL, NULL, tQoSPolicerParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"Queue", &DMWRITE, os_addObjQoSQueue, os_delObjQoSQueue, NULL, os_browseQoSQueueInst, NULL, NULL, tQoSQueueParams, os_get_linker_qos_queue, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"Shaper", &DMWRITE, os_addObjQoSShaper, os_delObjQoSShaper, NULL, os_browseQoSShaperInst, NULL, NULL, tQoSShaperParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", "Alias", NULL}},
{0}
};

DMLEAF tQoSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ClassificationNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_ClassificationNumberOfEntries, NULL, BBFDM_BOTH},
{"QueueStatsNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_QueueStatsNumberOfEntries, NULL, BBFDM_BOTH},
{"ShaperNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_ShaperNumberOfEntries, NULL, BBFDM_BOTH},
{"QueueNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_QueueNumberOfEntries, NULL, BBFDM_BOTH},
//{"MaxClassificationEntries", &DMREAD, DMT_UNINT, get_QoS_MaxClassificationEntries, NULL, BBFDM_BOTH},
//{"MaxAppEntries", &DMREAD, DMT_UNINT, get_QoS_MaxAppEntries, NULL, BBFDM_BOTH},
//{"AppNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_AppNumberOfEntries, NULL, BBFDM_BOTH},
//{"MaxFlowEntries", &DMREAD, DMT_UNINT, get_QoS_MaxFlowEntries, NULL, BBFDM_BOTH},
//{"FlowNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_FlowNumberOfEntries, NULL, BBFDM_BOTH},
//{"MaxPolicerEntries", &DMREAD, DMT_UNINT, get_QoS_MaxPolicerEntries, NULL, BBFDM_BOTH},
{"PolicerNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_PolicerNumberOfEntries, NULL, BBFDM_BOTH},
//{"MaxQueueEntries", &DMREAD, DMT_UNINT, get_QoS_MaxQueueEntries, NULL, BBFDM_BOTH},
//{"MaxShaperEntries", &DMREAD, DMT_UNINT, get_QoS_MaxShaperEntries, NULL, BBFDM_BOTH},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoS_DefaultForwardingPolicy, set_QoS_DefaultForwardingPolicy, BBFDM_BOTH},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoS_DefaultTrafficClass, set_QoS_DefaultTrafficClass, BBFDM_BOTH},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoS_DefaultPolicer, set_QoS_DefaultPolicer, BBFDM_BOTH},
//{"DefaultQueue", &DMWRITE, DMT_STRING, get_QoS_DefaultQueue, set_QoS_DefaultQueue, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoS_DefaultDSCPMark, set_QoS_DefaultDSCPMark, BBFDM_BOTH},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoS_DefaultEthernetPriorityMark, set_QoS_DefaultEthernetPriorityMark, BBFDM_BOTH},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoS_DefaultInnerEthernetPriorityMark, set_QoS_DefaultInnerEthernetPriorityMark, BBFDM_BOTH},
//{"AvailableAppList", &DMREAD, DMT_STRING, get_QoS_AvailableAppList, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Classification.{i}. *** */
DMLEAF tQoSClassificationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, os_get_QoSClassification_Enable, os_set_QoSClassification_Enable, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSClassification_Status, NULL, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_QoSClassification_Order, set_QoSClassification_Order, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSClassification_Alias, os_set_QoSClassification_Alias, BBFDM_BOTH},
//{"DHCPType", &DMWRITE, DMT_STRING, get_QoSClassification_DHCPType, set_QoSClassification_DHCPType, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSClassification_Interface, os_set_QoSClassification_Interface, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_QoSClassification_AllInterfaces, set_QoSClassification_AllInterfaces, BBFDM_BOTH},
{"DestIP", &DMWRITE, DMT_STRING, os_get_QoSClassification_DestIP, os_set_QoSClassification_DestIP, BBFDM_BOTH},
{"DestMask", &DMWRITE, DMT_STRING, os_get_QoSClassification_DestMask, os_set_QoSClassification_DestMask, BBFDM_BOTH},
//{"DestIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestIPExclude, set_QoSClassification_DestIPExclude, BBFDM_BOTH},
{"SourceIP", &DMWRITE, DMT_STRING, os_get_QoSClassification_SourceIP, os_set_QoSClassification_SourceIP, BBFDM_BOTH},
{"SourceMask", &DMWRITE, DMT_STRING, os_get_QoSClassification_SourceMask, os_set_QoSClassification_SourceMask, BBFDM_BOTH},
//{"SourceIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceIPExclude, set_QoSClassification_SourceIPExclude, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_INT, os_get_QoSClassification_Protocol, os_set_QoSClassification_Protocol, BBFDM_BOTH},
//{"ProtocolExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_ProtocolExclude, set_QoSClassification_ProtocolExclude, BBFDM_BOTH},
{"DestPort", &DMWRITE, DMT_INT, os_get_QoSClassification_DestPort, os_set_QoSClassification_DestPort, BBFDM_BOTH},
{"DestPortRangeMax", &DMWRITE, DMT_INT, os_get_QoSClassification_DestPortRangeMax, os_set_QoSClassification_DestPortRangeMax, BBFDM_BOTH},
//{"DestPortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestPortExclude, set_QoSClassification_DestPortExclude, BBFDM_BOTH},
{"SourcePort", &DMWRITE, DMT_INT, os_get_QoSClassification_SourcePort, os_set_QoSClassification_SourcePort, BBFDM_BOTH},
{"SourcePortRangeMax", &DMWRITE, DMT_INT, os_get_QoSClassification_SourcePortRangeMax, os_set_QoSClassification_SourcePortRangeMax, BBFDM_BOTH},
//{"SourcePortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourcePortExclude, set_QoSClassification_SourcePortExclude, BBFDM_BOTH},
{"SourceMACAddress", &DMWRITE, DMT_STRING, os_get_QoSClassification_SourceMACAddress, os_set_QoSClassification_SourceMACAddress, BBFDM_BOTH},
//{"SourceMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACMask, set_QoSClassification_SourceMACMask, BBFDM_BOTH},
//{"SourceMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceMACExclude, set_QoSClassification_SourceMACExclude, BBFDM_BOTH},
{"DestMACAddress", &DMWRITE, DMT_STRING, os_get_QoSClassification_DestMACAddress, os_set_QoSClassification_DestMACAddress, BBFDM_BOTH},
//{"DestMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACMask, set_QoSClassification_DestMACMask, BBFDM_BOTH},
//{"DestMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestMACExclude, set_QoSClassification_DestMACExclude, BBFDM_BOTH},
{"Ethertype", &DMWRITE, DMT_INT, os_get_QoSClassification_Ethertype, os_set_QoSClassification_Ethertype, BBFDM_BOTH},
//{"EthertypeExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthertypeExclude, set_QoSClassification_EthertypeExclude, BBFDM_BOTH},
//{"SSAP", &DMWRITE, DMT_INT, get_QoSClassification_SSAP, set_QoSClassification_SSAP, BBFDM_BOTH},
//{"SSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SSAPExclude, set_QoSClassification_SSAPExclude, BBFDM_BOTH},
//{"DSAP", &DMWRITE, DMT_INT, get_QoSClassification_DSAP, set_QoSClassification_DSAP, BBFDM_BOTH},
//{"DSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSAPExclude, set_QoSClassification_DSAPExclude, BBFDM_BOTH},
//{"LLCControl", &DMWRITE, DMT_INT, get_QoSClassification_LLCControl, set_QoSClassification_LLCControl, BBFDM_BOTH},
//{"LLCControlExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_LLCControlExclude, set_QoSClassification_LLCControlExclude, BBFDM_BOTH},
//{"SNAPOUI", &DMWRITE, DMT_INT, get_QoSClassification_SNAPOUI, set_QoSClassification_SNAPOUI, BBFDM_BOTH},
//{"SNAPOUIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SNAPOUIExclude, set_QoSClassification_SNAPOUIExclude, BBFDM_BOTH},
{"SourceVendorClassID", &DMWRITE, DMT_STRING, os_get_QoSClassification_SourceVendorClassID, os_set_QoSClassification_SourceVendorClassID, BBFDM_BOTH},
//{"SourceVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorClassIDv6, set_QoSClassification_SourceVendorClassIDv6, BBFDM_BOTH},
//{"SourceVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorClassIDExclude, set_QoSClassification_SourceVendorClassIDExclude, BBFDM_BOTH},
//{"SourceVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassIDMode, set_QoSClassification_SourceVendorClassIDMode, BBFDM_BOTH},
{"DestVendorClassID", &DMWRITE, DMT_STRING, os_get_QoSClassification_DestVendorClassID, os_set_QoSClassification_DestVendorClassID, BBFDM_BOTH},
//{"DestVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorClassIDv6, set_QoSClassification_DestVendorClassIDv6, BBFDM_BOTH},
//{"DestVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorClassIDExclude, set_QoSClassification_DestVendorClassIDExclude, BBFDM_BOTH},
//{"DestVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassIDMode, set_QoSClassification_DestVendorClassIDMode, BBFDM_BOTH},
{"SourceClientID", &DMWRITE, DMT_HEXBIN, os_get_QoSClassification_SourceClientID, os_set_QoSClassification_SourceClientID, BBFDM_BOTH},
//{"SourceClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceClientIDExclude, set_QoSClassification_SourceClientIDExclude, BBFDM_BOTH},
{"DestClientID", &DMWRITE, DMT_HEXBIN, os_get_QoSClassification_DestClientID, os_set_QoSClassification_DestClientID, BBFDM_BOTH},
//{"DestClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestClientIDExclude, set_QoSClassification_DestClientIDExclude, BBFDM_BOTH},
{"SourceUserClassID", &DMWRITE, DMT_HEXBIN, os_get_QoSClassification_SourceUserClassID, os_set_QoSClassification_SourceUserClassID, BBFDM_BOTH},
//{"SourceUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceUserClassIDExclude, set_QoSClassification_SourceUserClassIDExclude, BBFDM_BOTH},
{"DestUserClassID", &DMWRITE, DMT_HEXBIN, os_get_QoSClassification_DestUserClassID, os_set_QoSClassification_DestUserClassID, BBFDM_BOTH},
//{"DestUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestUserClassIDExclude, set_QoSClassification_DestUserClassIDExclude, BBFDM_BOTH},
//{"SourceVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorSpecificInfo, set_QoSClassification_SourceVendorSpecificInfo, BBFDM_BOTH},
//{"SourceVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorSpecificInfoExclude, set_QoSClassification_SourceVendorSpecificInfoExclude, BBFDM_BOTH},
//{"SourceVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_SourceVendorSpecificInfoEnterprise, set_QoSClassification_SourceVendorSpecificInfoEnterprise, BBFDM_BOTH},
//{"SourceVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_SourceVendorSpecificInfoSubOption, set_QoSClassification_SourceVendorSpecificInfoSubOption, BBFDM_BOTH},
//{"DestVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorSpecificInfo, set_QoSClassification_DestVendorSpecificInfo, BBFDM_BOTH},
//{"DestVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorSpecificInfoExclude, set_QoSClassification_DestVendorSpecificInfoExclude, BBFDM_BOTH},
//{"DestVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_DestVendorSpecificInfoEnterprise, set_QoSClassification_DestVendorSpecificInfoEnterprise, BBFDM_BOTH},
//{"DestVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_DestVendorSpecificInfoSubOption, set_QoSClassification_DestVendorSpecificInfoSubOption, BBFDM_BOTH},
//{"TCPACK", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACK, set_QoSClassification_TCPACK, BBFDM_BOTH},
//{"TCPACKExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACKExclude, set_QoSClassification_TCPACKExclude, BBFDM_BOTH},
{"IPLengthMin", &DMWRITE, DMT_UNINT, os_get_QoSClassification_IPLengthMin, os_set_QoSClassification_IPLengthMin, BBFDM_BOTH},
{"IPLengthMax", &DMWRITE, DMT_UNINT, os_get_QoSClassification_IPLengthMax, os_set_QoSClassification_IPLengthMax, BBFDM_BOTH},
//{"IPLengthExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_IPLengthExclude, set_QoSClassification_IPLengthExclude, BBFDM_BOTH},
{"DSCPCheck", &DMWRITE, DMT_INT, os_get_QoSClassification_DSCPCheck, os_set_QoSClassification_DSCPCheck, BBFDM_BOTH},
//{"DSCPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSCPExclude, set_QoSClassification_DSCPExclude, BBFDM_BOTH},
{"DSCPMark", &DMWRITE, DMT_INT, os_get_QoSClassification_DSCPMark, os_set_QoSClassification_DSCPMark, BBFDM_BOTH},
{"EthernetPriorityCheck", &DMWRITE, DMT_INT, os_get_QoSClassification_EthernetPriorityCheck, os_set_QoSClassification_EthernetPriorityCheck, BBFDM_BOTH},
//{"EthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetPriorityExclude, set_QoSClassification_EthernetPriorityExclude, BBFDM_BOTH},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityMark, set_QoSClassification_EthernetPriorityMark, BBFDM_BOTH},
//{"InnerEthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityCheck, set_QoSClassification_InnerEthernetPriorityCheck, BBFDM_BOTH},
//{"InnerEthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_InnerEthernetPriorityExclude, set_QoSClassification_InnerEthernetPriorityExclude, BBFDM_BOTH},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityMark, set_QoSClassification_InnerEthernetPriorityMark, BBFDM_BOTH},
//{"EthernetDEICheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetDEICheck, set_QoSClassification_EthernetDEICheck, BBFDM_BOTH},
//{"EthernetDEIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetDEIExclude, set_QoSClassification_EthernetDEIExclude, BBFDM_BOTH},
{"VLANIDCheck", &DMWRITE, DMT_INT, os_get_QoSClassification_VLANIDCheck, os_set_QoSClassification_VLANIDCheck, BBFDM_BOTH},
//{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_VLANIDExclude, set_QoSClassification_VLANIDExclude, BBFDM_BOTH},
//{"OutOfBandInfo", &DMWRITE, DMT_INT, get_QoSClassification_OutOfBandInfo, set_QoSClassification_OutOfBandInfo, BBFDM_BOTH},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSClassification_ForwardingPolicy, set_QoSClassification_ForwardingPolicy, BBFDM_BOTH},
{"TrafficClass", &DMWRITE, DMT_INT, os_get_QoSClassification_TrafficClass, os_set_QoSClassification_TrafficClass, BBFDM_BOTH},
{"Policer", &DMWRITE, DMT_STRING, os_get_QoSClassification_Policer, os_set_QoSClassification_Policer, BBFDM_BOTH},
//{"App", &DMWRITE, DMT_STRING, get_QoSClassification_App, set_QoSClassification_App, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.App.{i}. *** */
DMLEAF tQoSAppParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSApp_Enable, set_QoSApp_Enable, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSApp_Status, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSApp_Alias, set_QoSApp_Alias, BBFDM_BOTH},
//{"ProtocolIdentifier", &DMWRITE, DMT_STRING, get_QoSApp_ProtocolIdentifier, set_QoSApp_ProtocolIdentifier, BBFDM_BOTH},
//{"Name", &DMWRITE, DMT_STRING, get_QoSApp_Name, set_QoSApp_Name, BBFDM_BOTH},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultForwardingPolicy, set_QoSApp_DefaultForwardingPolicy, BBFDM_BOTH},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultTrafficClass, set_QoSApp_DefaultTrafficClass, BBFDM_BOTH},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoSApp_DefaultPolicer, set_QoSApp_DefaultPolicer, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultDSCPMark, set_QoSApp_DefaultDSCPMark, BBFDM_BOTH},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultEthernetPriorityMark, set_QoSApp_DefaultEthernetPriorityMark, BBFDM_BOTH},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultInnerEthernetPriorityMark, set_QoSApp_DefaultInnerEthernetPriorityMark, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Flow.{i}. *** */
DMLEAF tQoSFlowParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSFlow_Enable, set_QoSFlow_Enable, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSFlow_Status, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSFlow_Alias, set_QoSFlow_Alias, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_QoSFlow_Type, set_QoSFlow_Type, BBFDM_BOTH},
//{"TypeParameters", &DMWRITE, DMT_STRING, get_QoSFlow_TypeParameters, set_QoSFlow_TypeParameters, BBFDM_BOTH},
//{"Name", &DMWRITE, DMT_STRING, get_QoSFlow_Name, set_QoSFlow_Name, BBFDM_BOTH},
//{"App", &DMWRITE, DMT_STRING, get_QoSFlow_App, set_QoSFlow_App, BBFDM_BOTH},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSFlow_ForwardingPolicy, set_QoSFlow_ForwardingPolicy, BBFDM_BOTH},
//{"TrafficClass", &DMWRITE, DMT_UNINT, get_QoSFlow_TrafficClass, set_QoSFlow_TrafficClass, BBFDM_BOTH},
//{"Policer", &DMWRITE, DMT_STRING, get_QoSFlow_Policer, set_QoSFlow_Policer, BBFDM_BOTH},
//{"DSCPMark", &DMWRITE, DMT_INT, get_QoSFlow_DSCPMark, set_QoSFlow_DSCPMark, BBFDM_BOTH},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_EthernetPriorityMark, set_QoSFlow_EthernetPriorityMark, BBFDM_BOTH},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_InnerEthernetPriorityMark, set_QoSFlow_InnerEthernetPriorityMark, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Policer.{i}. *** */
DMLEAF tQoSPolicerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, os_get_QoSPolicer_Enable, os_set_QoSPolicer_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_QoSPolicer_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSPolicer_Alias, os_set_QoSPolicer_Alias, BBFDM_BOTH},
{"CommittedRate", &DMWRITE, DMT_UNINT, os_get_QoSPolicer_CommittedRate, os_set_QoSPolicer_CommittedRate, BBFDM_BOTH},
{"CommittedBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSPolicer_CommittedBurstSize, os_set_QoSPolicer_CommittedBurstSize, BBFDM_BOTH},
{"ExcessBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSPolicer_ExcessBurstSize, os_set_QoSPolicer_ExcessBurstSize, BBFDM_BOTH},
{"PeakRate", &DMWRITE, DMT_UNINT, os_get_QoSPolicer_PeakRate, os_set_QoSPolicer_PeakRate, BBFDM_BOTH},
{"PeakBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSPolicer_PeakBurstSize, os_set_QoSPolicer_PeakBurstSize, BBFDM_BOTH},
{"MeterType", &DMWRITE, DMT_STRING, os_get_QoSPolicer_MeterType, os_set_QoSPolicer_MeterType, BBFDM_BOTH},
{"PossibleMeterTypes", &DMREAD, DMT_STRING, os_get_QoSPolicer_PossibleMeterTypes, NULL, BBFDM_BOTH},
//{"ConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_ConformingAction, set_QoSPolicer_ConformingAction, BBFDM_BOTH},
//{"PartialConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_PartialConformingAction, set_QoSPolicer_PartialConformingAction, BBFDM_BOTH},
//{"NonConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_NonConformingAction, set_QoSPolicer_NonConformingAction, BBFDM_BOTH},
//{"TotalCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedPackets, NULL, BBFDM_BOTH},
//{"TotalCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedBytes, NULL, BBFDM_BOTH},
//{"ConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedPackets, NULL, BBFDM_BOTH},
//{"ConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedBytes, NULL, BBFDM_BOTH},
//{"PartiallyConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedPackets, NULL, BBFDM_BOTH},
//{"PartiallyConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedBytes, NULL, BBFDM_BOTH},
//{"NonConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedPackets, NULL, BBFDM_BOTH},
//{"NonConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedBytes, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Queue.{i}. *** */
DMLEAF tQoSQueueParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, os_get_QoSQueue_Enable, os_set_QoSQueue_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_QoSQueue_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSQueue_Alias, os_set_QoSQueue_Alias, BBFDM_BOTH},
{"TrafficClasses", &DMWRITE, DMT_STRING, os_get_QoSQueue_TrafficClasses, os_set_QoSQueue_TrafficClasses, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSQueue_Interface, os_set_QoSQueue_Interface, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, os_get_QoSQueue_AllInterfaces, os_set_QoSQueue_AllInterfaces, BBFDM_BOTH},
//{"HardwareAssisted", &DMREAD, DMT_BOOL, os_get_QoSQueue_HardwareAssisted, NULL, BBFDM_BOTH},
//{"BufferLength", &DMREAD, DMT_UNINT, os_get_QoSQueue_BufferLength, NULL, BBFDM_BOTH},
{"Weight", &DMWRITE, DMT_UNINT, os_get_QoSQueue_Weight, os_set_QoSQueue_Weight, BBFDM_BOTH},
{"Precedence", &DMWRITE, DMT_UNINT, os_get_QoSQueue_Precedence, os_set_QoSQueue_Precedence, BBFDM_BOTH},
//{"REDThreshold", &DMWRITE, DMT_UNINT, os_get_QoSQueue_REDThreshold, os_set_QoSQueue_REDThreshold, BBFDM_BOTH},
//{"REDPercentage", &DMWRITE, DMT_UNINT, os_get_QoSQueue_REDPercentage, os_set_QoSQueue_REDPercentage, BBFDM_BOTH},
//{"DropAlgorithm", &DMWRITE, DMT_STRING, os_get_QoSQueue_DropAlgorithm, os_set_QoSQueue_DropAlgorithm, BBFDM_BOTH},
{"SchedulerAlgorithm", &DMWRITE, DMT_STRING, os_get_QoSQueue_SchedulerAlgorithm, os_set_QoSQueue_SchedulerAlgorithm, BBFDM_BOTH},
{"ShapingRate", &DMWRITE, DMT_INT, os_get_QoSQueue_ShapingRate, os_set_QoSQueue_ShapingRate, BBFDM_BOTH},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSQueue_ShapingBurstSize, os_set_QoSQueue_ShapingBurstSize, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.QueueStats.{i}. *** */
DMLEAF tQoSQueueStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSQueueStats_Enable, set_QoSQueueStats_Enable, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSQueueStats_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSQueueStats_Alias, os_set_QoSQueueStats_Alias, BBFDM_BOTH},
//{"Queue", &DMWRITE, DMT_STRING, get_QoSQueueStats_Queue, set_QoSQueueStats_Queue, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSQueueStats_Interface, os_set_QoSQueueStats_Interface, BBFDM_BOTH},
{"OutputPackets", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_OutputPackets, NULL, BBFDM_BOTH},
{"OutputBytes", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_OutputBytes, NULL, BBFDM_BOTH},
{"DroppedPackets", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_DroppedPackets, NULL, BBFDM_BOTH},
{"DroppedBytes", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_DroppedBytes, NULL, BBFDM_BOTH},
{"QueueOccupancyPackets", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_QueueOccupancyPackets, NULL, BBFDM_BOTH},
//{"QueueOccupancyPercentage", &DMREAD, DMT_UNINT, get_QoSQueueStats_QueueOccupancyPercentage, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Shaper.{i}. *** */
DMLEAF tQoSShaperParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, os_get_QoSShaper_Enable, os_set_QoSShaper_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_QoSShaper_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSShaper_Alias, os_set_QoSShaper_Alias, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSShaper_Interface, os_set_QoSShaper_Interface, BBFDM_BOTH},
{"ShapingRate", &DMWRITE, DMT_INT, os_get_QoSShaper_ShapingRate, os_set_QoSShaper_ShapingRate, BBFDM_BOTH},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSShaper_ShapingBurstSize, os_set_QoSShaper_ShapingBurstSize, BBFDM_BOTH},
{0}
};
