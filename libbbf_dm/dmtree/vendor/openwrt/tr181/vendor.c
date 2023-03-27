/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "deviceinfo.h"
#include "qos.h"
#include "vendor.h"

DM_MAP_OBJ tVendorExtensionOverwriteOPENWRT[] = {
/* parentobj, nextobject, parameter */
{"Device.DeviceInfo.", tOPENWRT_DeviceInfoObj, tOPENWRT_DeviceInfoParams},
{"Device.QoS.", tOPENWRT_QoSObj, tOPENWRT_QoSParams},
{0}
};

char *VendorExtensionExcludeOPENWRT[] = {
	"Device.Hosts.", //Object
	"Device.WiFi.Radio.{i}.Stats.", //Object
	"Device.WiFi.SSID.{i}.Stats.", //Object
	"Device.WiFi.AccessPoint.{i}.AssociatedDevice.", //Object
	"Device.WiFi.NeighboringWiFiDiagnostic.", //Object
	"Device.WiFi.DataElements.Network.", //Object
	"Device.DeviceInfo.MemoryStatus.", //Object
	"Device.QoS.Policer.{i}.", //Object
	"Device.QoS.Queue.{i}.", //Object
	"Device.QoS.Shaper.{i}.", //Object

	"Device.Ethernet.Interface.{i}.Stats.MulticastPacketsSent", //Parameter
	"Device.Ethernet.Interface.{i}.Stats.UnicastPacketsSent", //Parameter
	"Device.Ethernet.Interface.{i}.Stats.UnicastPacketsReceived", //Parameter
	"Device.Ethernet.Interface.{i}.Stats.BroadcastPacketsSent", //Parameter
	"Device.Ethernet.Interface.{i}.Stats.BroadcastPacketsReceived", //Parameter
	"Device.Ethernet.Interface.{i}.Stats.UnknownProtoPacketsReceived", //Parameter
	"Device.Ethernet.Link.{i}.Stats.MulticastPacketsSent", //Parameter
	"Device.Ethernet.Link.{i}.Stats.UnicastPacketsSent", //Parameter
	"Device.Ethernet.Link.{i}.Stats.UnicastPacketsReceived", //Parameter
	"Device.Ethernet.Link.{i}.Stats.BroadcastPacketsSent", //Parameter
	"Device.Ethernet.Link.{i}.Stats.BroadcastPacketsReceived", //Parameter
	"Device.Ethernet.Link.{i}.Stats.UnknownProtoPacketsReceived", //Parameter
	"Device.Firewall.Chain.{i}.Rule.{i}.ExpiryDate", //Parameter
	"Device.NAT.PortMapping.{i}.LeaseDuration", //Parameter
	"Device.WiFi.Radio.{i}.MaxBitRate", //Parameter
	"Device.WiFi.Radio.{i}.OperatingFrequencyBand", //Parameter
	"Device.WiFi.Radio.{i}.SupportedFrequencyBands", //Parameter
	"Device.WiFi.Radio.{i}.SupportedStandards", //Parameter
	"Device.WiFi.Radio.{i}.OperatingStandards", //Parameter
	"Device.WiFi.Radio.{i}.ChannelsInUse", //Parameter
	"Device.WiFi.Radio.{i}.Channel", //Parameter
	"Device.WiFi.Radio.{i}.PossibleChannels", //Parameter
	"Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths", //Parameter
	"Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth", //Parameter
	"Device.WiFi.SSID.{i}.BSSID", //Parameter
	"Device.WiFi.AccessPoint.{i}.Status", //Parameter
	"Device.WiFi.AccessPoint.{i}.AssociatedDeviceNumberOfEntries", //Parameter
	"Device.QoS.ShaperNumberOfEntries", //Parameter
	"Device.QoS.QueueNumberOfEntries", //Parameter
	"Device.QoS.PolicerNumberOfEntries", //Parameter
	"Device.QoS.QueueStats.{i}.Enable", //Parameter
	"Device.QoS.QueueStats.{i}.Status", //Parameter
	"Device.QoS.QueueStats.{i}.Queue", //Parameter
	"Device.QoS.QueueStats.{i}.DroppedBytes", //Parameter
	"Device.QoS.Classification.{i}.Enable", //Parameter
	"Device.QoS.Classification.{i}.DestMask", //Parameter
	"Device.QoS.Classification.{i}.SourceMask", //Parameter
	"Device.QoS.Classification.{i}.SourcePortRangeMax", //Parameter
	"Device.QoS.Classification.{i}.SourceMACAddress", //Parameter
	"Device.QoS.Classification.{i}.DestMACAddress", //Parameter
	"Device.QoS.Classification.{i}.Ethertype", //Parameter
	"Device.QoS.Classification.{i}.SourceVendorClassID", //Parameter
	"Device.QoS.Classification.{i}.DestVendorClassID", //Parameter
	"Device.QoS.Classification.{i}.SourceClientID", //Parameter
	"Device.QoS.Classification.{i}.DestClientID", //Parameter
	"Device.QoS.Classification.{i}.SourceUserClassID", //Parameter
	"Device.QoS.Classification.{i}.DestUserClassID", //Parameter
	"Device.QoS.Classification.{i}.IPLengthMin", //Parameter
	"Device.QoS.Classification.{i}.IPLengthMax", //Parameter
	"Device.QoS.Classification.{i}.DSCPCheck", //Parameter
	"Device.QoS.Classification.{i}.EthernetPriorityCheck", //Parameter
	"Device.QoS.Classification.{i}.VLANIDCheck", //Parameter
	"Device.QoS.Classification.{i}.TrafficClass", //Parameter
	"Device.QoS.Classification.{i}.Policer", //Parameter
	NULL
};
