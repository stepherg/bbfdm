/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Saurabh Verma <saurabh.verma@iopsys.eu>
 *
 */

#include "dmentry.h"
#include "wifi-dataelements.h"

/**************************************************************************
 * SET AND GET ALIAS
 ***************************************************************************/
/*#Device.WiFi.DataElements.Network.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ID*/
static int get_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "ID");
	}
	return 0;
}

static int set_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.TimeStamp!UBUS:wifi.dataelements.collector/dump//description*/
static int get_WiFiDataElementsNetwork_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "TimeStamp");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.ControllerID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ControllerID*/
static int get_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "ControllerID");
	}
	return 0;
}

static int set_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.DeviceNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[@i-1].wfa-dataelements:Network.NumberOfDevices*/
static int get_WiFiDataElementsNetwork_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "NumberOfDevices");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDevice_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ID");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_MultiAPCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].CollectionInterval*/
static int get_WiFiDataElementsNetworkDevice_CollectionInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CollectionInterval");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].NumberOfRadios*/
static int get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfRadios");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDeviceRadio_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadio_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadio_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadio_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Transmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Transmit*/
static int get_WiFiDataElementsNetworkDeviceRadio_Transmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Transmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveSelf!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ReceiveSelf*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ReceiveSelf");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveOther!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].RecieveOther*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "RecieveOther");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfCurrOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfCurrOpClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfUnassocSta*/
static int get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfUnassocSta");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfBSS*/
static int get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfBSS");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfScanRes*/
static int get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int num_scanres = 0;
	json_object *scanres_arr = NULL;

	json_object_object_get_ex((json_object *)data, "ScanResultList", &scanres_arr);
	if (scanres_arr)
		num_scanres = json_object_array_length(scanres_arr);

	dmasprintf(value, "%d", num_scanres);
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BackhaulSta.MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *backsta_obj = NULL;

	if (data) {
		json_object_object_get_ex((json_object *)data, "BackhaulSta", &backsta_obj);
		if (backsta_obj)
			*value = dmjson_get_value(backsta_obj, 1, "MACAddress");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "HTCapabilities");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "VHTCapabilities");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "HECapabilities");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.NumberOfOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "NumberOfOpClass");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].Class*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.MaxTxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].MaxTxPower*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MaxTxPower");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NonOperable!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NonOperable*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NonOperable");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NumberOfNonOperChan!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NumberOfNonOperChan*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfNonOperChan");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Class*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Channel*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TxPower*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TxPower");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.LastChange!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].LastChange*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastChange");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBE!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBE*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBE");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBK!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBK*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBK");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersVI!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersVI*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVI");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersVO!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersVO*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVO");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberofSTA*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberofSTA");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "VHTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "HECapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataDownlinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataDownlinkRate*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastDataDownlinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataUplinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataUplinkRate*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastDataUplinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationReceive!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationReceive*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UtilizationReceive");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationTransmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationTransmit*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UtilizationTransmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateDownlink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateDownlink*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstMACDataRateDownlink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateUplink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateUplink*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstMACDataRateUplink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].SignalStrength*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastConnectTime!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastConnectTime*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastConnectTime");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "PacketsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "PacketsReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ErrorsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MeasurementReport!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Measurementreport*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Measurementreport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.NumberOfMeasureReports!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberOfMeasureReports*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfMeasureReports");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Hostname*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Hostname");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].NumberOfOpClassScans*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfOpClassScans");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.OperatingClass!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].OperatingClass*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OperatingClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].NumberOfChannelScans*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfChannelScans");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Channel*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NumberofNeighbors*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberofNeighbors");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SignalStrengh*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrengh");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelBandwidth!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelBandwidth*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ChannelBandwidth");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelUtilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelUtilization*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ChannelUtilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.StationCount!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].StationCount*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "StationCount");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].SignalStrength*/
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}

static int get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*************************************************************
 * ENTRY METHOD
 **************************************************************/
static int browseWiFiDataElementsNetworkDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int i, j, id = 0;
	char *inst = NULL, *max_inst = NULL;
	json_object *res = NULL, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;
	json_object *dev_arr = NULL, *dev_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
			json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
			dmjson_foreach_obj_in_array(net_obj, dev_arr, dev_obj, j, 1, "DeviceList") {
				inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dev_obj, inst) == DM_STOP)
					break;
			}
		}
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *radio_arr = NULL, *radio_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, radio_arr, radio_obj, i, 1, "RadioList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)radio_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, opclass_arr, opclass_obj, i, 1, "CurrentOperatingClasses") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *bss_arr = NULL, *bss_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, bss_arr, bss_obj, i, 1, "BSSList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bss_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *scanres_arr = NULL, *scanres_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, scanres_arr, scanres_obj, i, 1, "ScanResultList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)scanres_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *unassoc_arr = NULL, *unassoc_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, unassoc_arr, unassoc_obj, i, 1, "UnassociatedStaList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)unassoc_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *caps_obj = NULL, *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	json_object_object_get_ex((json_object *)prev_data, "Capabilites", &caps_obj);
	if (caps_obj) {
		dmjson_foreach_obj_in_array(caps_obj, opclass_arr, opclass_obj, i, 1, "OperatingClasses") {
			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *sta_arr = NULL, *sta_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, sta_arr, sta_obj, i, 1, "STAList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)sta_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_scan_arr = NULL, *opclass_scan_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, opclass_scan_arr, opclass_scan_obj, i, 1, "OpClassScanList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_scan_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *chscan_arr = NULL, *chscan_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, chscan_arr, chscan_obj, i, 1, "ChannelScanList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)chscan_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *neigh_arr = NULL, *neigh_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, neigh_arr, neigh_obj, i, 1, "NeighborList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)neigh_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsAssociationEventAssociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

static int browseWiFiDataElementsDisassociationEventDisassociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

/* *** Device.WiFi.DataElements. *** */
DMOBJ tWiFiDataElementsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Network", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkObj, tWiFiDataElementsNetworkParams, NULL, BBFDM_BOTH},
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventObj, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventObj, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network. *** */
DMOBJ tWiFiDataElementsNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Device", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceObj, tWiFiDataElementsNetworkDeviceParams, NULL, BBFDM_BOTH, (const char *[]){"ID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ID", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetwork_ID, set_WiFiDataElementsNetwork_ID, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{"ControllerID", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetwork_ControllerID, set_WiFiDataElementsNetwork_ControllerID, NULL, NULL, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetwork_DeviceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Radio", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioObj, tWiFiDataElementsNetworkDeviceRadioParams, NULL, BBFDM_BOTH, (const char *[]){"ID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ID, NULL, NULL, NULL, BBFDM_BOTH},
{"MultiAPCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_MultiAPCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"CollectionInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_CollectionInterval, NULL, NULL, NULL, BBFDM_BOTH},
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"BackhaulSta", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams, NULL, BBFDM_BOTH},
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj, tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, (const char *[]){"Class", NULL}},
{"BSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSObj, tWiFiDataElementsNetworkDeviceRadioBSSParams, NULL, BBFDM_BOTH, (const char *[]){"BSSID", NULL}},
{"ScanResult", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultObj, tWiFiDataElementsNetworkDeviceRadioScanResultParams, NULL, BBFDM_BOTH},
{"UnassociatedSTA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams, NULL, BBFDM_BOTH, (const char *[]){"MACAddress", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadio_ID, NULL, NULL, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_Enabled, NULL, NULL, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Noise, NULL, NULL, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Utilization, NULL, NULL, NULL, BBFDM_BOTH},
{"Transmit", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Transmit, NULL, NULL, NULL, BBFDM_BOTH},
{"ReceiveSelf", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf, NULL, NULL, NULL, BBFDM_BOTH},
{"ReceiveOther", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther, NULL, NULL, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"UnassociatedSTANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"BSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ScanResultNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"CapableOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams, NULL, BBFDM_BOTH, (const char *[]){"Class", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"HTCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"CapableOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxTxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower, NULL, NULL, NULL, BBFDM_BOTH},
{"NonOperable", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable, NULL, NULL, NULL, BBFDM_BOTH},
{"NumberOfNonOperChan", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class, NULL, NULL, NULL, BBFDM_BOTH},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel, NULL, NULL, NULL, BBFDM_BOTH},
{"TxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"STA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAParams, NULL, BBFDM_BOTH, (const char *[]){"MACAddress", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID, NULL, NULL, NULL, BBFDM_BOTH},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_SSID, NULL, NULL, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastBytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastBytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastBytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastBytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastBytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastBytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"EstServiceParametersBE", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE, NULL, NULL, NULL, BBFDM_BOTH},
{"EstServiceParametersBK", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK, NULL, NULL, NULL, BBFDM_BOTH},
{"EstServiceParametersVI", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI, NULL, NULL, NULL, BBFDM_BOTH},
{"EstServiceParametersVO", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO, NULL, NULL, NULL, BBFDM_BOTH},
{"STANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate, NULL, NULL, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate, NULL, NULL, NULL, BBFDM_BOTH},
{"UtilizationReceive", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive, NULL, NULL, NULL, BBFDM_BOTH},
{"UtilizationTransmit", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit, NULL, NULL, NULL, BBFDM_BOTH},
{"EstMACDataRateDownlink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink, NULL, NULL, NULL, BBFDM_BOTH},
{"EstMACDataRateUplink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink, NULL, NULL, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength, NULL, NULL, NULL, BBFDM_BOTH},
{"LastConnectTime", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount, NULL, NULL, NULL, BBFDM_BOTH},
{"MeasurementReport", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport, NULL, NULL, NULL, BBFDM_BOTH},
{"NumberOfMeasureReports", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports, NULL, NULL, NULL, BBFDM_BOTH},
{"IPV4Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address, NULL, NULL, NULL, BBFDM_BOTH},
{"IPV6Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address, NULL, NULL, NULL, BBFDM_BOTH},
{"Hostname", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"OpClassScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams, NULL, BBFDM_BOTH, (const char *[]){"OperatingClass", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{"OpClassScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"ChannelScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams, NULL, BBFDM_BOTH, (const char *[]){"Channel", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"OperatingClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass, NULL, NULL, NULL, BBFDM_BOTH},
{"ChannelScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"NeighborBSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams, NULL, BBFDM_BOTH, (const char *[]){"BSSID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization, NULL, NULL, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise, NULL, NULL, NULL, BBFDM_BOTH},
{"NeighborBSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID, NULL, NULL, NULL, BBFDM_BOTH},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID, NULL, NULL, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength, NULL, NULL, NULL, BBFDM_BOTH},
{"ChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth, NULL, NULL, NULL, BBFDM_BOTH},
{"ChannelUtilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization, NULL, NULL, NULL, BBFDM_BOTH},
{"StationCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent. *** */
DMOBJ tWiFiDataElementsAssociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"AssociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsAssociationEventAssociationEventDataInst, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"AssociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_BSSID, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"StatusCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode, NULL, NULL, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent. *** */
DMOBJ tWiFiDataElementsDisassociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"DisassociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsDisassociationEventDisassociationEventDataInst, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventDisassociationEventDataParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsDisassociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DisassociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"ReasonCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
