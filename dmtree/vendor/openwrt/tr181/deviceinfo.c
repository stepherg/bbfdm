#include "deviceinfo.h"

static char *get_uci_deviceinfo(char *opt)
{
	char *v;

	dmuci_get_option_value_string("cwmp", "@deviceinfo[0]", opt, &v);
	return v;
}

static int openwrt__get_device_manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("Manufacturer");
	return 0;
}

static int openwrt__get_device_manufactureroui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("ManufacturerOUI");
	return 0;
}

static int openwrt__get_device_productclass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("ProductClass");
	return 0;
}

static int openwrt__get_device_serialnumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("SerialNumber");
	return 0;
}

static int openwrt__get_device_softwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("SoftwareVersion");
	return 0;
}

static int openwrt__get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("HardwareVersion");
	return 0;
}

static int openwrt__get_device_devicecategory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("DeviceCategory");
	return 0;
}

static int openwrt__get_device_additionalhardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("AdditionalHardwareVersion");
	return 0;
}

static int openwrt__get_device_additionalsoftwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("AdditionalSoftwareVersion");
	return 0;
}

static int openwrt__get_device_modelname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("ModelName");
	return 0;
}

static int openwrt__get_device_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("Description");
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DeviceInfo. *** */
DMLEAF tOPENWRT_DeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DeviceCategory", &DMREAD, DMT_STRING, openwrt__get_device_devicecategory, NULL, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, openwrt__get_device_manufacturer, NULL, BBFDM_BOTH},
{"ManufacturerOUI", &DMREAD, DMT_STRING, openwrt__get_device_manufactureroui, NULL, BBFDM_BOTH},
{"ModelName", &DMREAD, DMT_STRING, openwrt__get_device_modelname, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, openwrt__get_device_description, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, openwrt__get_device_productclass, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, openwrt__get_device_serialnumber, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, openwrt__get_device_hardwareversion, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, openwrt__get_device_softwareversion, NULL, BBFDM_BOTH},
{"AdditionalHardwareVersion", &DMREAD, DMT_STRING, openwrt__get_device_additionalhardwareversion, NULL, BBFDM_BOTH},
{"AdditionalSoftwareVersion", &DMREAD, DMT_STRING, openwrt__get_device_additionalsoftwareversion, NULL, BBFDM_BOTH},
{0}
};
