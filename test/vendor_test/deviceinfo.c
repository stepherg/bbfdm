#include "deviceinfo.h"

static char *get_uci_deviceinfo(char *opt)
{
	char *v;

	dmuci_get_option_value_string("cwmp", "@deviceinfotest[0]", opt, &v);
	return v;
}

static int test__get_device_manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("Manufacturer");
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DeviceInfo. *** */
DMOBJ tTEST_DeviceInfoObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"VendorConfigFile", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_NONE},
{0}
};

DMLEAF tTEST_DeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Manufacturer", &DMREAD, DMT_STRING, test__get_device_manufacturer, NULL, BBFDM_BOTH},
{0}
};
