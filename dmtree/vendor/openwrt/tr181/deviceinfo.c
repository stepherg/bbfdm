#include "deviceinfo.h"

enum fw_image_status {
	FW_IMAGE_STATUS_NoImage,
	FW_IMAGE_STATUS_Downloading,
	FW_IMAGE_STATUS_Validating,
	FW_IMAGE_STATUS_Available,
	FW_IMAGE_STATUS_DownloadFailed,
	FW_IMAGE_STATUS_ValidationFailed,
	FW_IMAGE_STATUS_InstallationFailed,
	FW_IMAGE_STATUS_ActivationFailed,
	__FW_IMAGE_STATUS_MAX
};

static const char *fw_image_status_str[__FW_IMAGE_STATUS_MAX] = {
	"NoImage",
	"Downloading",
	"Validating",
	"Available",
	"DownloadFailed",
	"ValidationFailed",
	"InstallationFailed",
	"ActivationFailed"
};

struct fw_image {
	const char *name;
	enum fw_image_status status;
};

static const struct fw_image fw_images[] = {
	{ .name = "default", .status = FW_IMAGE_STATUS_Available }
};

static int openwrt__browseDeviceInfoFirmwareImageInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(fw_images); i++) {
		const struct fw_image *fw_img = &fw_images[i];

		inst = handle_instance_without_section(dmctx, parent_node, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)fw_img, inst) == DM_STOP)
			break;
	}
	return 0;
}

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

static int openwrt__get_device_active_fwimage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup("Device.DeviceInfo.FirmwareImage.1");
	return 0;
}

static int openwrt__get_device_fwimage_numberofentries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%d", ARRAY_SIZE(fw_images));
	return 0;
}

static int openwrt__get_FirmwareImage_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct fw_image *fw_img = data;

	*value = (char *)fw_img->name;
	return 0;
}

static int openwrt__get_FirmwareImage_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return openwrt__get_device_softwareversion(refparam, ctx, data, instance, value);
}

static int openwrt__get_FirmwareImage_available(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct fw_image *fw_img = data;

	*value = fw_img->status == FW_IMAGE_STATUS_Available ? "1" : "0";
	return 0;
}

static int openwrt__get_FirmwareImage_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct fw_image *fw_img = data;

	*value = (char *)fw_image_status_str[fw_img->status];
	return 0;
}

static int openwrt__get_FirmwareImage_bootfailurelog(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = 0;
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DeviceInfo. *** */
DMOBJ tOPENWRT_DeviceInfoObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"FirmwareImage", &DMREAD, NULL, NULL, NULL, openwrt__browseDeviceInfoFirmwareImageInst, NULL, NULL, NULL, tOPENWRT_DeviceInfoFirmwareImageParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

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
{"ActiveFirmwareImage", &DMREAD, DMT_STRING, openwrt__get_device_active_fwimage, NULL, BBFDM_BOTH},
{"FirmwareImageNumberOfEntries", &DMREAD, DMT_UNINT, openwrt__get_device_fwimage_numberofentries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.FirmwareImage.{i}. *** */
DMLEAF tOPENWRT_DeviceInfoFirmwareImageParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Name", &DMREAD, DMT_STRING, openwrt__get_FirmwareImage_name, NULL, BBFDM_BOTH },
{"Version", &DMREAD, DMT_STRING, openwrt__get_FirmwareImage_version, NULL, BBFDM_BOTH },
{"Available", &DMREAD, DMT_BOOL, openwrt__get_FirmwareImage_available, NULL, BBFDM_BOTH },
{"Status", &DMREAD, DMT_STRING, openwrt__get_FirmwareImage_status, NULL, BBFDM_BOTH },
{"BootFailureLog", &DMREAD, DMT_STRING, openwrt__get_FirmwareImage_bootfailurelog, NULL, BBFDM_BOTH },
{0}
};
