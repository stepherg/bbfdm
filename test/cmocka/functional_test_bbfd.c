#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libbbfdm-api/dmuci.h>
#include <libbbfdm-api/dmapi.h>
#include <libbbfdm-api/dmentry.h>

#include "../../libbbfdm/device.h"

static DMOBJ TR181_ROOT_TREE[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDMRootObj, tDMRootParams, NULL, BBFDM_BOTH},
{0}
};

static int setup(void **state)
{
	struct dmctx *ctx = calloc(1, sizeof(struct dmctx));
	if (!ctx)
		return -1;

	bbf_ctx_init(ctx, TR181_ROOT_TREE);

	*state = ctx;

	return 0;
}

static int teardown_commit(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;

	bbf_entry_services(ctx->dm_type, true, true);
	bbf_ctx_clean(ctx);
	free(ctx);

	return 0;
}

static int group_init(void **state)
{
	bbf_global_init(TR181_ROOT_TREE, "/usr/share/bbfdm/plugins");
	return 0;
}

static int group_teardown(void **state)
{
	bbf_global_clean(TR181_ROOT_TREE);
	return 0;
}

static void validate_parameter(struct dmctx *ctx, const char *name, const char *value, const char *type)
{
	struct blob_attr *cur = NULL;
	size_t rem = 0;

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[3] = {0};
		const struct blobmsg_policy p[3] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING }
		};

		blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *dm_name = blobmsg_get_string(tb[0]);
		char *dm_data = blobmsg_get_string(tb[1]);
		char *dm_type = blobmsg_get_string(tb[2]);

		// check the returned path
		assert_string_equal(dm_name, name);

		// check the returned value
		assert_string_equal(dm_data, value);

		// check the returned type
		assert_string_equal(dm_type, type);
	}

	bbf_ctx_clean(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE);
}

static void test_api_bbfdm_get_set_standard_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	ctx->in_param = "Device.WiFi.Radio.1.Channel";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.1.Channel", "36", "xsd:unsignedInt");

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.WiFi.Radio.1.Channel";
	ctx->in_value = "64t";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.WiFi.Radio.1.Channel";
	ctx->in_value = "100";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.WiFi.Radio.1.Channel";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 64: name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.1.Channel", "100", "xsd:unsignedInt");
}

static void test_api_bbfdm_get_set_json_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_WiFi.Radio.1.Noise";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_WiFi.Radio.1.Noise", "-87", "xsd:int");

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_WiFi.Radio.2.Noise";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_WiFi.Radio.2.Noise", "-85", "xsd:int");

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_WiFi.Radio.2.Band";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_WiFi.Radio.2.Band", "2.4GHz", "xsd:string");

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_WiFi.Radio.1.Stats.BytesSent";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_WiFi.Radio.1.Stats.BytesSent", "14418177", "xsd:unsignedInt");

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_WiFi.Radio.2.Stats.BytesSent";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_WiFi.Radio.2.Stats.BytesSent", "14417451", "xsd:unsignedInt");
}

static void test_api_bbfdm_get_set_json_v1_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	char *value = NULL;
	int fault = 0;

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.Password";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.Password", "", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.Password";
	ctx->in_value = "iopsys_test";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);
	dmuci_commit_package("users");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.Password";
	ctx->dm_type = BBFDM_CWMP;
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.Password", "", "xsd:string");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.Password";
	ctx->dm_type = BBFDM_USP;
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.Password", "iopsys_test", "xsd:string");

	// validate uci config
	fault = dmuci_get_option_value_string("users", "user", "password_required", &value);
	assert_int_equal(fault, 0);
	assert_string_equal(value, "iopsys_test");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSDNumberOfEntries";
	ctx->dm_type = BBFDM_BOTH;
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSDNumberOfEntries", "3", "xsd:unsignedInt");

	// set value ==> expected "9008" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSDNumberOfEntries";
	ctx->in_value = "5";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.2.IPv6";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.2.IPv6", "off", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.2.IPv6";
	ctx->in_value = "on";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.2.IPv6";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.2.IPv6", "on", "xsd:string");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.1.Port";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.1.Port", "80", "xsd:unsignedInt");

	// set value ==> expected "9007" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.1.Port";
	ctx->in_value = "65536";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.1.Port";
	ctx->in_value = "8081";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.1.Port";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.1.Port", "8081", "xsd:unsignedInt");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.3.Password";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.3.Password", "", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.3.Password";
	ctx->in_value = "owsd_pwd";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);
	dmuci_commit_package("owsd");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.3.Password";
	ctx->dm_type = BBFDM_CWMP;
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.3.Password", "", "xsd:string");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.3.Password";
	ctx->dm_type = BBFDM_USP;
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.3.Password", "owsd_pwd", "xsd:string");

	// validate uci config
	fault = dmuci_get_option_value_string("owsd", "@owsd_listen[2]", "password", &value);
	assert_int_equal(fault, 0);
	assert_string_equal(value, "owsd_pwd");

	// get value ==> expected "0" error
	ctx->in_param = "Device.UBUS_TEST_V1.Uptime";
	ctx->dm_type = BBFDM_BOTH;
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Uptime", "5859", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.UBUS_TEST_V1.Uptime";
	ctx->in_value = "lan";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UBUS_TEST_V1.InterfaceNumberOfEntries";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.InterfaceNumberOfEntries", "10", "xsd:unsignedInt");

	// set value ==> expected "9008" error
	ctx->in_param = "Device.UBUS_TEST_V1.InterfaceNumberOfEntries";
	ctx->in_value = "5";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.3.MacAddress";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Interface.3.MacAddress", "60:8d:26:c4:96:f7", "xsd:string");

	// set value ==> expected "9008" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.3.MacAddress";
	ctx->in_value = "49:d4:40:71:7e:55";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.4.Ifname";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Interface.4.Ifname", "eth4", "xsd:string");

	// set value ==> expected "9008" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.4.Ifname";
	ctx->in_value = "lan5";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.2.Media";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Interface.2.Media", "IEEE 802_3AB_GIGABIT_ETHERNET", "xsd:string");

	// set value ==> expected "9008" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.2.Media";
	ctx->in_value = "IEEE 802_11AX_5_GHZ";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name", "homeoffice", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name";
	ctx->in_value = "home+office test";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name", "home+office test", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name";
	ctx->in_value = "office_test";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_URLFilter.Profile.1.Name", "office_test", "xsd:string");
}

static void test_api_bbfdm_get_set_library_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	ctx->in_param = "Device.WiFi.SSID.1.Enable";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.SSID.1.Enable", "1", "xsd:boolean");

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.WiFi.SSID.1.Enable";
	ctx->in_value = "truee";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.WiFi.SSID.1.Enable";
	ctx->in_value = "0";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.WiFi.SSID.1.Enable";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 0: name, type, value
	validate_parameter(ctx, "Device.WiFi.SSID.1.Enable", "0", "xsd:boolean");
}

static void test_api_bbfdm_input_value_validation_json_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	/*
	 * Validate Boolean parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Enable";
	ctx->in_value = "64t";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Enable";
	ctx->in_value = "truee";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Enable";
	ctx->in_value = "true";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Enable";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Enable", "1", "xsd:boolean");

	/*
	 * Validate unsignedInt parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries";
	ctx->in_value = "64t";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries";
	ctx->in_value = "15600";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries", "15600", "xsd:unsignedInt");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Port";
	ctx->in_value = "1050";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [0-1000] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Port";
	ctx->in_value = "1000";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Port";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Port", "1000", "xsd:unsignedInt");

	// Mapping with range: set value in the second range [15000-65535] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Port";
	ctx->in_value = "20546";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Port";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Port", "20546", "xsd:unsignedInt");

	/*
	 * Validate int parameters
	 */

	// Mapping with range (only min): Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Min_value";
	ctx->in_value = "-300";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Min_value";
	ctx->in_value = "-273";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Min_value";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Min_value", "-273", "xsd:int");

	// Mapping with range (only max): Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Max_value";
	ctx->in_value = "280";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [0-1000] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Max_value";
	ctx->in_value = "274";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Max_value";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Max_value", "274", "xsd:int");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Value";
	ctx->in_value = "-3";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [-10:-5] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Value";
	ctx->in_value = "-7";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Value";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Value", "-7", "xsd:int");

	// Mapping with range: set value in the second range [-1:10] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Value";
	ctx->in_value = "1";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Value";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Value", "1", "xsd:int");

	/*
	 * Validate unsignedLong parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes";
	ctx->in_value = "64t";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes";
	ctx->in_value = "15600";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes", "15600", "xsd:unsignedLong");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_packets";
	ctx->in_value = "499";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [0-100] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_packets";
	ctx->in_value = "99";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_packets";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "99", "xsd:unsignedLong");

	// Mapping with range: set value in the second range [500-3010] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_packets";
	ctx->in_value = "1024";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Nbr_packets";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "1024", "xsd:unsignedLong");

	/*
	 * Validate long parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.MaxTxPower";
	ctx->in_value = "-300t";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.MaxTxPower";
	ctx->in_value = "-273";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.MaxTxPower";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.MaxTxPower", "-273", "xsd:long");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit";
	ctx->in_value = "-91";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [-90:36] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit";
	ctx->in_value = "274";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "274", "xsd:long");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit";
	ctx->in_value = "37";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [70:360] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit";
	ctx->in_value = "70";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "70", "xsd:long");

	/*
	 * Validate dateTime parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.AssociationTime";
	ctx->in_value = "2030-01-01T11:22:33.2Z";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.AssociationTime";
	ctx->in_value = "2022-01-01T12:20:22.2222Z";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.AssociationTime";
	ctx->in_value = "2022-01-01T12:20:22Z";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.AssociationTime";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.AssociationTime", "2022-01-01T12:20:22Z", "xsd:dateTime");

	/*
	 * Validate hexBinary parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.ButtonColor";
	ctx->in_value = "64t";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.ButtonColor";
	ctx->in_value = "64ab78cef12";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.ButtonColor";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.ButtonColor", "64ab78cef12", "xsd:hexBinary");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TextColor";
	ctx->in_value = "am123";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [3-3] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TextColor";
	ctx->in_value = "123abc";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TextColor";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TextColor", "123abc", "xsd:hexBinary");

	// Mapping with range: set value in the second range [5-5] ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TextColor";
	ctx->in_value = "12345abcde";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TextColor";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TextColor", "12345abcde", "xsd:hexBinary");

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.BackgroundColor";
	ctx->in_value = "12345abce";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.BackgroundColor";
	ctx->in_value = "45a1bd";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.BackgroundColor";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.BackgroundColor", "45a1bd", "xsd:hexBinary");

	/*
	 * Validate string parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Interface";
	ctx->in_value = "64";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Interface";
	ctx->in_value = "wan";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Interface";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Interface", "wan", "xsd:string");

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.IPAddr";
	ctx->in_value = "192.168.1.789";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.IPAddr";
	ctx->in_value = "192.168.117.45";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.IPAddr";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.IPAddr", "192.168.117.45", "xsd:string");

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Protocol";
	ctx->in_value = "OMA-D";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Protocol";
	ctx->in_value = "OMA-DM";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Protocol";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Protocol", "OMA-DM", "xsd:string");

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Description";
	ctx->in_value = "bbf validate test";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Description";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Description", "bbf validate test", "xsd:string");

	/*
	 * Validate list string parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.FailureReasons";
	ctx->in_value = "te,be,re,yu";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.FailureReasons";
	ctx->in_value = "ExcessiveDelay,InsufficientBuffers";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.FailureReasons";
	ctx->in_value = "LowRate,Other";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.FailureReasons";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.FailureReasons", "LowRate,Other", "xsd:string");

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths";
	ctx->in_value = "200MHz,10MHz";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths";
	ctx->in_value = "ExcessiveDelay,InsufficientBuffers";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths";
	ctx->in_value = "40MHz,80+80MHz";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths";
	ctx->in_value = "";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	ctx->in_param = "";
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths", "40MHz,80+80MHz", "xsd:string");

	/*
	 * Validate list int parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported";
	ctx->in_value = "-5,-3,99,120";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported";
	ctx->in_value = "-1,9,990";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported";
	ctx->in_value = "-1,9,100";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported", "-1,9,100", "xsd:string");

	/*
	 * Validate list unsignedInt parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration";
	ctx->in_value = "8,1,2,3";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration";
	ctx->in_value = "1,2,3,4,5,6,7,8";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration";
	ctx->in_value = "0,1,2,3,4,5,6,7";
	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration", "0,1,2,3,4,5,6,7", "xsd:string");
}

static void test_api_bbfdm_add_del_standard_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	ctx->in_param = "Device.Users.User.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	ctx->in_param = "Device.Users.User.";
	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "2");

	// delete object ==> expected "0" error
	ctx->in_param = "Device.Users.User.2.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	ctx->in_param = "Device.Users.User.2.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "9005" error
	ctx->in_param = "Device.Users.User.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_add_del_json_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "2");

	// delete object ==> expected "0" error
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.2.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.2.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "9005" error
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_add_del_json_v1_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.";
	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "4");

	// delete object ==> expected "0" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.2.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.2.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "9005" error
	ctx->in_param = "Device.UCI_TEST_V1.OWSD.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);

	// add object ==> expected "9005" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.";
	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "9005" error
	ctx->in_param = "Device.UBUS_TEST_V1.Interface.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_add_del_library_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	ctx->in_param = "Device.WiFi.AccessPoint.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	// Get name object ==> expected "0" error
	ctx->in_param = "Device.WiFi.SSID.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	ctx->in_param = "Device.WiFi.SSID.";
	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "4");

	// delete object ==> expected "0" error
	ctx->in_param = "Device.WiFi.SSID.2.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	ctx->in_param = "Device.WiFi.SSID.2.";
	ctx->nextlevel = true;
	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "9005" error
	ctx->in_param = "Device.WiFi.SSID.";
	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_valid_standard_operate(void **state)
{
	// TODO: To be used later with micro-service
#if 0
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL;
	size_t rem = 0;
	int fault = 0;

	ctx->in_param = "Device.IP.Diagnostics.IPPing()";
	ctx->in_value = "{\"Host\":\"iopsys.eu\",\"NumberOfRepetitions\":\"1\",\"Timeout\":\"5000\",\"DataBlockSize\":\"64\"}";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[3] = {0};
		const struct blobmsg_policy p[3] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING }
		};

		blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);

		if (DM_STRCMP(name, "Status") == 0) {
			assert_string_equal(data, "Complete");
			assert_string_equal(type, "xsd:string");
		} else if (DM_STRCMP(name, "IPAddressUsed") == 0) {
			assert_string_equal(data, "");
			assert_string_equal(type, "xsd:string");
		} else if (DM_STRCMP(name, "SuccessCount") == 0) {
			assert_string_equal(data, "1");
			assert_string_equal(type, "xsd:unsignedInt");
		} else if (DM_STRCMP(name, "FailureCount") == 0) {
			assert_string_equal(data, "0");
			assert_string_equal(type, "xsd:unsignedInt");
		} else {
			assert_string_not_equal(data, "0");
			assert_string_equal(type, "xsd:unsignedInt");
		}
	}
#endif
}

static void test_api_bbfdm_valid_standard_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL;
	size_t rem = 0;
	int fault = 0, idx = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = false;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *_cur = NULL;
		size_t _rem = 0;
		struct blob_attr *tb[5] = {0};
		const struct blobmsg_policy p[5] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY },
				{ "output", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 5, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *command_in = tb[3];
		struct blob_attr *command_out = tb[4];

		if (DM_STRCMP(name, "Device.FactoryReset()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "sync");
			assert_non_null(data);
			assert_null(command_in);
			assert_null(command_out);
		}

		if (DM_STRCMP(name, "Device.DeviceInfo.VendorLogFile.{i}.Upload()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "async");
			assert_non_null(command_in);
			assert_null(command_out);

			blobmsg_for_each_attr(_cur, command_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "URL");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Username");
						break;
					case 2:
						assert_string_equal(blobmsg_get_string(__cur), "Password");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 3);
		}

		if (DM_STRCMP(name, "Device.WiFi.NeighboringWiFiDiagnostic()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "async");
			assert_null(command_in);
			assert_non_null(command_out);

			idx = 0;

			blobmsg_for_each_attr(_cur, command_out, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Status");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Result.{i}.Radio");
						break;
					case 2:
						assert_string_equal(blobmsg_get_string(__cur), "Result.{i}.SSID");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 18);
		}
	}
}

static void test_api_bbfdm_valid_library_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL;
	size_t rem = 0;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_PingTEST.Run()";
	ctx->in_value = "{\"Host\":\"iopsys.eu\"}";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[2] = {0};
		const struct blobmsg_policy p[2] = {
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING }
		};

		blobmsg_parse(p, 2, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *data = blobmsg_get_string(tb[0]);
		char *type = blobmsg_get_string(tb[1]);

		assert_string_not_equal(data, "0");
		assert_string_equal(type, "xsd:unsignedInt");
	}
}

static void test_api_bbfdm_valid_library_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL, *_cur = NULL;
	size_t rem = 0, _rem = 0;
	int fault = 0, idx = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = false;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[5] = {0};
		const struct blobmsg_policy p[5] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY },
				{ "output", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 5, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *command_in = tb[3];
		struct blob_attr *command_out = tb[4];

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_Reboot()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "sync");
			assert_null(command_in);
			assert_null(command_out);
		}

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_PingTEST.Run()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "async");
			assert_non_null(command_in);
			assert_non_null(command_out);

			blobmsg_for_each_attr(_cur, command_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Host");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 1);

			idx = 0;

			blobmsg_for_each_attr(_cur, command_out, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "AverageResponseTime");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "MinimumResponseTime");
						break;
					case 2:
						assert_string_equal(blobmsg_get_string(__cur), "MaximumResponseTime");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 3);
		}
	}
}

static void test_api_bbfdm_valid_json_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL;
	size_t rem = 0;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_TEST.1.Status()";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[3] = {0};
		const struct blobmsg_policy p[3] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING }
		};

		blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *dm_name = blobmsg_get_string(tb[0]);
		char *dm_data = blobmsg_get_string(tb[1]);
		char *dm_type = blobmsg_get_string(tb[2]);

		assert_string_equal(dm_name, "Result");
		assert_string_equal(dm_data, "Success");
		assert_string_equal(dm_type, "xsd:string");
	}
}

static void test_api_bbfdm_valid_json_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL, *_cur = NULL;
	size_t rem = 0, _rem = 0;
	int fault = 0, idx = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = false;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[5] = {0};
		const struct blobmsg_policy p[5] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY },
				{ "output", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 5, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *command_in = tb[3];
		struct blob_attr *command_out = tb[4];

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_TEST.{i}.Status()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "async");
			assert_non_null(command_in);
			assert_non_null(command_out);

			blobmsg_for_each_attr(_cur, command_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Option");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 1);

			idx = 0;

			blobmsg_for_each_attr(_cur, command_out, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Result");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 1);
		}
	}
}

static void test_api_bbfdm_valid_json_v1_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL;
	size_t rem = 0;
	int fault = 0;

	ctx->in_param = "Device.UBUS_TEST_V1.Interface.3.Status()";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[3] = {0};
		const struct blobmsg_policy p[3] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING }
		};

		blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *dm_name = blobmsg_get_string(tb[0]);
		char *dm_data = blobmsg_get_string(tb[1]);
		char *dm_type = blobmsg_get_string(tb[2]);

		assert_string_equal(dm_name, "Result");
		assert_string_equal(dm_data, "Success");
		assert_string_equal(dm_type, "xsd:string");
	}
}

static void test_api_bbfdm_valid_json_v1_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL, *_cur = NULL;
	int fault = 0, _rem = 0, idx = 0;
	size_t rem = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = false;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[5] = {0};
		const struct blobmsg_policy p[5] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY },
				{ "output", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 5, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *command_in = tb[3];
		struct blob_attr *command_out = tb[4];

		if (DM_STRCMP(name, "Device.UBUS_TEST_V1.Interface.{i}.Status()") == 0) {
			assert_string_equal(type, "xsd:command");
			assert_string_equal(data, "async");
			assert_non_null(command_in);
			assert_non_null(command_out);

			blobmsg_for_each_attr(_cur, command_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Option");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Value");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 2);

			idx = 0;

			blobmsg_for_each_attr(_cur, command_out, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Result");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Value");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 2);
		}
	}
}

static void test_api_bbfdm_valid_library_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL, *_cur = NULL;
	int fault = 0, _rem = 0, idx = 0, event_num = 0;
	size_t rem = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = false;
	ctx->isevent = true;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[4] = {0};
		const struct blobmsg_policy p[4] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *event_in = tb[3];

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_WakeUp!") == 0) {
			assert_string_equal(type, "xsd:event");
			assert_null(data);
		}

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_Boot!") == 0) {
			assert_string_equal(type, "xsd:event");
			assert_non_null(event_in);

			blobmsg_for_each_attr(_cur, event_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "CommandKey");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Cause");
						break;
					case 2:
						assert_string_equal(blobmsg_get_string(__cur), "FirmwareUpdated");
						break;
					case 3:
						assert_string_equal(blobmsg_get_string(__cur), "ParameterMap");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 4);
		}

		event_num++;
	}

	assert_int_not_equal(event_num, 0);
}

static void test_api_bbfdm_valid_json_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL, *_cur = NULL;
	int fault = 0, _rem = 0, idx = 0, event_num = 0;
	size_t rem = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = false;
	ctx->isevent = true;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[4] = {0};
		const struct blobmsg_policy p[4] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *event_in = tb[3];

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_TEST.{i}.Periodic!") == 0) {
			assert_string_equal(type, "xsd:event");
			assert_null(data);
		}

		if (DM_STRCMP(name, "Device.X_IOPSYS_EU_TEST.{i}.Push!") == 0) {
			assert_string_equal(type, "xsd:event");
			assert_non_null(event_in);

			blobmsg_for_each_attr(_cur, event_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Data");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Status");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 2);
		}

		event_num++;
	}

	assert_int_not_equal(event_num, 0);
}

static void test_api_bbfdm_valid_json_v1_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct blob_attr *cur = NULL, *_cur = NULL;
	int fault = 0, _rem = 0, idx = 0, event_num = 0;
	size_t rem = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = false;
	ctx->isevent = true;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	blobmsg_for_each_attr(cur, ctx->bb.head, rem) {
		struct blob_attr *tb[4] = {0};
		const struct blobmsg_policy p[4] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "input", BLOBMSG_TYPE_ARRAY }
		};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		char *name = blobmsg_get_string(tb[0]);
		char *data = blobmsg_get_string(tb[1]);
		char *type = blobmsg_get_string(tb[2]);
		struct blob_attr *event_in = tb[3];

		if (DM_STRCMP(name, "Device.UBUS_TEST_V1.Interface.{i}.Periodic!") == 0) {
			assert_string_equal(type, "xsd:event");
			assert_null(data);
		}

		if (DM_STRCMP(name, "Device.UBUS_TEST_V1.Interface.{i}.Push!") == 0) {
			assert_string_equal(type, "xsd:event");
			assert_non_null(event_in);

			blobmsg_for_each_attr(_cur, event_in, _rem) {
				struct blob_attr *__cur = NULL;
				size_t __rem = 0;

				blobmsg_for_each_attr(__cur, _cur, __rem) {
					switch (idx) {
					case 0:
						assert_string_equal(blobmsg_get_string(__cur), "Data");
						break;
					case 1:
						assert_string_equal(blobmsg_get_string(__cur), "Status");
						break;
					case 2:
						assert_string_equal(blobmsg_get_string(__cur), "Value");
						break;
					}
					idx++;
				}
			}
			assert_int_equal(idx, 3);
		}

		event_num++;
	}

	assert_int_not_equal(event_num, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		// Get/Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_standard_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_json_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_json_v1_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_library_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_input_value_validation_json_parameter, setup, teardown_commit),

		// Add/Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_standard_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_json_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_json_v1_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_library_object, setup, teardown_commit),

		// Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_standard_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_standard_list_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_library_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_library_list_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_json_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_json_list_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_json_v1_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_json_v1_list_operate, setup, teardown_commit),

		// Event method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_library_event, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_json_event, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_json_v1_event, setup, teardown_commit),
	};

	return cmocka_run_group_tests(tests, group_init, group_teardown);
}


