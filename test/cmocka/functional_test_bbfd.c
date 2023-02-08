#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libubus.h>
#include <libbbf_api/dmuci.h>
#include <libbbfdm/dmentry.h>

static struct ubus_context *ubus_ctx = NULL;

static int group_setup(void **state)
{
	ubus_ctx = ubus_connect(NULL);
	if (ubus_ctx == NULL)
		return -1;

	dm_config_ubus(ubus_ctx);
	return 0;
}

static int setup(void **state)
{
	struct dmctx *ctx = calloc(1, sizeof(struct dmctx));
	if (!ctx)
		return -1;

	dm_ctx_init(ctx, INSTANCE_MODE_NUMBER);
	*state = ctx;

	return 0;
}

static int setup_alias(void **state)
{
	struct dmctx *ctx = calloc(1, sizeof(struct dmctx));
	if (!ctx)
		return -1;

	dm_ctx_init(ctx, INSTANCE_MODE_ALIAS);
	*state = ctx;

	return 0;
}

static int teardown_commit(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;

	dm_entry_restart_services();
	dm_ctx_clean(ctx);
	free(ctx);

	return 0;
}

static int group_teardown(void **state)
{
	bbf_dm_cleanup();
	if (ubus_ctx != NULL) {
		ubus_free(ubus_ctx);
		ubus_ctx = NULL;
	}

	return 0;
}


static void validate_parameter(struct dmctx *ctx, const char *name, const char *value, const char *type)
{
	struct dm_parameter *n;

	dm_ctx_clean_sub(ctx);
	dm_ctx_init_sub(ctx, INSTANCE_MODE_NUMBER);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		// check the returned path
		assert_string_equal(n->name, name);

		// check the returned value
		assert_string_equal(n->data, value);

		// check the returned type
		assert_string_equal(n->type, type);
	}
}

static void test_api_bbfdm_get_set_standard_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.1.Channel", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.1.Channel", "1", "xsd:unsignedInt");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.1.Channel", "64t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.1.Channel", "64", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.1.Channel", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 64: name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.1.Channel", "64", "xsd:unsignedInt");
}

static void test_api_bbfdm_get_set_json_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UserInterface.CurrentLanguage", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UserInterface.CurrentLanguage", "en", "xsd:string");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UserInterface.CurrentLanguage", "fr", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UserInterface.CurrentLanguage", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to fr: name, type, value
	validate_parameter(ctx, "Device.UserInterface.CurrentLanguage", "fr", "xsd:string");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.X_IOPSYS_EU_Radio.1.Noise", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.X_IOPSYS_EU_Radio.2.Noise", "-87", "xsd:int");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.X_IOPSYS_EU_Radio.2.Noise", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.X_IOPSYS_EU_Radio.2.Noise", "-85", "xsd:int");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.X_IOPSYS_EU_Radio.2.Band", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.X_IOPSYS_EU_Radio.2.Band", "2.4GHz", "xsd:string");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.X_IOPSYS_EU_Radio.1.Stats.BytesSent", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.X_IOPSYS_EU_Radio.1.Stats.BytesSent", "14418177,", "xsd:unsignedInt");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.X_IOPSYS_EU_Radio.2.Stats.BytesSent", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.X_IOPSYS_EU_Radio.2.Stats.BytesSent", "14417451", "xsd:unsignedInt");
}

static void test_api_bbfdm_get_set_json_v1_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	char *value = NULL;
	int fault = 0;

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.Password", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.Password", "", "xsd:string");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UCI_TEST_V1.Password", "iopsys_test", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.Password", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.Password", "", "xsd:string");

	// validate uci config
	fault = dmuci_get_option_value_string("users", "user", "password_required", &value);
	assert_int_equal(fault, 0);
	assert_string_equal(value, "iopsys_test");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSDNumberOfEntries", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSDNumberOfEntries", "3", "xsd:unsignedInt");

	// set value ==> expected "9008" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UCI_TEST_V1.OWSDNumberOfEntries", "5", NULL);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSD.2.IPv6", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.2.IPv6", "off", "xsd:unsignedInt");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UCI_TEST_V1.OWSD.2.IPv6", "on", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSD.2.IPv6", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.2.IPv6", "on", "xsd:unsignedInt");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSD.1.Port", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.1.Port", "80", "xsd:unsignedInt");

	// set value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UCI_TEST_V1.OWSD.1.Port", "65536", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UCI_TEST_V1.OWSD.1.Port", "8081", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSD.1.Port", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.1.Port", "8081", "xsd:unsignedInt");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSD.3.Password", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.3.Password", "", "xsd:string");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UCI_TEST_V1.OWSD.3.Password", "owsd_pwd", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UCI_TEST_V1.OWSD.3.Password", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UCI_TEST_V1.OWSD.3.Password", "", "xsd:string");

	// validate uci config
	fault = dmuci_get_option_value_string("owsd", "@owsd-listen[2]", "password", &value);
	assert_int_equal(fault, 0);
	assert_string_equal(value, "owsd_pwd");

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UBUS_TEST_V1.Uptime", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Uptime", "5859", "xsd:string");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UBUS_TEST_V1.Uptime", "lan", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UBUS_TEST_V1.InterfaceNumberOfEntries", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.InterfaceNumberOfEntries", "10", "xsd:unsignedInt");

	// set value ==> expected "9008" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UBUS_TEST_V1.InterfaceNumberOfEntries", "5", NULL);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UBUS_TEST_V1.Interface.3.MacAddress", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Interface.3.MacAddress", "60:8d:26:c4:96:f7", "xsd:string");

	// set value ==> expected "9008" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UBUS_TEST_V1.Interface.3.MacAddress", "49:d4:40:71:7e:55", NULL);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UBUS_TEST_V1.Interface.4.Ifname", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Interface.4.Ifname", "eth4", "xsd:string");

	// set value ==> expected "9008" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UBUS_TEST_V1.Interface.4.Ifname", "lan5", NULL);
	assert_int_equal(fault, FAULT_9008);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UBUS_TEST_V1.Interface.2.Media", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.UBUS_TEST_V1.Interface.2.Media", "IEEE 802_3AB_GIGABIT_ETHERNET", "xsd:string");

	// set value ==> expected "9008" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UBUS_TEST_V1.Interface.2.Media", "IEEE 802_11AX_5_GHZ", NULL);
	assert_int_equal(fault, FAULT_9008);
}

static void test_api_bbfdm_get_set_library_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.SSID.1.Enable", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.SSID.1.Enable", "1", "xsd:boolean");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.SSID.1.Enable", "truee", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.SSID.1.Enable", "0", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.SSID.1.Enable", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 0: name, type, value
	validate_parameter(ctx, "Device.WiFi.SSID.1.Enable", "0", "xsd:boolean");
}

static void test_api_bbfdm_get_set_standard_parameter_alias(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.[cpe-1].Channel", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.[cpe-1].Channel", "64", "xsd:unsignedInt");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.[cpe-1].Channel", "64t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.[cpe-1].Channel", "84", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.[cpe-1].Channel", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 64: name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.[cpe-1].Channel", "84", "xsd:unsignedInt");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.[cpe-1].Alias", "iopsys_test", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.[iopsys_test].Alias", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 64: name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.[iopsys_test].Alias", "iopsys_test", "xsd:string");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.[iopsys_test].Channel", "74", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.[iopsys_test].Channel", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 64: name, type, value
	validate_parameter(ctx, "Device.WiFi.Radio.[iopsys_test].Channel", "74", "xsd:unsignedInt");
}

static void test_api_bbfdm_input_value_validation_json_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	/*
	 * Validate Boolean parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Enable", "64t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Enable", "truee", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Enable", "true", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Enable", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Enable", "1", "xsd:boolean");

	/*
	 * Validate unsignedInt parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries", "64t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries", "15600", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_Retries", "15600", "xsd:unsignedInt");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Port", "1050", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [0-1000] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Port", "1000", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Port", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Port", "1000", "xsd:unsignedInt");

	// Mapping with range: set value in the second range [15000-65535] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Port", "20546", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Port", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Port", "20546", "xsd:unsignedInt");

	/*
	 * Validate int parameters
	 */

	// Mapping with range (only min): Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Min_value", "-300", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Min_value", "-273", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Min_value", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Min_value", "-273", "xsd:int");

	// Mapping with range (only max): Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Max_value", "280", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [0-1000] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Max_value", "274", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Max_value", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Max_value", "274", "xsd:int");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Value", "-3", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [-10:-5] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Value", "-7", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Value", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.value", "-7", "xsd:int");

	// Mapping with range: set value in the second range [-1:10] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Value", "1", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Value", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Value", "1", "xsd:int");

	/*
	 * Validate unsignedLong parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes", "64t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes", "15600", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_bytes", "15600", "xsd:unsignedLong");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "499", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [0-100] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "99", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "99", "xsd:unsignedLong");

	// Mapping with range: set value in the second range [500-3010] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "1024", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Nbr_packets", "1024", "xsd:unsignedLong");

	/*
	 * Validate long parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.MaxTxPower", "-300t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.MaxTxPower", "-273", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.MaxTxPower", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.MaxTxPower", "-273", "xsd:long");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "-91", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [-90:36] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "274", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "274", "xsd:long");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "37", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [70:360] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "70", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerLimit", "70", "xsd:long");

	/*
	 * Validate dateTime parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.AssociationTime", "2030-01-01T11:22:33.2Z", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.AssociationTime", "2022-01-01T12:20:22.2222Z", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.AssociationTime", "2022-01-01T12:20:22Z", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.AssociationTime", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.AssociationTime", "2022-01-01T12:20:22Z", "xsd:dateTime");

	/*
	 * Validate hexBinary parameters
	 */

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.ButtonColor", "64t", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.ButtonColor", "64ab78cef12", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.ButtonColor", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.ButtonColor", "64ab78cef12", "xsd:hexBinary");

	// Mapping with range: Set Wrong Value out of range ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TextColor", "am123", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Mapping with range: set value in the first range [3-3] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TextColor", "123abc", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TextColor", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TextColor", "123abc", "xsd:hexBinary");

	// Mapping with range: set value in the second range [5-5] ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TextColor", "12345abcde", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TextColor", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TextColor", "12345abcde", "xsd:hexBinary");

	// Mapping without range: Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.BackgroundColor", "12345abce", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.BackgroundColor", "45a1bd", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.BackgroundColor", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.BackgroundColor", "45a1bd", "xsd:hexBinary");

	/*
	 * Validate string parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Interface", "64", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Interface", "wan", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Interface", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Interface", "wan", "xsd:string");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.IPAddr", "192.168.1.789", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.IPAddr", "192.168.117.45", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.IPAddr", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.IPAddr", "192.168.117.45", "xsd:string");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Protocol", "OMA-D", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Protocol", "OMA-DM", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Protocol", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Protocol", "OMA-DM", "xsd:string");

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Description", "bbf validate test", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.Description", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.Description", "bbf validate test", "xsd:string");

	/*
	 * Validate list string parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.FailureReasons", "te,be,re,yu", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.FailureReasons", "ExcessiveDelay,InsufficientBuffers", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.FailureReasons", "LowRate,Other", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.FailureReasons", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.FailureReasons", "LowRate,Other", "xsd:string");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths", "200MHz,10MHz", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths", "ExcessiveDelay,InsufficientBuffers", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths", "40MHz,80+80MHz", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.SupportedOperatingChannelBandwidths", "40MHz,80+80MHz", "xsd:string");

	/*
	 * Validate list int parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported", "-5,-3,99,120", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported", "-1,9,990", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported", "-1,9,100", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.TransmitPowerSupported", "-1,9,100", "xsd:string");

	/*
	 * Validate list unsignedInt parameters
	 */

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration", "8,1,2,3", NULL);
	assert_int_equal(fault, FAULT_9007);

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration", "1,2,3,4,5,6,7,8", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration", "0,1,2,3,4,5,6,7", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to true: name, type, value
	validate_parameter(ctx, "Device.X_IOPSYS_EU_TEST.1.PriorityRegeneration", "0,1,2,3,4,5,6,7", "xsd:string");
}

static void test_api_bbfdm_add_del_standard_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.Users.User.", "1", NULL);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.Users.User.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "2");

	// delete object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.Users.User.2.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.Users.User.2.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.Users.User.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting all instances ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.Users.User.1.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_add_del_json_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.X_IOPSYS_EU_Dropbear.", "1", NULL);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.X_IOPSYS_EU_Dropbear.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "2");

	// delete object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.X_IOPSYS_EU_Dropbear.2.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.X_IOPSYS_EU_Dropbear.2.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.X_IOPSYS_EU_Dropbear.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting all instances ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.X_IOPSYS_EU_Dropbear.1.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_add_del_json_v1_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.UCI_TEST_V1.OWSD.", "1", NULL);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.UCI_TEST_V1.OWSD.", "test", NULL);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "4");

	// delete object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.UCI_TEST_V1.OWSD.2.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.UCI_TEST_V1.OWSD.2.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.UCI_TEST_V1.OWSD.", "test", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting all instances ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.UCI_TEST_V1.OWSD.1.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);

	// add object ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.UBUS_TEST_V1.Interface.", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.UBUS_TEST_V1.Interface.", "test", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_add_del_library_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.WiFi.SSID.", "1", NULL);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.WiFi.SSID.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "4");

	// delete object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.WiFi.SSID.2.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.X_IOPSYS_EU_Dropbear.2.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.WiFi.SSID.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting all instances ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.WiFi.SSID.1.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_valid_standard_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	char *input = "{\"Host\":\"iopsys.eu\",\"NumberOfRepetitions\":\"1\",\"Timeout\":\"5000\",\"DataBlockSize\":\"64\"}";
	struct dm_parameter *n;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_OPERATE, "Device.IP.Diagnostics.IPPing()", input, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {
		if (DM_STRCMP(n->name, "Status") == 0) {
			assert_string_equal(n->data, "Complete");
			assert_string_equal(n->type, "xsd:string");
		} else if (DM_STRCMP(n->name, "IPAddressUsed") == 0) {
			assert_string_equal(n->data, "");
			assert_string_equal(n->type, "xsd:string");
		} else if (DM_STRCMP(n->name, "SuccessCount") == 0) {
			assert_string_equal(n->data, "1");
			assert_string_equal(n->type, "xsd:unsignedInt");
		} else if (DM_STRCMP(n->name, "FailureCount") == 0) {
			assert_string_equal(n->data, "0");
			assert_string_equal(n->type, "xsd:unsignedInt");
		} else {
			assert_string_not_equal(n->data, "0");
			assert_string_equal(n->type, "xsd:unsignedInt");
		}
	}
}

static void test_api_bbfdm_valid_standard_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, i = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_OPERATE, "Device.", NULL, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		if (DM_STRCMP(n->name, "Device.FactoryReset()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "sync");
			assert_null(n->data);
		}

		if (DM_STRCMP(n->name, "Device.DeviceInfo.VendorLogFile.{i}.Upload()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "async");
			operation_args *args = (operation_args *)n->data;
			assert_non_null(args);
			const char **command_in = args->in;
			const char **command_out = args->out;
			assert_non_null(command_in);
			assert_null(command_out);

			for (i = 0; command_in[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_in[i], "URL");
					break;
				case 1:
					assert_string_equal(command_in[i], "Username");
					break;
				case 2:
					assert_string_equal(command_in[i], "Password");
					break;
				}
			}
			assert_int_equal(i, 3);
		}

		if (DM_STRCMP(n->name, "Device.WiFi.NeighboringWiFiDiagnostic()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "async");
			operation_args *args = (operation_args *)n->data;
			assert_non_null(args);
			const char **command_in = args->in;
			const char **command_out = args->out;
			assert_null(command_in);
			assert_non_null(command_out);

			for (i = 0; command_out[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_out[i], "Status");
					break;
				case 1:
					assert_string_equal(command_out[i], "Result.{i}.Radio");
					break;
				case 2:
					assert_string_equal(command_out[i], "Result.{i}.SSID");
					break;
				}
			}
			assert_int_equal(i, 18);
		}
	}
}

static void test_api_bbfdm_valid_library_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	char *input = "{\"Host\":\"iopsys.eu\"}";
	struct dm_parameter *n;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_OPERATE, "Device.X_IOPSYS_EU_PingTEST.Run()", input, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {
		assert_string_not_equal(n->data, "0");
		assert_string_equal(n->type, "xsd:unsignedInt");
	}}

static void test_api_bbfdm_valid_library_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, i = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_OPERATE, "Device.", NULL, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_Reboot()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "sync");
			assert_null(n->data);
		}

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_PingTEST.Run()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "async");
			operation_args *args = (operation_args *)n->data;
			assert_non_null(args);
			const char **command_in = args->in;
			const char **command_out = args->out;
			assert_non_null(command_in);
			assert_non_null(command_out);

			for (i = 0; command_in[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_in[i], "Host");
					break;
				}
			}
			assert_int_equal(i, 1);

			for (i = 0; command_out[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_out[i], "AverageResponseTime");
					break;
				case 1:
					assert_string_equal(command_out[i], "MinimumResponseTime");
					break;
				case 2:
					assert_string_equal(command_out[i], "MaximumResponseTime");
					break;
				}
			}
			assert_int_equal(i, 3);
		}
	}
}

static void test_api_bbfdm_valid_json_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_OPERATE, "Device.X_IOPSYS_EU_TEST.1.Status()", NULL, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {
		assert_string_equal(n->name, "Result");
		assert_string_equal(n->data, "Success");
		assert_string_equal(n->type, "xsd:string");
	}
}

static void test_api_bbfdm_valid_json_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, i = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_OPERATE, "Device.", NULL, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_TEST.{i}.Status()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "async");
			operation_args *args = (operation_args *)n->data;
			assert_non_null(args);
			const char **command_in = args->in;
			const char **command_out = args->out;
			assert_non_null(command_in);
			assert_non_null(command_out);

			for (i = 0; command_in[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_in[i], "Option");
					break;
				}
			}
			assert_int_equal(i, 1);

			for (i = 0; command_out[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_out[i], "Result");
					break;
				}
			}
			assert_int_equal(i, 1);
		}
	}
}

static void test_api_bbfdm_valid_json_v1_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_OPERATE, "Device.UBUS_TEST_V1.Interface.3.Status()", NULL, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {
		assert_string_equal(n->name, "Result");
		assert_string_equal(n->data, "Success");
		assert_string_equal(n->type, "xsd:string");
	}
}

static void test_api_bbfdm_valid_json_v1_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, i = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_OPERATE, "Device.", NULL, NULL);
	assert_int_equal(fault, CMD_SUCCESS);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		if (DM_STRCMP(n->name, "Device.UBUS_TEST_V1.Interface.{i}.Status()") == 0) {
			assert_string_equal(n->type, "xsd:command");
			assert_string_equal(n->additional_data, "async");
			operation_args *args = (operation_args *)n->data;
			assert_non_null(args);
			const char **command_in = args->in;
			const char **command_out = args->out;
			assert_non_null(command_in);
			assert_non_null(command_out);

			for (i = 0; command_in[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_in[i], "Option");
					break;
				case 1:
					assert_string_equal(command_out[i], "Value");
					break;
				}
			}
			assert_int_equal(i, 2);

			for (i = 0; command_out[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(command_out[i], "Result");
					break;
				case 1:
					assert_string_equal(command_out[i], "Value");
					break;
				}
			}
			assert_int_equal(i, 2);
		}
	}
}

static void test_api_bbfdm_valid_library_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, idx = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_EVENT, NULL, NULL, NULL);
	assert_int_equal(fault, 0);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_WakeUp!") == 0) {
			assert_string_equal(n->type, "xsd:event");
			assert_null(n->data);
		}

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_Boot!") == 0) {
			assert_string_equal(n->type, "xsd:event");
			event_args *args = (event_args *)n->data;
			assert_non_null(args);
			const char **event_param = args->param;
			assert_non_null(event_param);
			for (int i = 0; event_param[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(event_param[i], "CommandKey");
					break;
				case 1:
					assert_string_equal(event_param[i], "Cause");
					break;
				case 2:
					assert_string_equal(event_param[i], "FirmwareUpdated");
					break;
				case 3:
					assert_string_equal(event_param[i], "ParameterMap");
					break;
				}
			}
		}

		idx++;
	}

	assert_int_equal(idx, 8);
}

static void test_api_bbfdm_valid_json_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, idx = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_EVENT, NULL, NULL, NULL);
	assert_int_equal(fault, 0);

	list_for_each_entry(n, &ctx->list_parameter, list) {

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_TEST.{i}.Periodic!") == 0) {
			assert_string_equal(n->type, "xsd:event");
			assert_null(n->data);
		}

		if (DM_STRCMP(n->name, "Device.X_IOPSYS_EU_TEST.{i}.Push!") == 0) {
			assert_string_equal(n->type, "xsd:event");
			event_args *args = (event_args *)n->data;
			assert_non_null(args);
			const char **event_param = args->param;
			assert_non_null(event_param);
			for (int i = 0; event_param[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(event_param[i], "Data");
					break;
				case 1:
					assert_string_equal(event_param[i], "Status");
					break;
				}
			}
		}

		idx++;
	}

	assert_int_equal(idx, 8);
}

static void test_api_bbfdm_valid_json_v1_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *n;
	int fault = 0, idx = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_EVENT, NULL, NULL, NULL);
	assert_int_equal(fault, 0);

	list_for_each_entry(n, &ctx->list_parameter, list) {
		if (DM_STRCMP(n->name, "Device.UBUS_TEST_V1.Interface.{i}.Periodic!") == 0) {
			assert_string_equal(n->type, "xsd:event");
			assert_null(n->data);
		}

		if (DM_STRCMP(n->name, "Device.UBUS_TEST_V1.Interface.{i}.Push!") == 0) {
			assert_string_equal(n->type, "xsd:event");
			event_args *args = (event_args *)n->data;
			assert_non_null(args);
			const char **event_param = args->param;
			assert_non_null(event_param);
			for (int i = 0; event_param[i] != NULL; i++) {
				switch (i) {
				case 0:
					assert_string_equal(event_param[i], "Data");
					break;
				case 1:
					assert_string_equal(event_param[i], "Status");
					break;
				case 2:
					assert_string_equal(event_param[i], "Value");
					break;
				}
			}
		}

		idx++;
	}

	assert_int_equal(idx, 8);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		// Get/Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_standard_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_json_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_json_v1_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_library_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_standard_parameter_alias, setup_alias, teardown_commit),
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

	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}


