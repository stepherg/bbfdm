#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libbbf_api/dmuci.h>
#include <libbbfdm/dmentry.h>

static int setup(void **state)
{
	struct dmctx *ctx = calloc(1, sizeof(struct dmctx));
	if (!ctx)
		return -1;

	dm_ctx_init(ctx, INSTANCE_MODE_NUMBER);
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
	free_dynamic_arrays();
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
}

static void test_api_bbfdm_get_set_library_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.ManagementServer.EnableCWMP", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter : name, type, value
	validate_parameter(ctx, "Device.ManagementServer.EnableCWMP", "1", "xsd:boolean");

	// Set Wrong Value ==> expected "9007" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.ManagementServer.EnableCWMP", "truee", NULL);
	assert_int_equal(fault, FAULT_9007);

	// set value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.ManagementServer.EnableCWMP", "0", NULL);
	assert_int_equal(fault, 0);

	// apply value ==> expected "0" error
	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key");
	assert_int_equal(fault, 0);

	// get value ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.ManagementServer.EnableCWMP", NULL, NULL);
	assert_int_equal(fault, 0);

	// validate parameter after setting to 0: name, type, value
	validate_parameter(ctx, "Device.ManagementServer.EnableCWMP", "0", "xsd:boolean");
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

static void test_api_bbfdm_add_del_library_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	// Get name object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.ManagementServer.InformParameter.", "1", NULL);
	assert_int_equal(fault, 0);

	// add object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.ManagementServer.InformParameter.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// check the new instance
	assert_non_null(ctx->addobj_instance);
	assert_string_equal(ctx->addobj_instance, "3");

	// delete object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.ManagementServer.InformParameter.2.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting instance 2 ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.X_IOPSYS_EU_Dropbear.2.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);

	// delete all object ==> expected "0" error
	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.ManagementServer.InformParameter.", "test_key", NULL);
	assert_int_equal(fault, 0);

	// Get name object after deleting all instances ==> expected "9005" error
	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.ManagementServer.InformParameter.1.", "1", NULL);
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
		if (strcmp(n->name, "SuccessCount") == 0) {
			assert_string_equal(n->data, "1");
		} else if (strcmp(n->name, "FailureCount") == 0) {
			assert_string_equal(n->data, "0");
		} else {
			assert_string_not_equal(n->data, "0");
		}
		assert_string_equal(n->type, "xsd:unsignedInt");
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
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		// Get/Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_standard_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_json_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_set_library_parameter, setup, teardown_commit),

		// Add/Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_standard_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_json_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_del_library_object, setup, teardown_commit),

		// Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_standard_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_library_operate, setup, teardown_commit),
	};

	return cmocka_run_group_tests(tests, NULL, group_teardown);
}


