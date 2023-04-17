#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libbbf_api/dmuci.h>
#include <libbbf_api/dmapi.h>
#include <libbbf_api/dmentry.h>
#include <libbbf_dm/device.h>
#include <libbbf_dm/vendor.h>

static DMOBJ *TR181_ROOT_TREE = tEntryRoot;
static DM_MAP_VENDOR *TR181_VENDOR_EXTENSION[2] = {
		tVendorExtension,
		tVendorExtensionOverwrite
};
static DM_MAP_VENDOR_EXCLUDE *TR181_VENDOR_EXTENSION_EXCLUDE = tVendorExtensionExclude;

#define DROPBEAR_FILE_PATH "../files/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json"
#define DROPBEAR_JSON_PATH "/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json"
#define LIBBBF_TEST_PATH "../bbf_test/libbbf_test.so"
#define LIBBBF_TEST_BBFDM_PATH "/usr/lib/bbfdm/libbbf_test.so"

static int setup(void **state)
{
	struct dmctx *ctx = calloc(1, sizeof(struct dmctx));
	if (!ctx)
		return -1;

	bbf_ctx_init(ctx, TR181_ROOT_TREE, TR181_VENDOR_EXTENSION, TR181_VENDOR_EXTENSION_EXCLUDE);

	*state = ctx;

	return 0;
}

static int teardown_commit(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;

	bbf_entry_restart_services(NULL, true);
	bbf_ctx_clean(ctx);
	free(ctx);

	return 0;
}

static int teardown_revert(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;

	bbf_entry_revert_changes(NULL);
	bbf_ctx_clean(ctx);
	free(ctx);

	return 0;
}

static int group_teardown(void **state)
{
	bbf_global_clean(TR181_ROOT_TREE);
	return 0;
}

static void test_api_bbfdm_get_value_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.1.Alias";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.DSLL.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.Users.User.1.Enabl";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_object_alias(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->instance_mode = INSTANCE_MODE_ALIAS;

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_parameter_alias(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.[cpe-1].Alias";
	ctx->instance_mode = INSTANCE_MODE_ALIAS;

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.1.Enable";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_dot(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = ".";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFii.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_parameter_alias(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.[cpe-1].Enable";
	ctx->instance_mode = INSTANCE_MODE_ALIAS;
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_set_value_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.";
	ctx->in_value = "test";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_value_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.1.Username";
	ctx->in_value = "test";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_set_value_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "";
	ctx->in_value = "test";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_value_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.Username";
	ctx->in_value = "test";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_value_parameter_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.1.Status";
	ctx->in_value = "Enabled";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);
}

static void test_api_bbfdm_set_value_parameter_wrong_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.1.Enable";
	ctx->in_value = "truee";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);
}

static void test_api_bbfdm_set_value_parameter_alias(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.[cpe-1].Username";
	ctx->in_value = "test";
	ctx->instance_mode = INSTANCE_MODE_ALIAS;

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_add_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Users.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_add_object_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.Radio.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_add_object_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.SSID.1.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_delete_object_all_instances(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_delete_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.SSID";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_delete_object_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Hosts.Host.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_delete_object_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_valid_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.AccessPoint.1.Security.Reset()";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, CMD_SUCCESS);
}

static void test_api_bbfdm_wrong_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.IP.Diagnostics.IPing()";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, CMD_NOT_FOUND);
}

static void test_api_bbfdm_get_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = false;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_list_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = false;
	ctx->isevent = true;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_schema(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = true;
	ctx->isinfo = true;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_INSTANCES);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFii.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_INSTANCES);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_without_next_level(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.WiFi.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_INSTANCES);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_json_get_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	/*
	 * Test of JSON Object Path
	 */
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	bbf_ctx_clean_sub(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE, TR181_VENDOR_EXTENSION, TR181_VENDOR_EXTENSION_EXCLUDE);

	/*
	 * Test of JSON Parameter Path
	 */
	ctx->in_param = "Device.UserInterface.Enable";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	bbf_ctx_clean_sub(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE, TR181_VENDOR_EXTENSION, TR181_VENDOR_EXTENSION_EXCLUDE);

	remove(DROPBEAR_JSON_PATH);

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_json_set_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	dmcmd("/bin/cp", 2, DROPBEAR_FILE_PATH, DROPBEAR_JSON_PATH);

	ctx->in_param = "Device.UserInterface.Enable";
	ctx->in_value = "true";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.Port";
	ctx->in_value = "9856";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_json_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_json_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_library_get_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Syslog.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	bbf_ctx_clean_sub(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE, TR181_VENDOR_EXTENSION, TR181_VENDOR_EXTENSION_EXCLUDE);

	ctx->in_param = "Device.WiFi.SSID.1.Enable";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	bbf_ctx_clean_sub(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE, TR181_VENDOR_EXTENSION, TR181_VENDOR_EXTENSION_EXCLUDE);

	remove(LIBBBF_TEST_BBFDM_PATH);

	ctx->in_param = "Device.X_IOPSYS_EU_Syslog.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_library_set_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	dmcmd("/bin/cp", 2, LIBBBF_TEST_PATH, LIBBBF_TEST_BBFDM_PATH);

	ctx->in_param = "Device.WiFi.SSID.1.Enable";
	ctx->in_value = "true";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);

	ctx->in_param = "Device.X_IOPSYS_EU_Syslog.ServerPort";
	ctx->in_value = "9856";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_library_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.SSID.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_library_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WiFi.SSID.1.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	ctx->in_param = "Device.WiFi.SSID.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {

		// Get Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_empty, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_wrong_object_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_wrong_parameter_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_object_alias, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_value_parameter_alias, setup, teardown_commit),

		// Get Name method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_dot, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_wrong_object_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_parameter_alias, setup, teardown_commit),

		// Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_empty, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_wrong_parameter_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_non_writable, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_wrong_value, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_alias, setup, teardown_commit),

		// Add Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_wrong_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_object_non_writable, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_add_object_empty, setup, teardown_revert),

		// Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_delete_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_delete_object_all_instances, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_delete_wrong_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_delete_object_non_writable, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_delete_object_empty, setup, teardown_revert),

		// Get Instances method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_instances_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_instances_wrong_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_instances_without_next_level, setup, teardown_revert),

		// Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_wrong_operate, setup, teardown_commit),

		// Get List Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_list_operate, setup, teardown_commit),

		// Get List Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_list_event, setup, teardown_commit),

		// Get Schema method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_schema, setup, teardown_commit),

		// JSON: Get Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_json_get_value, setup, teardown_commit),

		// JSON: Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_json_set_value, setup, teardown_commit),

		// JSON: Add Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_json_add_object, setup, teardown_commit),

		// JSON: Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_json_delete_object, setup, teardown_commit),

		// Library: Get Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_get_value, setup, teardown_commit),

		// Library: Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_set_value, setup, teardown_commit),

		// Library: Add Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_add_object, setup, teardown_commit),

		// Library: Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_delete_object, setup, teardown_commit),
	};

	return cmocka_run_group_tests(tests, NULL, group_teardown);
}
