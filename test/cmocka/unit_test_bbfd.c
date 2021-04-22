#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libbbf_api/dmuci.h>
#include <libbbfdm/dmentry.h>

#define DROPBEAR_FILE_PATH "/builds/iopsys/bbf/test/files/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json"
#define DROPBEAR_JSON_PATH "/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json"
#define LIBBBF_TEST_PATH "/builds/iopsys/bbf/test/bbf_test/libbbf_test.so"
#define LIBBBF_TEST_BBFDM_PATH "/usr/lib/bbfdm/libbbf_test.so"

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

static int teardown_revert(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;

	dm_entry_revert_changes();
	dm_ctx_clean(ctx);
	free(ctx);

	return 0;
}

static int group_teardown(void **state)
{
	free_dynamic_arrays();
	return 0;
}

static void test_api_bbfdm_get_value_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.WiFi.Radio.1.Alias", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.DSLL.", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_value_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.Users.User.1.Enabl", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.", "0", NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.WiFi.Radio.1.Enable", "false", NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_dot(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NAME, ".", "0", NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.WiFii.", "0", NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_without_next_level(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.", NULL, NULL);
	assert_int_equal(fault, FAULT_9003);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_name_wrong_next_level(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NAME, "Device.WiFi.", "test", NULL);
	assert_int_equal(fault, FAULT_9003);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_notification_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NOTIFICATION, "Device.", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_notification_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NOTIFICATION, "Device.ManagementServer.ConnReqJabberID", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_notification_dot(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NOTIFICATION, ".", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_notification_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NOTIFICATION, "Device.User.", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_notification_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_NOTIFICATION, "Device.Users.User.1.Usename", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_set_value_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.Users.User.", "test", NULL);
	assert_int_equal(fault, FAULT_9005);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list != &ctx->list_fault_param);
}

static void test_api_bbfdm_set_value_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.Users.User.1.Username", "test", NULL);
	assert_int_equal(fault, 0);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list == &ctx->list_fault_param);

	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_set_value_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "", "test", NULL);
	assert_int_equal(fault, FAULT_9005);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list != &ctx->list_fault_param);
}

static void test_api_bbfdm_set_value_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.Users.User.Username", "test", NULL);
	assert_int_equal(fault, FAULT_9005);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list != &ctx->list_fault_param);
}

static void test_api_bbfdm_set_value_parameter_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.1.Status", "Enabled", NULL);
	assert_int_equal(fault, FAULT_9008);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list != &ctx->list_fault_param);
}

static void test_api_bbfdm_set_value_parameter_wrong_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.WiFi.Radio.1.Enable", "truee", NULL);
	assert_int_equal(fault, FAULT_9007);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list != &ctx->list_fault_param);
}

static void test_api_bbfdm_set_notification_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.Users.", "1", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_set_notification_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.DeviceInfo.UpTime", "2", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_set_notification_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.", "1", NULL);
	assert_int_equal(fault, FAULT_9009);
}

static void test_api_bbfdm_set_notification_root(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "", "2", NULL);
	assert_int_equal(fault, FAULT_9009);
}

static void test_api_bbfdm_set_notification_wrong_notif(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.DeviceInfo.", "12", NULL);
	assert_int_equal(fault, FAULT_9003);
}

static void test_api_bbfdm_set_notification_forced_parameter_notif(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.DeviceInfo.SoftwareVersion", "1", NULL);
	assert_int_equal(fault, FAULT_9009);
}

static void test_api_bbfdm_set_notification_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.Device.", "1", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_notification_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.Users.1.Username", "1", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_notification_parameter_in_notification(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.Users.User.1.Username", "1", "false");
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_set_notification_parameter_wrong_in_notification(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_SET_NOTIFICATION, "Device.WiFi.Radio.1.Enable", "1", "test");
	assert_int_equal(fault, FAULT_9003);
}

static void test_api_bbfdm_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.Users.User.", "test_key", NULL);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_add_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.WiFi.Users.", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_add_object_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.WiFi.Radio.", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_add_object_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.WiFi.SSID.1.", "test_key", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_delete_object_all_instances(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.Users.User.", "test_key", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_delete_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.WiFi.SSID", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_delete_object_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.Hosts.Host.", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_delete_object_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "", "test_key", NULL);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_get_list_notify(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_LIST_NOTIFY, NULL, NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_valid_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_OPERATE, "Device.DHCPv4.Client.1.Renew", NULL, NULL);
	assert_int_equal(fault, SUCCESS);
}

static void test_api_bbfdm_wrong_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_OPERATE, "Device.IP.Diagnostics.IPing", NULL, NULL);
	assert_int_equal(fault, CMD_NOT_FOUND);
}

static void test_api_bbfdm_get_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_USP_LIST_OPERATE, NULL, NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_schema(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_SCHEMA, NULL, NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_INSTANCES, "Device.", "0", NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_INSTANCES, "Device.WiFii.", "true", NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_without_next_level(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_INSTANCES, "Device.WiFi.", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);
}

static void test_api_bbfdm_get_instances_wrong_next_level(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_INSTANCES, "Device.WiFi.", "test", NULL);
	assert_int_equal(fault, FAULT_9003);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_json_get_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	/*
	 * Test of JSON Object Path
	 */
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_Dropbear.", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	dm_ctx_clean_sub(ctx);
	dm_ctx_init_sub(ctx, INSTANCE_MODE_NUMBER);

	/*
	 * Test of JSON Parameter Path
	 */
	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.UserInterface.Enable", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	dm_ctx_clean_sub(ctx);
	dm_ctx_init_sub(ctx, INSTANCE_MODE_NUMBER);

	remove(DROPBEAR_JSON_PATH);

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_Dropbear.", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_json_set_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	DMCMD("/bin/cp", 2, DROPBEAR_FILE_PATH, DROPBEAR_JSON_PATH);

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.UserInterface.Enable", "true", NULL);
	assert_int_equal(fault, 0);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list == &ctx->list_fault_param);

	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key", NULL);
	assert_int_equal(fault, 0);

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_Dropbear.1.Port", "9856", NULL);
	assert_int_equal(fault, 0);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list == &ctx->list_fault_param);

	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_json_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.X_IOPSYS_EU_Dropbear.", "test_key", NULL);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_json_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.X_IOPSYS_EU_Dropbear.1.", "test_key", NULL);
	assert_int_equal(fault, 0);

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.X_IOPSYS_EU_Dropbear.", "test_key", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_library_get_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct dm_parameter *first_entry;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_Syslog.", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	dm_ctx_clean_sub(ctx);
	dm_ctx_init_sub(ctx, INSTANCE_MODE_NUMBER);

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.ManagementServer.EnableCWMP", NULL, NULL);
	assert_int_equal(fault, 0);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list != &ctx->list_parameter);

	dm_ctx_clean_sub(ctx);
	dm_ctx_init_sub(ctx, INSTANCE_MODE_NUMBER);

	remove(LIBBBF_TEST_BBFDM_PATH);

	fault = dm_entry_param_method(ctx, CMD_GET_VALUE, "Device.X_IOPSYS_EU_Syslog.", NULL, NULL);
	assert_int_equal(fault, FAULT_9005);

	first_entry = list_first_entry(&ctx->list_parameter, struct dm_parameter, list);
	assert_true(&first_entry->list == &ctx->list_parameter);
}

static void test_api_bbfdm_library_set_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	struct param_fault *first_fault;
	int fault = 0;

	DMCMD("/bin/cp", 2, LIBBBF_TEST_PATH, LIBBBF_TEST_BBFDM_PATH);

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.ManagementServer.EnableCWMP", "true", NULL);
	assert_int_equal(fault, 0);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list == &ctx->list_fault_param);

	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key", NULL);
	assert_int_equal(fault, 0);

	fault = dm_entry_param_method(ctx, CMD_SET_VALUE, "Device.X_IOPSYS_EU_Syslog.ServerPort", "9856", NULL);
	assert_int_equal(fault, 0);

	first_fault = list_first_entry(&ctx->list_fault_param, struct param_fault, list);
	assert_true(&first_fault->list == &ctx->list_fault_param);

	fault = dm_entry_apply(ctx, CMD_SET_VALUE, "test_key", NULL);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_library_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_ADD_OBJECT, "Device.ManagementServer.InformParameter.", "test_key", NULL);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_library_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.ManagementServer.InformParameter.1.", "test_key", NULL);
	assert_int_equal(fault, 0);

	fault = dm_entry_param_method(ctx, CMD_DEL_OBJECT, "Device.ManagementServer.InformParameter.", "test_key", NULL);
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

		// Get Name method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_dot, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_wrong_object_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_without_next_level, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_name_wrong_next_level, setup, teardown_revert),

		// Get Notification method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_notification_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_notification_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_notification_dot, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_notification_wrong_object_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_notification_wrong_parameter_path, setup, teardown_revert),

		// Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_empty, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_wrong_parameter_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_non_writable, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_wrong_value, setup, teardown_revert),

		// Set Notification method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_object, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_empty, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_root, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_wrong_notif, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_forced_parameter_notif, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_wrong_object_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_wrong_parameter_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_parameter_in_notification, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_notification_parameter_wrong_in_notification, setup, teardown_revert),

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
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_instances_wrong_next_level, setup, teardown_revert),

		// Get List Notify method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_list_notify, setup, teardown_commit),

		// Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_valid_operate, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_wrong_operate, setup, teardown_commit),

		// Get List Operate method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_get_list_operate, setup, teardown_commit),

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
