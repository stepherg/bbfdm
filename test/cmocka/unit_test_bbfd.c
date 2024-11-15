#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libbbfdm-api/dmuci.h>
#include <libbbfdm-api/dmapi.h>
#include <libbbfdm-api/dmentry.h>
#include <libubox/blobmsg_json.h>

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

static int teardown_revert(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;

	bbf_entry_services(ctx->dm_type, false, true);
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

static void test_api_bbfdm_get_value_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_value_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.Alias";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_value_empty(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_value_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.DSLL.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, FAULT_9005);

	assert_int_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_value_wrong_parameter_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.Users.User.1.Enabl";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, FAULT_9005);

	assert_int_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_name_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_name_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.Verbose";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_name_dot(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = ".";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	assert_int_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_name_wrong_object_path(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WrongObjPath.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_GET_NAME);
	assert_int_equal(fault, FAULT_9005);

	assert_int_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_set_value_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	ctx->in_value = "test";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_value_parameter(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.BannerFile";
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

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.Port";
	ctx->in_value = "test";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_set_value_parameter_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.UCI_TEST_V1.OWSDNumberOfEntries";
	ctx->in_value = "5";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9008);
}

static void test_api_bbfdm_set_value_parameter_wrong_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.RootLogin";
	ctx->in_value = "truee";

	fault = bbf_entry_method(ctx, BBF_SET_VALUE);
	assert_int_equal(fault, FAULT_9007);
}

static void test_api_bbfdm_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_add_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.Users.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, FAULT_9005);

	assert_null(ctx->addobj_instance);
}

static void test_api_bbfdm_add_object_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.InterfaceStack.";

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

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_delete_object_all_instances(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_delete_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_delete_object_non_writable(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.InterfaceStack.";

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

	ctx->in_param = "Device.X_IOPSYS_EU_Reboot()";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, 0);
}

static void test_api_bbfdm_wrong_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.IP.Diagnostics.IPing()";

	fault = bbf_entry_method(ctx, BBF_OPERATE);
	assert_int_equal(fault, USP_FAULT_INVALID_PATH);
}

static void test_api_bbfdm_get_list_operate(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = false;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_list_event(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = false;
	ctx->isevent = true;
	ctx->isinfo = false;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_schema(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->dm_type = BBFDM_USP;
	ctx->nextlevel = false;
	ctx->iscommand = true;
	ctx->isevent = true;
	ctx->isinfo = true;

	fault = bbf_entry_method(ctx, BBF_SCHEMA);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_instances_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_INSTANCES);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_instances_wrong_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.WrongObj.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_INSTANCES);
	assert_int_equal(fault, FAULT_9005);

	assert_int_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_get_instances_without_next_level(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	ctx->nextlevel = false;

	fault = bbf_entry_method(ctx, BBF_INSTANCES);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_json_get_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	/*
	 * Test of JSON Object Path
	 */
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);

	bbf_ctx_clean(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE);

	/*
	 * Test of JSON Parameter Path
	 */
	ctx->in_param = "Device.X_IOPSYS_EU_Dropbear.1.Alias";
	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
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
	assert_int_equal(fault, FAULT_9005);
}

static void test_api_bbfdm_library_get_value(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.InterfaceStack.";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);

	bbf_ctx_clean(ctx);
	bbf_ctx_init(ctx, TR181_ROOT_TREE);

	ctx->in_param = "Device.RootDataModelVersion";

	fault = bbf_entry_method(ctx, BBF_GET_VALUE);
	assert_int_equal(fault, 0);

	assert_int_not_equal(blobmsg_len(ctx->bb.head), 0);
}

static void test_api_bbfdm_library_add_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_TEST.";

	fault = bbf_entry_method(ctx, BBF_ADD_OBJECT);
	assert_int_equal(fault, 0);

	assert_non_null(ctx->addobj_instance);
	assert_string_not_equal(ctx->addobj_instance, "0");
}

static void test_api_bbfdm_library_delete_object(void **state)
{
	struct dmctx *ctx = (struct dmctx *) *state;
	int fault = 0;

	ctx->in_param = "Device.X_IOPSYS_EU_TEST.2.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, 0);

	ctx->in_param = "Device.X_IOPSYS_EU_TEST.";

	fault = bbf_entry_method(ctx, BBF_DEL_OBJECT);
	assert_int_equal(fault, FAULT_9005);
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

		// Set Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_object, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter, setup, teardown_commit),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_empty, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_wrong_parameter_path, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_non_writable, setup, teardown_revert),
		cmocka_unit_test_setup_teardown(test_api_bbfdm_set_value_parameter_wrong_value, setup, teardown_revert),

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

		// JSON: Add Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_json_add_object, setup, teardown_commit),

		// JSON: Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_json_delete_object, setup, teardown_commit),

		// Library: Get Value method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_get_value, setup, teardown_commit),

		// Library: Add Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_add_object, setup, teardown_commit),

		// Library: Delete Object method test cases
		cmocka_unit_test_setup_teardown(test_api_bbfdm_library_delete_object, setup, teardown_commit),
	};

	return cmocka_run_group_tests(tests, group_init, group_teardown);
}
