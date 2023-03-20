#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <syslog.h>

#include <json-c/json.h>

#include "usp.h"
#include "get_helper.h"
#include "test_utils.h"

struct test_ctx {
	struct usp_context uspctx;
	struct blob_buf bb;
	struct ubus_object usp;
	struct ubus_object usp_raw;
	FILE *fp;
	struct ubus_request_data *req;
	unsigned long instance;
};

// Stub functions to override existing functionalities
void ubus_complete_deferred_request(struct ubus_context *ctx,
				    struct ubus_request_data *req, int ret)
{
}

static int group_setup(void **state)
{
	struct test_ctx *ctx = calloc(1, sizeof(struct test_ctx));

	if (!ctx)
		return -1;

	openlog("unit_test", LOG_CONS| LOG_NDELAY, LOG_LOCAL1);

	memset(&ctx->uspctx, 0, sizeof(struct usp_context));

	ubus_connect_ctx(&ctx->uspctx.ubus_ctx, NULL);

	INIT_LIST_HEAD(&ctx->uspctx.obj_list);
	INIT_LIST_HEAD(&ctx->uspctx.instances);
	INIT_LIST_HEAD(&ctx->uspctx.old_instances);

	usp_pre_init(&ctx->uspctx);

	remove("/tmp/test.log");
	ctx->usp.name = "usp";
	ctx->usp_raw.name = "usp.raw";
	memset(&ctx->bb, 0, sizeof(struct blob_buf));
	ctx->req = (struct ubus_request_data *) calloc(1, sizeof(struct ubus_request_data));
	*state = ctx;

	return 0;
}

static int setup(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;

	remove("/tmp/test.log");
	blob_buf_init(&ctx->bb, 0);

	return 0;
}

static int group_teardown(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;

	usp_cleanup(&ctx->uspctx);
	blob_buf_free(&ctx->bb);
	ubus_shutdown(&ctx->uspctx.ubus_ctx);
	free(ctx->req);
	free(ctx);
	remove("/tmp/test.log");

	return 0;
}

static void test_api_usp_get_DeviceInfo_Manufacturer(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "DeviceInfo.Manufacturer");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	//printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "fault", &tmp);
	assert_string_equal(json_object_to_json_string(tmp), "7026");

	json_object_put(jobj);
	return;
}

static void test_api_usp_raw_getm_values_Device_WiFi_SSID_Alias(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct json_object *local;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	void *paths;
	paths = blobmsg_open_array(bb, "paths");
	blobmsg_add_string(bb, NULL, "Device.WiFi.SSID.1.Alias");
	blobmsg_close_array(bb, paths);
	blobmsg_add_string(bb, "proto", GET_RAW_PROTO);

	usp_getm_values(uctx, obj, req, "getm_values", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "parameters", &tmp);

	if (json_object_get_type(tmp) == json_type_array) {
		for (int i = 0; i<json_object_array_length(tmp);++i) {
			struct json_object *val = json_object_array_get_idx(tmp, i);
			json_object_object_get_ex(val, "value", &local);
			assert_string_equal(json_object_get_string(local), "cpe-1");
		}
	}

	json_object_put(jobj);
	return;
}

static void test_api_usp_raw_resolve_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct json_object *local;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.1.Username");
	blobmsg_add_string(bb, "proto", GET_RAW_PROTO);

	usp_get_handler(uctx, obj, req, "validate", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "parameters", &tmp);
	if (json_object_get_type(tmp) == json_type_array) {
		for (int i = 0; i<json_object_array_length(tmp); ++i) {
			struct json_object *val = json_object_array_get_idx(tmp, i);
			json_object_object_get_ex(val, "parameter", &local);
			assert_string_equal(json_object_get_string(local), "Device.Users.User.1.Usernam");
		}
	}

	json_object_put(jobj);
	return;
}
static void test_api_usp_resolve_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct json_object *local;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.1.Username");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "validate", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "parameters", &tmp);
	if (json_object_get_type(tmp) == json_type_array) {
		for (int i = 0; i<json_object_array_length(tmp); ++i) {
			struct json_object *val = json_object_array_get_idx(tmp, i);
			json_object_object_get_ex(val, "parameter", &local);
			assert_string_equal(json_object_get_string(local), "Device.Users.User.1.Usernam");
		}
	}

	json_object_put(jobj);
	return;
}

static void test_api_usp_raw_getm_names_Device_WiFi_SSID_Alias(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct json_object *local;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	void *paths;
	paths = blobmsg_open_array(bb, "paths");
	blobmsg_add_string(bb, NULL, "Device.WiFi.SSID.1.Alias");
	blobmsg_close_array(bb, paths);
	blobmsg_add_string(bb, "proto", GET_RAW_PROTO);

	usp_getm_names(uctx, obj, req, "getm_names", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "parameters", &tmp);

	if (json_object_get_type(tmp) == json_type_array) {
		for (int i = 0; i<json_object_array_length(tmp); ++i) {
			struct json_object *val = json_object_array_get_idx(tmp, i);

			json_object_object_get_ex(val, "parameter", &local);
			assert_string_equal(json_object_get_string(local), "Device.WiFi.SSID.1.Alias");
			json_object_object_get_ex(val, "value", &local);
			assert_string_equal(json_object_get_string(local), "1");
		}
	}

	json_object_put(jobj);
	return;
}


static void test_api_usp_raw_dump_schema(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct ubus_context *ubus_ctx = &ctx->uspctx.ubus_ctx;
	struct ubus_object *obj = &ctx->usp_raw;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj;

	usp_list_schema(ubus_ctx, obj, req, "dump_schema", NULL);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	//printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_put(jobj);
	return;
}

static void test_api_usp_list_operate(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct ubus_context *ubus_ctx = &ctx->uspctx.ubus_ctx;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj;

	usp_list_operate(ubus_ctx, obj, req, "list_operate", NULL);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	//printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_wrong_name_Device_IP_Interface(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path","Device.IP._Interface.1.Status");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "fault", &tmp);
	assert_string_equal(json_object_to_json_string(tmp), "7026");

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_wrong_braces_Device_IP_Interface(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path","Device.IP.Interface.{Type==\"Normal\"}.Status");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "fault", &tmp);
	assert_string_equal(json_object_to_json_string(tmp), "7026");

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_wrong_exp_Device_IP_Interface(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path","Device.IP.Interface.[Type==\"Normal\"&&IPv4Address.*.AddressingType==\"Static\"].Status");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "fault", &tmp);
	assert_string_equal(json_object_to_json_string(tmp), "7011");

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_Device_IP_Interface(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.IP.Interface.[].");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "fault", &tmp);
	assert_string_equal(json_object_to_json_string(tmp), "7026");

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_search_exp_Device_WiFi_SSID(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp, *array_obj;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.WiFi.SSID.[Status==\"Up\"].Alias");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "SSID");
	if (json_object_get_type(array_obj) == json_type_array) {
		for (int i = 0; i<json_object_array_length(array_obj);++i) {
			char temp[512];
			struct json_object *array_index_obj = json_object_array_get_idx(array_obj, i);

			json_object_object_get_ex(array_index_obj, "Alias", &tmp);
			snprintf(temp, 512, "cpe-%d", i+1);
			assert_string_equal(json_object_get_string(tmp), temp);
		}
	}

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_Device_WiFi_SSID(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp, *array_obj;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.WiFi.SSID.*.Alias");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "SSID");

	if (json_object_get_type(array_obj) == json_type_array) {
		for (int i = 0; i < json_object_array_length(array_obj); ++i) {
			char temp[512];
			struct json_object *array_index_obj = json_object_array_get_idx(array_obj, i);

			json_object_object_get_ex(array_index_obj, "Alias", &tmp);
			snprintf(temp, 512, "cpe-%d", i+1);
			assert_string_equal(json_object_get_string(tmp), temp);
		}
	}

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_wrong_oper_Device_WiFi_SSID(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct ubus_request_data *req = ctx->req;
	struct json_object *jobj, *tmp;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.WiFi.SSID.[Status>Up].Alias");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "fault", &tmp);
	assert_string_equal(json_object_to_json_string(tmp), "7008");

	json_object_put(jobj);
	return;
}


static void test_api_usp_get_Device_DeviceInfo_Manufacturer(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", GET_PATH);
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "Manufacturer", &tmp);
	assert_string_equal(json_object_get_string(tmp), "iopsys");

	json_object_put(jobj);
	return;
}

static void test_api_usp_add_object_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp, *array_index_obj, *array_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_add_del_handler(uctx, obj, req, "add_object", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");
	assert_string_equal(json_object_get_string(tmp), "Device.Users.User.");
	json_object_object_get_ex(array_index_obj, "status", &tmp);
	assert_string_equal(json_object_get_string(tmp), "true");

	tmp = NULL;
	json_object_object_get_ex(array_index_obj, "instance", &tmp);
	assert_non_null(tmp);
	ctx->instance = strtoul(json_object_get_string(tmp), NULL, 10);

	assert_int_not_equal((int)ctx->instance, 0);

	json_object_put(jobj);
	return;
}

static void test_api_usp_del_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	assert_int_not_equal((int)ctx->instance, 0);

	char path[1024] = {0};
	snprintf(path, sizeof(path), "Device.Users.User.%lu.", ctx->instance);
	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_add_del_handler(uctx, obj, req, "del_object", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");
	assert_string_equal(json_object_get_string(tmp), path);

	tmp = json_object_object_get(array_index_obj, "status");
	assert_string_equal(json_object_get_string(tmp), "true");

	ctx->instance = 0;

	json_object_put(jobj);
	return;
}

static void test_api_usp_instances_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "instances", bb->head);
	jobj = json_object_from_file("/tmp/test.log");

	assert_non_null(jobj);

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");

	assert_string_equal(json_object_get_string(tmp), "Device.Users.User.1");

	json_object_put(jobj);
	return;
}

static void test_api_usp_instances_Device(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "instances", bb->head);
	jobj = json_object_from_file("/tmp/test.log");

	assert_non_null(jobj);

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);
	assert_non_null(array_index_obj);

	json_object_put(jobj);
	return;
}

static void test_api_usp_set_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	assert_int_not_equal((int)ctx->instance, 0);

	char path[1024] = {0};
	snprintf(path, sizeof(path), "Device.Users.User.%lu.Username", ctx->instance);
	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "value", "user2");

	usp_set(uctx, obj, req, "set", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	tmp = json_object_object_get(jobj, "status");
	assert_string_equal(json_object_get_string(tmp), "true");

	json_object_put(jobj);
	return;
}

static void test_api_usp_object_name_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.");
	blobmsg_add_string(bb, "proto", GET_PROTO);
	blobmsg_add_u8(bb, "next-level", true);

	usp_get_handler(uctx, obj, req, "object_names", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");
	assert_string_equal(json_object_get_string(tmp), "Device.Users.User.1.");

	json_object_put(jobj);
	return;
}

static void test_api_usp_raw_get_Device_DeviceInfo_Manufacturer(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", GET_PATH);
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");

	assert_string_equal(json_object_get_string(tmp), "Device.DeviceInfo.Manufacturer");

	tmp = json_object_object_get(array_index_obj, "value");
	assert_string_equal(json_object_get_string(tmp), "iopsys");

	json_object_put(jobj);
	return;
}


static void test_api_usp_raw_add_object_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	int trans_id;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	trans_id = transaction_start("ut", 0);
	blobmsg_add_string(bb, "path", "Device.Users.User.");
	blobmsg_add_string(bb, "proto", GET_PROTO);
	blobmsg_add_u32(bb, "transaction_id", trans_id);
	usp_raw_add_del_handler(uctx, obj, req, "add_object", bb->head);
	transaction_commit(trans_id, NULL, true);

	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	json_object_object_get_ex(array_index_obj, "status", &tmp);
	assert_string_equal(json_object_get_string(tmp), "true");

	tmp = NULL;
	json_object_object_get_ex(array_index_obj, "instance", &tmp);
	assert_non_null(tmp);
	ctx->instance = strtoul(json_object_get_string(tmp), NULL, 10);

	assert_int_not_equal((int)ctx->instance, 0);

	json_object_put(jobj);
	return;
}


static void test_api_usp_raw_del_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	int trans_id;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	assert_int_not_equal((int)ctx->instance, 0);

	char path[1024] = {0};
	snprintf(path, sizeof(path), "Device.Users.User.%lu.", ctx->instance);

	trans_id = transaction_start("ut", 0);
	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "proto", GET_PROTO);
	blobmsg_add_u32(bb, "transaction_id", trans_id);
	usp_raw_add_del_handler(uctx, obj, req, "del_object", bb->head);
	transaction_commit(trans_id, NULL, true);

	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");
	assert_string_equal(json_object_get_string(tmp), path);

	tmp = json_object_object_get(array_index_obj, "status");
	assert_string_equal(json_object_get_string(tmp), "true");

	ctx->instance = 0;

	json_object_put(jobj);
	return;
}

static void test_api_usp_raw_instances_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.");
	blobmsg_add_string(bb, "proto", GET_PROTO);

	usp_get_handler(uctx, obj, req, "instances", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");

	assert_string_equal(json_object_get_string(tmp), "Device.Users.User.1");

	json_object_put(jobj);
	return;
}

static void test_api_usp_raw_set_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct json_object *jobj, *tmp;
	struct ubus_request_data *req = ctx->req;
	int trans_id;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	assert_int_not_equal((int)ctx->instance, 0);

	char path[1024] = {0};
	snprintf(path, sizeof(path), "Device.Users.User.%lu.Username", ctx->instance);

	trans_id = transaction_start("ut", 0);
	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "value", "user3");
	blobmsg_add_u32(bb, "transaction_id", trans_id);
	usp_raw_set(uctx, obj, req, "set", bb->head);
	transaction_commit(trans_id, NULL, true);

	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	tmp = json_object_object_get(jobj, "status");
	if (tmp == NULL) {
		json_object_put(jobj);
	}
	assert_non_null(tmp);
	assert_string_equal(json_object_get_string(tmp), "true");
	json_object_put(jobj);

	return;
}

static void test_api_usp_raw_object_name_Device_Users_User(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp_raw;
	struct json_object *jobj, *tmp, *array_obj, *array_index_obj;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", "Device.Users.User.");
	blobmsg_add_string(bb, "proto", GET_PROTO);
	blobmsg_add_u8(bb, "next-level", true);

	usp_get_handler(uctx, obj, req, "object_names", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	array_obj = json_object_object_get(jobj, "parameters");
	array_index_obj = json_object_array_get_idx(array_obj, 0);

	tmp = json_object_object_get(array_index_obj, "parameter");
	assert_string_equal(json_object_get_string(tmp), "Device.Users.User.1.");

	json_object_put(jobj);
	return;
}

static void test_api_usp_get_cwmp_Device_DeviceInfo_Manufacturer(void **state)
{
	struct test_ctx *ctx = (struct test_ctx *) *state;
	struct blob_buf *bb = &ctx->bb;
	struct ubus_object *obj = &ctx->usp;
	struct json_object *jobj, *tmp;
	struct ubus_request_data *req = ctx->req;
	struct ubus_context *uctx = &ctx->uspctx.ubus_ctx;

	blobmsg_add_string(bb, "path", GET_PATH);
	blobmsg_add_string(bb, "proto", GET_CWMP_PROTO);

	usp_get_handler(uctx, obj, req, "get", bb->head);
	jobj = json_object_from_file("/tmp/test.log");
	assert_non_null(jobj);
	printf("json(%s)\n", json_object_to_json_string(jobj));

	json_object_object_get_ex(jobj, "Manufacturer", &tmp);
	assert_string_equal(json_object_get_string(tmp), "iopsys");

	json_object_put(jobj);
	return;
}

// overriding this function
int ubus_send_event(struct ubus_context *ctx, const char *id,
		    struct blob_attr *data)
{
	char *str;

	str = blobmsg_format_json(data, true);
	printf("{\"%s\": %s }", id, str);

	free(str);

	return 0;
}


int ubus_send_reply(struct ubus_context *ctx, struct ubus_request_data *req,
		    struct blob_attr *msg)
{
	char *str;
	FILE *fp;

	fp = fopen("/tmp/test.log", "w");
	if (!fp) {
		printf("failed to open file\n");
		return -1;
	}

	if (!msg) {
		fclose(fp);
		return -1;
	}

	str = blobmsg_format_json_indent(msg, true, -1);
	fprintf(fp, "%s", str);

	fclose(fp);
	free(str);
	return 0;
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		// usp object test cases
		cmocka_unit_test_setup(test_api_usp_list_operate, setup),
		cmocka_unit_test_setup(test_api_usp_get_Device_DeviceInfo_Manufacturer, setup),
		cmocka_unit_test_setup(test_api_usp_get_Device_WiFi_SSID, setup),
		cmocka_unit_test_setup(test_api_usp_get_search_exp_Device_WiFi_SSID, setup),
		cmocka_unit_test_setup(test_api_usp_instances_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_instances_Device, setup),
		cmocka_unit_test_setup(test_api_usp_resolve_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_add_object_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_set_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_del_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_object_name_Device_Users_User, setup),
		// usp.raw object test cases
		cmocka_unit_test_setup(test_api_usp_raw_dump_schema, setup),
		cmocka_unit_test_setup(test_api_usp_raw_get_Device_DeviceInfo_Manufacturer, setup),
		cmocka_unit_test_setup(test_api_usp_raw_getm_values_Device_WiFi_SSID_Alias, setup),
		cmocka_unit_test_setup(test_api_usp_raw_getm_names_Device_WiFi_SSID_Alias, setup),
		cmocka_unit_test_setup(test_api_usp_raw_instances_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_raw_resolve_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_raw_add_object_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_raw_set_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_raw_del_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_raw_object_name_Device_Users_User, setup),
		cmocka_unit_test_setup(test_api_usp_get_cwmp_Device_DeviceInfo_Manufacturer, setup),

		// -ve scenerios
		cmocka_unit_test_setup(test_api_usp_get_DeviceInfo_Manufacturer, setup),
		cmocka_unit_test_setup(test_api_usp_get_wrong_oper_Device_WiFi_SSID, setup),
		cmocka_unit_test_setup(test_api_usp_get_Device_IP_Interface, setup),
		cmocka_unit_test_setup(test_api_usp_get_wrong_exp_Device_IP_Interface, setup),
		cmocka_unit_test_setup(test_api_usp_get_wrong_braces_Device_IP_Interface, setup),
		cmocka_unit_test_setup(test_api_usp_get_wrong_name_Device_IP_Interface, setup)
	};

	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

