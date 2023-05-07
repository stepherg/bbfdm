#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libbbfdm-api/dmcommon.h>
#include <libbbfdm-api/dmmem.h>

static int setup_teardown(void **state)
{
	dm_uci_init();
	return 0;
}

static int group_teardown(void **state)
{
	dm_uci_exit();
	dmubus_free();
	dmcleanmem();
	return 0;
}

static void test_bbf_api_uci(void **state)
{
	struct uci_section *uci_s = NULL;
	struct uci_list *ulist = NULL;
	char *value = NULL;
	int uci_res = 0;

	/*
	 * Test of dmuci_get_section_type function
	 */

	// dmuci_get_section_type: test with correct config and wrong section
	uci_res = dmuci_get_section_type("cwmp", "@notifications[0]", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_section_type: test with wrong config and correct section
	uci_res = dmuci_get_section_type("tett", "@notifications[0]", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_section_type: test with correct config/section
	uci_res = dmuci_get_section_type("firewall", "@rule[0]", &value);
	assert_int_equal(uci_res, 0);
	assert_string_not_equal(value, "");

	// dmuci_get_section_type: test with correct config/section
	uci_res = dmuci_get_section_type("network", "wan", &value);
	assert_int_equal(uci_res, 0);
	assert_string_not_equal(value, "");

	/*
	 * Test of dmuci_get_option_value_string function
	 */

	// dmuci_get_option_value_string: test with correct section/option and wrong config name
	uci_res = dmuci_get_option_value_string("netwo", "lann", "vendorid", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_option_value_string: test with correct config/option and wrong section name
	uci_res = dmuci_get_option_value_string("network", "lann", "vendorid", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_option_value_string: test with correct config/section and wrong option name
	uci_res = dmuci_get_option_value_string("network", "wan", "tetst", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_option_value_string: test correct config/section/option
	uci_res = dmuci_get_option_value_string("network", "wan", "vendorid", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "eg400");

	// dmuci_get_option_value_string: test correct config/section/option
	uci_res = dmuci_get_option_value_string("dropbear", "@dropbear[0]", "Port", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "22");

	/*
	 * Test of dmuci_get_option_value_list function
	 */

	// dmuci_get_option_value_list: test with correct config/section/option
	uci_res = dmuci_get_option_value_list("systemm", "ntp", "server", &ulist);
	assert_int_equal(uci_res, -1);
	assert_null(ulist);

	// dmuci_get_option_value_list: test with correct config/section/option
	uci_res = dmuci_get_option_value_list("system", "ntpp", "server", &ulist);
	assert_int_equal(uci_res, -1);
	assert_null(ulist);

	// dmuci_get_option_value_list: test with correct config/section/option
	uci_res = dmuci_get_option_value_list("system", "ntp", "serverr", &ulist);
	assert_int_equal(uci_res, -1);
	assert_null(ulist);

	// dmuci_get_option_value_list: test with correct section/option and wrong config name
	uci_res = dmuci_get_option_value_list("system", "ntp", "server", &ulist);
	assert_int_equal(uci_res, 0);
	assert_non_null(ulist);
	value = dmuci_list_to_string(ulist, ",");
	assert_string_equal(value, "ntp1.sth.netnod.se,ntp1.gbg.netnod.se");

	/*
	 * Test of db_get_value_string function
	 */

	// db_get_value_string: test with correct section/option and wrong config name
	uci_res = db_get_value_string("devicee", "deviceinfo", "ProductClass", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// db_get_value_string: test with correct config/option and wrong section name
	uci_res = db_get_value_string("device", "deviceinfoo", "ProductClass", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// db_get_value_string: test with correct config/section and wrong option name
	uci_res = db_get_value_string("device", "deviceinfo", "ProductCla", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// db_get_value_string: test correct config/section/option
	uci_res = db_get_value_string("device", "deviceinfo", "ProductClass", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "FirstClass");

	/*
	 * Test of dmuci_get_option_value_string_varstate function
	 */

	// dmuci_get_option_value_string_varstate: test with correct section/option and wrong config name
	uci_res = dmuci_get_option_value_string_varstate("cwm", "acs", "dhcp_url", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_option_value_string_varstate: test with correct config/option and wrong section name
	uci_res = dmuci_get_option_value_string_varstate("cwmp", "acss", "dhcp_url", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_option_value_string_varstate: test with correct config/section and wrong option name
	uci_res = dmuci_get_option_value_string_varstate("cwmp", "acs", "hcp_url", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_option_value_string_varstate: test correct config/section/option
	uci_res = dmuci_get_option_value_string_varstate("cwmp", "acs", "dhcp_url", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "http://192.168.1.123:8080/openacs");

	/*
	 * Test of dmuci_add_list_value function
	 */

	// dmuci_add_list_value: test with correct config/section/option
	uci_res = dmuci_add_list_value("systemm", "ntp", "server", "ntp2.gbg.netnod.se");
	assert_int_equal(uci_res, -1);

	// dmuci_add_list_value: test with correct config/section/option
	uci_res = dmuci_add_list_value("system", "ntpp", "server", "ntp2.gbg.netnod.se");
	assert_int_equal(uci_res, -1);

	// dmuci_add_list_value: test with correct config/section/option
	uci_res = dmuci_add_list_value("system", "ntp", "server", "ntp2.gbg.netnod.se");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_commit_package("system");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_option_value_list("system", "ntp", "server", &ulist);
	assert_int_equal(uci_res, 0);
	assert_non_null(ulist);
	value = dmuci_list_to_string(ulist, ",");
	assert_string_equal(value, "ntp1.sth.netnod.se,ntp1.gbg.netnod.se,ntp2.gbg.netnod.se");

	/*
	 * Test of dmuci_del_list_value function
	 */

	// dmuci_del_list_value: test with correct config/section/option
	uci_res = dmuci_del_list_value("systemm", "ntp", "server", "ntp1.gbg.netnod.se");
	assert_int_equal(uci_res, -1);

	// dmuci_del_list_value: test with correct config/section/option
	uci_res = dmuci_del_list_value("system", "ntpp", "server", "ntp1.gbg.netnod.se");
	assert_int_equal(uci_res, -1);

	// dmuci_del_list_value: test with correct config/section/option
	uci_res = dmuci_del_list_value("system", "ntp", "server", "ntp1.gbg.netnod.se");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_commit_package("system");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_option_value_list("system", "ntp", "server", &ulist);
	assert_int_equal(uci_res, 0);
	assert_non_null(ulist);
	value = dmuci_list_to_string(ulist, ",");
	assert_string_equal(value, "ntp1.sth.netnod.se,ntp2.gbg.netnod.se");

	/*
	 * Test of dmuci_set_value function
	 */

	// dmuci_set_value: test with correct section/option and wrong config name
	uci_res = dmuci_set_value("netwo", "wan", "vendorid", "dg400prime");
	assert_int_equal(uci_res, -1);

	// dmuci_set_value: test with correct config/option and wrong section name
	uci_res = dmuci_set_value("network", "wann", "vendorid", "dg400prime");
	assert_int_equal(uci_res, -1);

	// dmuci_set_value: test correct config/section/option
	uci_res = dmuci_set_value("network", "wan", "vendorid", "dg400prime");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_commit_package("network");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_option_value_string("network", "wan", "vendorid", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "dg400prime");

	// dmuci_set_value: test correct config/section/option
	uci_res = dmuci_set_value("dropbear", "@dropbear[0]", "Port", "7845");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_commit_package("dropbear");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_option_value_string("dropbear", "@dropbear[0]", "Port", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "7845");

	/*
	 * Test of dmuci_add_section function
	 */

	// dmuci_add_section: test with only config name
	uci_res = dmuci_add_section("network", "section_test", &uci_s);
	assert_int_equal(uci_res, 0);
	assert_non_null(uci_s);
	uci_res = dmuci_commit_package("network");
	assert_int_equal(uci_res, 0);


	/*
	 * Test of dmuci_delete function
	 */

	// dmuci_delete: test with only config name
	uci_res = dmuci_delete("network", "wan", "vendorid", NULL);
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_commit_package("network");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_option_value_string("network", "wan", "vendorid", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");


	/*
	 * Test of uci_foreach_sections function
	 */

	//uci_foreach_sections: test loop objects with wrong config name
	uci_s = NULL;
	uci_foreach_sections("netwo", "interface", uci_s) {
		break;
	}
	assert_null(uci_s);

	//uci_foreach_sections: test loop objects with wrong option name
	uci_s = NULL;
	uci_foreach_sections("network", "interfa", uci_s) {
		break;
	}
	assert_null(uci_s);

	//uci_foreach_sections: test loop objects with wrong option name
	uci_s = NULL;
	uci_foreach_sections("network", "interface", uci_s) {
		break;
	}
	assert_non_null(uci_s);


	/*
	 * Test of dmuci_get_value_by_section_string function
	 */

	// dmuci_get_value_by_section_string: test with wrong option name
	uci_res = dmuci_get_value_by_section_string(uci_s, "vendorid", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_get_value_by_section_string: test with correct option name
	uci_res = dmuci_get_value_by_section_string(uci_s, "device", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "lo");

	/*
	 * Test of dmuci_set_value_by_section function
	 */

	// dmuci_set_value_by_section: test with correct option name
	uci_res = dmuci_set_value_by_section(uci_s, "reqopts", "44");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_value_by_section_string(uci_s, "reqopts", &value);
	assert_int_equal(uci_res, 0);
	assert_string_equal(value, "44");


	/*
	 * Test of dmuci_rename_section_by_section function
	 */

	// dmuci_rename_section_by_section: test
	assert_string_equal(section_name(uci_s), "loopback");
	uci_res = dmuci_rename_section_by_section(uci_s, "loop_interface");
	assert_int_equal(uci_res, 0);
	assert_string_equal(section_name(uci_s), "loop_interface");


	/*
	 * Test of dmuci_delete_by_section function
	 */

	// dmuci_delete_by_section: test with correct option name
	uci_res = dmuci_delete_by_section(uci_s, "reqopts", NULL);
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_value_by_section_string(uci_s, "reqopts", &value);
	assert_int_equal(uci_res, -1);
	assert_string_equal(value, "");

	// dmuci_delete_by_section: test without option name
	uci_res = dmuci_delete_by_section(uci_s, NULL, NULL);
	assert_int_equal(uci_res, 0);


	/*
	 * Test of dmuci_get_value_by_section_list function
	 */

	uci_s = NULL;
	uci_foreach_sections("system", "timeserver", uci_s) {
		break;
	}
	assert_non_null(uci_s);

	// dmuci_get_value_by_section_list: test with wrong option name
	uci_res = dmuci_get_value_by_section_list(uci_s, "serverer", &ulist);
	assert_int_equal(uci_res, -1);
	assert_null(ulist);

	// dmuci_get_value_by_section_list: test with correct option name
	uci_res = dmuci_get_value_by_section_list(uci_s, "server", &ulist);
	assert_int_equal(uci_res, 0);
	assert_non_null(ulist);
	value = dmuci_list_to_string(ulist, ",");
	assert_string_equal(value, "ntp1.sth.netnod.se,ntp2.gbg.netnod.se");


	/*
	 * Test of dmuci_add_list_value_by_section function
	 */

	// dmuci_add_list_value_by_section: test with correct option name
	uci_res = dmuci_add_list_value_by_section(uci_s, "server", "ntp3.gbg.netnod.se");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_value_by_section_list(uci_s, "server", &ulist);
	assert_int_equal(uci_res, 0);
	assert_non_null(ulist);
	value = dmuci_list_to_string(ulist, ",");
	assert_string_equal(value, "ntp1.sth.netnod.se,ntp2.gbg.netnod.se,ntp3.gbg.netnod.se");


	/*
	 * Test of dmuci_del_list_value_by_section function
	 */

	// dmuci_del_list_value_by_section: test with correct config/section/option
	uci_res = dmuci_del_list_value_by_section(uci_s, "server", "ntp2.gbg.netnod.se");
	assert_int_equal(uci_res, 0);
	uci_res = dmuci_get_value_by_section_list(uci_s, "server", &ulist);
	assert_int_equal(uci_res, 0);
	assert_non_null(ulist);
	value = dmuci_list_to_string(ulist, ",");
	assert_string_equal(value, "ntp1.sth.netnod.se,ntp3.gbg.netnod.se");
}

static void test_bbf_api_ubus(void **state)
{
	char ubus_name[128] = {'\0'};
	json_object *res = NULL;
	bool method_exist = false;
	int ubus_res = 0;

	/*
	 * Test of dmubus_call function
	 */

	// dmubus_call: test Wrong obj
	dmubus_call("ucii", "configs", UBUS_ARGS{0}, 0, &res);
	assert_null(res);

	// dmubus_call: test Wrong method
	dmubus_call("uci", "configss", UBUS_ARGS{0}, 0, &res);
	assert_null(res);

	// dmubus_call: test Wrong argument
	dmubus_call("uci", "get", UBUS_ARGS{{"confi", "users", String}}, 1, &res);
	assert_null(res);

	// dmubus_call: test correct obj/method
	dmubus_call("uci", "configs", UBUS_ARGS{0}, 0, &res);
	assert_non_null(res);

	// dmubus_call: test correct obj/method
	dmubus_call("uci", "get", UBUS_ARGS{{"config", "users", String}}, 1, &res);
	assert_non_null(res);

	/*
	 * Test of dmubus_call_set function
	 */

	// dmubus_call_set: test Wrong obj
	ubus_res = dmubus_call_set("ucii", "configs", UBUS_ARGS{0}, 0);
	assert_int_not_equal(ubus_res, 0);

	// dmubus_call_set: test Wrong method
	ubus_res = dmubus_call_set("uci", "configss", UBUS_ARGS{0}, 0);
	assert_int_not_equal(ubus_res, 0);

	// dmubus_call_set: test Wrong argument
	ubus_res = dmubus_call_set("uci", "get", UBUS_ARGS{{"confi", "users", String}}, 1);
	assert_int_not_equal(ubus_res, 0);

	// dmubus_call_set: test correct obj/method
	ubus_res = dmubus_call_set("uci", "configs", UBUS_ARGS{0}, 0);
	assert_int_equal(ubus_res, 0);

	// dmubus_call_set: test correct obj/method
	ubus_res = dmubus_call_set("uci", "get", UBUS_ARGS{{"config", "users", String}}, 1);
	assert_int_equal(ubus_res, 0);

	/*
	 * Test of dmubus_object_method_exists function
	 */

	// dmubus_object_method_exists: test with correct obj and wrong method
	DM_STRNCPY(ubus_name, "uci->configss", sizeof(ubus_name));
	method_exist = dmubus_object_method_exists(ubus_name);
	assert_false(method_exist);

	// dmubus_object_method_exists: test with wrong obj and correct method
	DM_STRNCPY(ubus_name, "ucii->configs", sizeof(ubus_name));
	method_exist = dmubus_object_method_exists(ubus_name);
	assert_false(method_exist);

	// dmubus_object_method_exists: test with wrong obj and without method
	DM_STRNCPY(ubus_name, "uciii", sizeof(ubus_name));
	method_exist = dmubus_object_method_exists(ubus_name);
	assert_false(method_exist);

	// dmubus_object_method_exists: test with correct obj and without method
	DM_STRNCPY(ubus_name, "uci", sizeof(ubus_name));
	method_exist = dmubus_object_method_exists(ubus_name);
	assert_true(method_exist);

	// dmubus_object_method_exists: test with correct obj and correct method
	DM_STRNCPY(ubus_name, "uci->configs", sizeof(ubus_name));
	method_exist = dmubus_object_method_exists(ubus_name);
	assert_true(method_exist);
}

static void test_bbf_api_json(void **state)
{
	json_object *wifi_status = NULL, *json_obj = NULL, *json_arr = NULL;
	char *json_value = NULL;
	int idx = 0;

	dmubus_call("wifi.ap.test2", "status", UBUS_ARGS{0}, 0, &wifi_status);
	assert_non_null(wifi_status);

	/*
	 * Test of dmjson_get_value function
	 */

	// dmjson_get_value: test wrong option
	json_value = dmjson_get_value(wifi_status, 1, "testt");
	assert_string_equal(json_value, "");

	// dmjson_get_value: test correct option
	json_value = dmjson_get_value(wifi_status, 1, "ssid");
	assert_string_equal(json_value, "iopsysWrt-44D43771B810");

	// dmjson_get_value: test correct option under object
	json_value = dmjson_get_value(wifi_status, 2, "capabilities", "dot11h");
	assert_string_equal(json_value, "false");

	/*
	 * Test of dmjson_get_obj function
	 */

	//dmjson_get_obj: test wrong option
	json_obj = dmjson_get_obj(wifi_status, 1, "testt");
	assert_null(json_obj);

	//dmjson_get_obj: test correct option
	json_obj = dmjson_get_obj(wifi_status, 1, "capabilities");
	assert_non_null(json_obj);
	json_value = dmjson_get_value(json_obj, 1, "dot11v_btm");
	assert_string_equal(json_value, "true");

	//dmjson_get_obj: test correct option under object
	json_obj = dmjson_get_obj(wifi_status, 2, "capabilities", "dot11ac");
	assert_non_null(json_obj);
	json_value = dmjson_get_value(json_obj, 1, "dot11ac_mpdu_max");
	assert_string_equal(json_value, "11454");

	/*
	 * Test of dmjson_select_obj_in_array_idx function
	 */

	//dmjson_select_obj_in_array_idx: test wrong option
	json_obj = dmjson_select_obj_in_array_idx(wifi_status, 0, 1, "test");
	assert_null(json_obj);

	//dmjson_select_obj_in_array_idx: test correct option with index 0
	json_obj = dmjson_select_obj_in_array_idx(wifi_status, 0, 1, "wmm_params");
	assert_non_null(json_obj);
	json_value = dmjson_get_value(json_obj, 1, "cwmin");
	assert_string_equal(json_value, "21");

	//dmjson_select_obj_in_array_idx: test correct option with index 3
	json_obj = dmjson_select_obj_in_array_idx(wifi_status, 3, 1, "wmm_params");
	assert_non_null(json_obj);
	json_value = dmjson_get_value(json_obj, 1, "cwmax");
	assert_string_equal(json_value, "149");

	/*
	 * Test of dmjson_get_value_array_all function
	 */

	//dmjson_get_value_array_all: test wrong option with comma separator
	json_value = dmjson_get_value_array_all(wifi_status, ",", 1, "testt");
	assert_string_equal(json_value, "");

	//dmjson_get_value_array_all: test correct option with comma separator
	json_value = dmjson_get_value_array_all(wifi_status, ",", 1, "supp_security");
	assert_string_equal(json_value, "NONE,WPA3PSK,WPA2PSK+WPA3PSK,WPA,WPA2,WPA2+WPA3");


	//dmjson_get_value_array_all: test correct option with :: separator
	json_value = dmjson_get_value_array_all(wifi_status, "::", 1, "supp_security");
	assert_string_equal(json_value, "NONE::WPA3PSK::WPA2PSK+WPA3PSK::WPA::WPA2::WPA2+WPA3");

	/*
	 * Test of dmjson_foreach_obj_in_array function
	 */

	//dmjson_foreach_obj_in_array: test loop objects
	dmjson_foreach_obj_in_array(wifi_status, json_arr, json_obj, idx, 1, "wmm_params") {

		assert_non_null(json_obj);

		json_value = dmjson_get_value(json_obj, 1, "cwmin");
		if (idx == 0)
			assert_string_equal(json_value, "21");
		else if (idx == 1)
			assert_string_equal(json_value, "3");
		else if (idx == 2)
			assert_string_equal(json_value, "78");
		else
			assert_string_equal(json_value, "66");

		idx++;
	}
	assert_int_equal(idx, 4);

	/*
	 * Test of dmjson_foreach_value_in_array function
	 */

	//dmjson_foreach_value_in_array: test loop values
	idx = 0;
	dmjson_foreach_value_in_array(wifi_status, json_arr, json_value, idx, 1, "supp_security") {

		assert_non_null(json_value);

		if (idx == 0)
			assert_string_equal(json_value, "NONE");
		else if (idx == 1)
			assert_string_equal(json_value, "WPA3PSK");
		else if (idx == 2)
			assert_string_equal(json_value, "WPA2PSK+WPA3PSK");
		else if (idx == 3)
			assert_string_equal(json_value, "WPA");
		else if (idx == 4)
			assert_string_equal(json_value, "WPA2");
		else
			assert_string_equal(json_value, "WPA2+WPA3");

		idx++;
	}
	assert_int_equal(idx, 6);
}

static void test_bbf_api_validate(void **state)
{
	int validate = 0;

	/*
	 * Test of dm_validate_string function
	 */

	// dm_validate_string: test with wrong min value
	validate = dm_validate_string("test", 5, 8, NULL, NULL);
	assert_int_equal(validate, -1);

	// dm_validate_string: test with wrong max value
	validate = dm_validate_string("test", -1, 2, NULL, NULL);
	assert_int_equal(validate, -1);

	// dm_validate_string: test with wrong enumaration value
	validate = dm_validate_string("test", -1, -1, DiagnosticsState, NULL);
	assert_int_equal(validate, -1);

	// dm_validate_string: test with wrong pattern value
	validate = dm_validate_string("test", -1, -1, NULL, IPv4Address);
	assert_int_equal(validate, -1);

	// dm_validate_string: test with correct min and max value
	validate = dm_validate_string("bbftest", 5, 8, NULL, NULL);
	assert_int_equal(validate, 0);

	// dm_validate_string: test with correct enumaration value
	validate = dm_validate_string("Requested", -1, -1, DiagnosticsState, NULL);
	assert_int_equal(validate, 0);

	// dm_validate_string: test with correct pattern value
	validate = dm_validate_string("10.10.9.80", -1, -1, NULL, IPv4Address);
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_boolean function
	 */

	// dm_validate_boolean: test with wrong value
	validate = dm_validate_boolean("test");
	assert_int_equal(validate, -1);

	// dm_validate_boolean: test with correct value
	validate = dm_validate_boolean("true");
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_unsignedInt function
	 */

	// dm_validate_unsignedInt: test with wrong value
	validate = dm_validate_unsignedInt("12t", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedInt: test with wrong min value
	validate = dm_validate_unsignedInt("1", RANGE_ARGS{{"12",NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedInt: test with wrong max value
	validate = dm_validate_unsignedInt("112", RANGE_ARGS{{NULL,"50"}}, 1);
	assert_int_equal(validate, -1);


	// dm_validate_unsignedInt: test without min/max value
	validate = dm_validate_unsignedInt("112", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_unsignedInt: test with correct min/max value
	validate = dm_validate_unsignedInt("112", RANGE_ARGS{{"10","1000"}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_unsignedInt: test with multi range and wrong value
	validate = dm_validate_unsignedInt("5420", RANGE_ARGS{{"10","1000"},{"11200","45000"}}, 2);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedInt: test with multi range and correct value
	validate = dm_validate_unsignedInt("50", RANGE_ARGS{{"10","1000"},{"11200","45000"}}, 2);
	assert_int_equal(validate, 0);

	// dm_validate_unsignedInt: test with wrong value
	validate = dm_validate_unsignedInt("112", RANGE_ARGS{{"4","4"}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedInt: test with correct value
	validate = dm_validate_unsignedInt("1124", RANGE_ARGS{{"4","4"}}, 1);
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_int function
	 */

	// dm_validate_int: test with wrong value
	validate = dm_validate_int("-12t", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_int: test with wrong min value
	validate = dm_validate_int("-1", RANGE_ARGS{{"12",NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_int: test with wrong max value
	validate = dm_validate_int("-1", RANGE_ARGS{{NULL,"-5"}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_int: test without min/max value
	validate = dm_validate_int("-112", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_int: test with correct min/max value
	validate = dm_validate_int("-2", RANGE_ARGS{{"-10","1000"}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_int: test with multi range and wrong value
	validate = dm_validate_int("-2", RANGE_ARGS{{"-10","-3"},{"-1","45"}}, 2);
	assert_int_equal(validate, -1);

	// dm_validate_int: test with multi range and correct value
	validate = dm_validate_int("-7", RANGE_ARGS{{"-10","-3"},{"-1","45"}}, 2);
	assert_int_equal(validate, 0);

	/*
	 * Test of dm_validate_unsignedLong function
	 */

	// dm_validate_unsignedLong: test with wrong value
	validate = dm_validate_unsignedLong("2t", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedLong: test with wrong min value
	validate = dm_validate_unsignedLong("1", RANGE_ARGS{{"12",NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedLong: test with wrong max value
	validate = dm_validate_unsignedLong("10", RANGE_ARGS{{NULL,"5"}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedLong: test without min/max value
	validate = dm_validate_unsignedLong("112", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_unsignedLong: test with correct min/max value
	validate = dm_validate_unsignedLong("20", RANGE_ARGS{{"10","1000"}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_unsignedLong: test with multi range and wrong value
	validate = dm_validate_unsignedLong("5420", RANGE_ARGS{{"10","1000"},{"11200","45000"}}, 2);
	assert_int_equal(validate, -1);

	// dm_validate_unsignedLong: test with multi range and correct value
	validate = dm_validate_unsignedLong("15000", RANGE_ARGS{{"10","1000"},{"11200","45000"}}, 2);
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_long function
	 */

	// dm_validate_long: test with wrong value
	validate = dm_validate_long("-12t", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_long: test with wrong min value
	validate = dm_validate_long("-1", RANGE_ARGS{{"12",NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_long: test with wrong max value
	validate = dm_validate_long("-1", RANGE_ARGS{{NULL,"-5"}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_long: test without min/max value
	validate = dm_validate_long("-112", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_long: test with correct min/max value
	validate = dm_validate_long("-2", RANGE_ARGS{{"-10","1000"}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_long: test with multi range and wrong value
	validate = dm_validate_long("-2", RANGE_ARGS{{"-10","-3"},{"-1","45"}}, 2);
	assert_int_equal(validate, -1);

	// dm_validate_long: test with multi range and correct value
	validate = dm_validate_long("-7", RANGE_ARGS{{"-10","-3"},{"-1","45"}}, 2);
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_dateTime function
	 */

	// dm_validate_dateTime: test with wrong value
	validate = dm_validate_dateTime("2021-12-31T20:53:99");
	assert_int_equal(validate, -1);

	// dm_validate_dateTime: test with wrong value
	validate = dm_validate_dateTime("2021-12-31T20:53:99.12Z");
	assert_int_equal(validate, -1);

	// dm_validate_dateTime: test with wrong value
	validate = dm_validate_dateTime("2021-12-31T20:53:99+01:00Z");
	assert_int_equal(validate, -1);

	// dm_validate_dateTime: test with wrong value
	validate = dm_validate_dateTime("2021-12-31T20:53:99.12");
	assert_int_equal(validate, -1);

	// dm_validate_dateTime: test with correct value
	validate = dm_validate_dateTime("2021-12-31T20:53:01Z");
	assert_int_equal(validate, 0);

	// dm_validate_dateTime: test with correct value
	validate = dm_validate_dateTime("2021-12-31T20:53:01.125Z");
	assert_int_equal(validate, 0);

	// dm_validate_dateTime: test with correct value
	validate = dm_validate_dateTime("2021-12-31T20:53:01.125345Z");
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_hexBinary function
	 */

	// dm_validate_hexBinary: test with wrong value
	validate = dm_validate_hexBinary("-12t", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_hexBinary: test with wrong min value
	validate = dm_validate_hexBinary("123bcd", RANGE_ARGS{{"12",NULL}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_hexBinary: test with wrong max value
	validate = dm_validate_hexBinary("123bcd", RANGE_ARGS{{NULL,"4"}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_hexBinary: test with wrong value
	validate = dm_validate_hexBinary("123b4cd", RANGE_ARGS{{"3","3"}}, 1);
	assert_int_equal(validate, -1);

	// dm_validate_hexBinary: test without min/max value
	validate = dm_validate_hexBinary("123bcd", RANGE_ARGS{{NULL,NULL}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_hexBinary: test with correct min/max value
	validate = dm_validate_hexBinary("123bcd", RANGE_ARGS{{"1","8"}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_hexBinary: test with correct value
	validate = dm_validate_hexBinary("123bcd", RANGE_ARGS{{"3","3"}}, 1);
	assert_int_equal(validate, 0);

	// dm_validate_hexBinary: test with multi range and wrong value
	validate = dm_validate_hexBinary("123bc", RANGE_ARGS{{"3","3"},{"5","5"}}, 2);
	assert_int_equal(validate, -1);

	// dm_validate_hexBinary: test with multi range and correct value
	validate = dm_validate_hexBinary("123bcd", RANGE_ARGS{{"3","3"},{"5","5"}}, 2);
	assert_int_equal(validate, 0);

	// dm_validate_hexBinary: test with multi range and correct value
	validate = dm_validate_hexBinary("12345abcde", RANGE_ARGS{{"3","3"},{"5","5"}}, 2);
	assert_int_equal(validate, 0);


	/*
	 * Test of dm_validate_string_list function
	 */

	// dm_validate_string_list: test with wrong min_item value
	validate = dm_validate_string_list("test", 2, -1, -1, -1, -1, NULL, NULL);
	assert_int_equal(validate, -1);

	// dm_validate_string_list: test with wrong max_item value
	validate = dm_validate_string_list("test1,test2,test3", -1, 2, -1, -1, -1, NULL, NULL);
	assert_int_equal(validate, -1);

	// dm_validate_string_list: test with wrong max_size value
	validate = dm_validate_string_list("test1,test2,test3", -1, -1, 10, -1, -1, NULL, NULL);
	assert_int_equal(validate, -1);

	// dm_validate_string_list: test with correct min and max item/size value
	validate = dm_validate_string_list("bbftest", -1, -1, -1, -1, -1, NULL, NULL);
	assert_int_equal(validate, 0);

	// dm_validate_string_list: test with correct min and max item/size value
	validate = dm_validate_string_list("test1,test2,test3", 2, 4, 20, -1, -1, NULL, NULL);
	assert_int_equal(validate, 0);
}

static void test_bbf_api_common(void **state)
{
	char buf[256] = {0};
	char *value = NULL;
	bool exist = false;

	/*
	 * Test of folder_exists function
	 */

	// folder_exists: test with wrong file name
	exist = folder_exists("/proc/sys/net/ipv");
	assert_false(exist);

	// folder_exists: test with correct file name
	exist = folder_exists("/proc/sys/net/ipv4");
	assert_true(exist);


	/*
	 * Test of file_exists function
	 */

	// file_exists: test with wrong min value
	exist = file_exists("/etc/passw");
	assert_false(exist);

	// file_exists: test with correct file name
	exist = file_exists("/etc/passwd");
	assert_true(exist);


	/*
	 * Test of is_regular_file function
	 */

	// is_regular_file: test with wrong file name
	exist = is_regular_file("/proc/net/rout");
	assert_false(exist);

	// is_regular_file: test with correct file name
	exist = is_regular_file("/proc/net/route");
	assert_true(exist);


	/*
	 * Test of replace_char function
	 */

	// replace_char: test
	DM_STRNCPY(buf, "/path/to/file", sizeof(buf));
	value = replace_char(buf, '/', ' ');
	assert_string_equal(value, " path to file");

	// replace_char: test
	DM_STRNCPY(buf, "Device.ATM.Link.{i}.Enable", sizeof(buf));
	value = replace_char(buf, '.', '/');
	assert_string_equal(value, "Device/ATM/Link/{i}/Enable");


	/*
	 * Test of replace_str function
	 */

	// replace_str: test
	DM_STRNCPY(buf, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.", sizeof(buf));
	value = replace_str(buf, ".{i}.", ".");
	assert_string_equal(value, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.IPv4Address.");
	FREE(value);

	// replace_str: test
	DM_STRNCPY(buf, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.", sizeof(buf));
	value = replace_str(buf, ".{i}.", ".*.");
	assert_string_equal(value, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.*.IPv4Address.*.");
	FREE(value);


	/*
	 * Test of base64_decode function
	 */

	// base64_decode: test
	value = base64_decode("YmJmX3VuaXRfdGVzdA");
	assert_string_equal(value, "bbf_unit_test");


	/*
	 * Test of convert_string_to_hex function
	 */

	// convert_string_to_hex: test
	convert_string_to_hex("bbf_unit_test", buf, sizeof(buf));
	assert_string_equal(buf, "6262665F756E69745F74657374");


	/*
	 * Test of convert_hex_to_string function
	 */

	// convert_hex_to_string: test
	convert_hex_to_string("6262665f756e69745f74657374", buf, sizeof(buf));
	assert_string_equal(buf, "bbf_unit_test");


	/*
	 * Test of hex_to_ip function
	 */

	// hex_to_ip: test
	hex_to_ip("0000FEA9", buf, sizeof(buf));
	assert_string_equal(buf, "169.254.0.0");

}

int main(void)
{
	const struct CMUnitTest tests[] = {
		// UCI functions test cases
		cmocka_unit_test(test_bbf_api_uci),

		// Ubus functions test cases
		cmocka_unit_test(test_bbf_api_ubus),

		// JSON functions test cases
		cmocka_unit_test(test_bbf_api_json),

		// Validate functions test cases
		cmocka_unit_test(test_bbf_api_validate),

		// Common functions test cases
		cmocka_unit_test(test_bbf_api_common),
	};

	return cmocka_run_group_tests(tests, setup_teardown, group_teardown);
}
