/*
 * Copyright (C) 2022 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 */

#include "gatewayinfo.h"
#include "dmbbfcommon.h"

enum gateway_param {
	E_OUI,
	E_SERIAL,
	E_CLASS
};

static void get_gateway_params(int param, char *dst, int size)
{
	char *interface = NULL, *vivso = NULL, search[3] = {0};
	json_object *res = NULL;

	if (dst == NULL)
		return;

	switch (param) {
	case E_OUI:
		if (2 != snprintf(search, sizeof(search), "4="))
			return;

		break;
	case E_SERIAL:
		if (2 != snprintf(search, sizeof(search), "5="))
			return;

		break;
	case E_CLASS:
		if (2 != snprintf(search, sizeof(search), "6="))
			return;

		break;
	default:
		return;
	}


	dmuci_get_option_value_string("cwmp", "cpe", "default_wan_interface", &interface);
	if (DM_STRLEN(interface) == 0)
		return;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	if (!res)
		return;

	vivso = dmjson_get_value(res, 2, "data", "vivsoinf");
	int len = DM_STRLEN(vivso);
	if (len == 0)
		return;

	char value[len + 1];
	memset(value, 0, sizeof(value));
	snprintf(value, len+1, "%s", vivso);

	char *temp = strtok(value, ",");
	while (temp) {
		if (DM_STRNCMP(temp, search, 2) != 0) {
			temp = strtok(NULL, ",");
			continue;
		}

		temp = temp + 2;
		snprintf(dst, size, "%s", temp);
		return;
	}

	return;
}

static int get_manufacturer_oui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char oui[7] = {0};

	get_gateway_params(E_OUI, oui, sizeof(oui));
	*value = dmstrdup(oui);

	return 0;
}

static int get_product_class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char class[65] = {0};

	get_gateway_params(E_CLASS, class, sizeof(class));
	*value = dmstrdup(class);

	return 0;
}

static int get_serial_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char serial[65] = {0};

	get_gateway_params(E_SERIAL, serial, sizeof(serial));
	*value = dmstrdup(serial);

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.GatewayInfo. *** */
DMLEAF tGatewayInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_manufacturer_oui, NULL, BBFDM_CWMP, "2.0"},
{"ProductClass", &DMREAD, DMT_STRING, get_product_class, NULL, BBFDM_CWMP, "2.0"},
{"SerialNumber", &DMREAD, DMT_STRING, get_serial_number, NULL, BBFDM_CWMP, "2.0"},
{0}
};

