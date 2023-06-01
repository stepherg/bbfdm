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

static int get_manufacturer_oui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_varstate("icwmp", "gatewayinfo", "oui", value);
	if (*value[0] == '\0') {
		dmuci_get_option_value_string("cwmp", "cpe", "manufacturer_oui", value);
		if (*value[0] == '\0')
			db_get_value_string("device", "deviceinfo", "ManufacturerOUI", value);
	}

	return 0;
}

static int get_product_class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_varstate("icwmp", "gatewayinfo", "class", value);
	if (*value[0] == '\0') {
		dmuci_get_option_value_string("cwmp", "cpe", "product_class", value);
		if (*value[0] == '\0')
			db_get_value_string("device", "deviceinfo", "ProductClass", value);
	}

	return 0;
}

static int get_serial_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_varstate("icwmp", "gatewayinfo", "serial", value);
	if (*value[0] == '\0') {
		dmuci_get_option_value_string("cwmp", "cpe", "serial_number", value);
		if (*value[0] == '\0')
			db_get_value_string("device", "deviceinfo", "SerialNumber", value);
	}

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

