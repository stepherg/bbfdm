/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicereservedports.h"
#include "common.h"

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_reserved_port_range(char **value)
{
	char *start = NULL, *end = NULL;

	dmuci_get_option_value_string("asterisk", "sip_options", "rtpstart", &start);
	dmuci_get_option_value_string("asterisk", "sip_options", "rtpend", &end);
	if (start && *start && end && *end) {
		dmasprintf(value, "%s-%s", start, end);
		dmfree(start);
		dmfree(end);
	}

	return 0;
}

/*#Device.Services.VoiceService.{i}.ReservedPorts.WANPortRange!UCI:asterisk/sip_advanced,sip_options/rtpstart*/
static int get_ServicesVoiceServiceReservedPorts_WANPortRange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_reserved_port_range(value);
}

/*#Device.Services.VoiceService.{i}.ReservedPorts.LANPortRange!UCI:asterisk/sip_advanced,sip_options/rtpend*/
static int get_ServicesVoiceServiceReservedPorts_LANPortRange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_reserved_port_range(value);
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.ReservedPorts. *** */
DMLEAF tServicesVoiceServiceReservedPortsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"WANPortRange", &DMREAD, DMT_STRING, get_ServicesVoiceServiceReservedPorts_WANPortRange, NULL, BBFDM_BOTH},
{"LANPortRange", &DMREAD, DMT_STRING, get_ServicesVoiceServiceReservedPorts_LANPortRange, NULL, BBFDM_BOTH},
{0}
};

