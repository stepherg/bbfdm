/*
 * Copyright (C) 2021 Iopsys Software Solutions AB
 *
 * Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/**
 * \file libbbf_ubus.h
 *
 * This Library provides APIs to expose the datamodel constructed with the help
 * of libbbf API over the ubus directly.
 * This library has an external dependency on libbbf_api
 */

#ifndef __LIBBBF_UBUS_H__
#define __LIBBBF_UBUS_H__

#include <libubus.h>
#include "libbbf_api/dmbbf.h"

/*********************************************************************//**
**
** dynamicdm_init
**
** This API is to register the predefined ubus methods to work on provided
** `DMOBJ` tree.
**
** NOTE: dynamicdm_free should be called to deregister and free the allocated
**       resources used in this API.
**
** \param   ctx - pre-allocated ubus context, should not be NULL
** \param   ubus_name - name of the ubus object on which pre-defined usus methods will be registered.
**                      It should not be NULL or Empty
** \param   entry - Object which points to the root node of the tree. More details available in
**                  libbbf_api documentation.
**
** \return  0 if ubus methods are registered with the given tree, -1 otherwise
**
**************************************************************************/
int dynamicdm_init(struct ubus_context *ctx, char *ubus_name, DMOBJ *entry);

/*********************************************************************//**
**
** dynamicdm_init_plugin_object
**
** This API is to register the predefined ubus methods to work on provided
** `DM_MAP_OBJ` tree.
**
** NOTE: dynamicdm_free_plugin_object should be called to deregister and free
**       the allocated resources used in this API.
**       This API is for developer purpose and can register a tree with intermediate
**       node.
**
** \param   ctx - pre-allocated ubus context, should not be NULL
** \param   ubus_name - name of the ubus object on which pre-defined usus methods will be registered.
**                      It should not be NULL or Empty
** \param   entry - Object which points to the root node of the tree. More details available in
**                  libbbf_api documentation.
**
** \return  0 if ubus methods are registered with the given tree, -1 otherwise
**
**************************************************************************/
int dynamicdm_init_plugin_object(struct ubus_context *ctx, char *ubus_name, DM_MAP_OBJ *entry);

/*********************************************************************//**
**
** dynamicdm_free
**
** This is the API responsible to deregister/remove the allocated resources
** used in dynamicdm_init
**
** NOTE: It's the responsibility of the application to call this API before
** termination in order to free the resources if dynamicdm_init has been used.
**
** \param   ctx - pre-allocated ubus context, should not be NULL
** \param   ubus_name - name of the ubus object on which pre-defined usus methods are registered.
**                      It should not be NULL or Empty
**
** \return  None
**
**************************************************************************/
void dynamicdm_free(struct ubus_context *ctx, const char *ubus_name);

/*********************************************************************//**
**
** dynamicdm_free
**
** This is the API responsible to deregister/remove the allocated resources
** used in dynamicdm_init_plugin_object
**
** NOTE: It's the responsibility of the application to call this API before
** termination in order to free the resources if dynamicdm_init_plugin_object
** has been used.
**
** \param   ctx - pre-allocated ubus context, should not be NULL
** \param   ubus_name - name of the ubus object on which pre-defined usus methods are registered.
**                      It should not be NULL or Empty
**
** \return  None
**
**************************************************************************/
void dynamicdm_free_plugin_object(struct ubus_context *ctx, const char *ubus_name);

#endif //__LIBBBF_UBUS_H__
