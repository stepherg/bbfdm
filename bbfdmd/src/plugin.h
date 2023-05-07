/*
 * plugin.h: Plugin file bbfdmd
 *
 * Copyright (C) 2023 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#ifndef PLUGIN_H

int load_dotso_plugin(void **lib_handle, const char *file_path,
		DMOBJ **main_entry,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE **tVendorExtensionExclude);
int free_dotso_plugin(void *lib_handle);

int load_json_plugin(struct list_head *json_plugin, struct list_head *json_list, struct list_head *json_memhead, const char *file_path,
		DMOBJ **main_entry);
int free_json_plugin(void);

#endif /* PLUGIN_H */
