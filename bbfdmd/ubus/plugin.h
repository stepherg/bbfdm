/*
 * plugin.h: Plugin file bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
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
