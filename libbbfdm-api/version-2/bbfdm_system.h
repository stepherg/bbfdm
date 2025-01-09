/*
 * Copyright (C) 2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#ifndef __BBFDM_SYSTEM_H
#define __BBFDM_SYSTEM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check if a folder exists at the given path.
 *
 * This function verifies the existence of a folder at the specified path.
 *
 * @param[in] path Path to the folder.
 * @return true if the folder exists, false otherwise.
 */
bool bbfdm_folder_exists(const char *path);

/**
 * @brief Check if a file exists at the given path.
 *
 * This function verifies the existence of a file at the specified path.
 *
 * @param[in] path Path to the file.
 * @return true if the file exists, false otherwise.
 */
bool bbfdm_file_exists(const char *path);

/**
 * @brief Check if a file is a regular file.
 *
 * This function determines whether the file at the specified path is a regular file.
 *
 * @param[in] path Path to the file.
 * @return true if the file is a regular file, false otherwise.
 */
bool bbfdm_is_regular_file(const char *path);

/**
 * @brief Create an empty file at the specified path.
 *
 * This function creates an empty file if it does not already exist. If the file already exists, it skips creation.
 *
 * @param[in] path Path to the file.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_create_empty_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif //__BBFDM_SYSTEM_H

