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

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

bool bbfdm_folder_exists(const char *path)
{
	struct stat buffer;

	if (!path)
		return false;

	return stat(path, &buffer) == 0 && S_ISDIR(buffer.st_mode);
}

bool bbfdm_file_exists(const char *path)
{
	struct stat buffer;

	if (!path)
		return false;

	return stat(path, &buffer) == 0;
}

bool bbfdm_is_regular_file(const char *path)
{
	struct stat buffer;

	if (!path)
		return false;

	return stat(path, &buffer) == 0 && S_ISREG(buffer.st_mode);
}

int bbfdm_create_empty_file(const char *path)
{
	if (!path)
		return -1;

	// Skip creating the file if it already exists
	if (bbfdm_file_exists(path))
		return 0;

	FILE *fp = fopen(path, "w");
	if (fp == NULL)
		return -1;

	fclose(fp);
	return 0;
}
