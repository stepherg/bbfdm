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

#ifndef BBFDMD_PRETTY_PRINT_H
#define BBFDMD_PRETTY_PRINT_H

void prepare_pretty_response(const char *path, struct blob_attr *msg, struct blob_buf *bb_pretty);

#endif /* BBFDMD_PRETTY_PRINT_H */
