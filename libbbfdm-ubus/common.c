/*
 * common.c: Common utils of Get/Set/Operate handlers
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "common.h"
#include "get_helper.h"

bool validate_msglen(bbfdm_data_t *data)
{
	size_t data_len = blob_pad_len(data->bbf_ctx.bb.head);

	if (data_len >= DEF_IPC_DATA_LEN) {
		BBF_ERR("Blob exceed max len(%d), data len(%zd)", DEF_IPC_DATA_LEN, data_len);
		blob_buf_free(&data->bbf_ctx.bb);
		blob_buf_init(&data->bbf_ctx.bb, 0);
		fill_err_code_table(data, FAULT_9002);
		return false;
	}

	return true;
}

// glibc doesn't guarantee a 0 termianted string on strncpy
// strncpy with always 0 terminated string
void strncpyt(char *dst, const char *src, size_t n)
{
	if (dst == NULL || src == NULL)
		return;

        if (n > 1) {
                strncpy(dst, src, n - 1);
                dst[n - 1] = 0;
        }
}
