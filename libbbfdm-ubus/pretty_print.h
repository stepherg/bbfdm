/*
 * pretty_print.h: utils for pretty printing of results
 *
 * Copyright (C) 2020-2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#ifndef PRETTY_PRINT_H
#define PRETTY_PRINT_H

void prepare_result_blob(struct blob_buf *bb, struct list_head *pv_list);
void prepare_raw_result(struct blob_buf *bb, struct dmctx *bbf_ctx, struct list_head *rslvd);
void prepare_pretty_result(uint8_t maxdepth, struct blob_buf *bb, struct dmctx *bbf_ctx, struct list_head *rslvd);

#endif /* PRETTY_PRINT_H */
