/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Jani Juvan <jani.juvan@iopsys.eu>
 */

#ifndef __FAST_H
#define __FAST_H

#include "libbbf_api/dmcommon.h"

extern DMOBJ tFASTObj[];
extern DMLEAF tFASTParams[];
extern DMOBJ tFASTLineObj[];
extern DMLEAF tFASTLineParams[];
extern DMOBJ tFASTLineStatsObj[];
extern DMLEAF tFASTLineStatsParams[];
extern DMLEAF tFASTLineStatsTotalParams[];
extern DMLEAF tFASTLineStatsShowtimeParams[];
extern DMLEAF tFASTLineStatsLastShowtimeParams[];
extern DMLEAF tFASTLineStatsCurrentDayParams[];
extern DMLEAF tFASTLineStatsQuarterHourParams[];

#endif //__FAST_H
