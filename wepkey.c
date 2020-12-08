/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *    Author: MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wepkey.h"

void wepkey64(char *passphrase, char strk64[4][11])
{
	unsigned char k64[4][5];
	unsigned char pseed[4] = {0};
    unsigned int randNumber, tmp;
    int i, j;

    for(i = 0; i < strlen(passphrase); i++)
    {
        pseed[i%4] ^= (unsigned char) passphrase[i];
    }

    randNumber = pseed[0] | (pseed[1] << 8) | (pseed[2] << 16) | (pseed[3] << 24);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 5; j++)
        {
            randNumber = (randNumber * 0x343fd + 0x269ec3) & 0xffffffff;
            tmp = (randNumber >> 16) & 0xff;
            k64[i][j] = (unsigned char) tmp;
        }
		snprintf(strk64[i], sizeof(strk64[i]), "%02X%02X%02X%02X%02X", k64[i][0], k64[i][1], k64[i][2], k64[i][3], k64[i][4]);
    }
}
