/*
 * Copyright (c) 2006, Chips & Media.  All rights reserved.
 *
 * Copyright (C) 2012-2013 Freescale Semiconductor, Inc.
 */

/* The following programs are the sole property of Freescale Semiconductor Inc.,
 * and contain its proprietary and confidential information. */

/*!
 * @file vpu_debug.c
 *
 * @brief This file implements VPU debug functions
 *
 * @ingroup VPU
 */

#include <stdio.h>
#include "vpu_lib.h"
#include "vpu_io.h"
#include "vpu_debug.h"

void dump_regs(Uint32 base, int cnt)
{
	int i;

	if (vpu_lib_dbg_level >= 6) {
		for (i=0; i<cnt; i++) {
			if ((i%8)==0)
				printf("\n 0x%08lx:   ", base+i*4);
			printf("0x%lx, ", VpuReadReg(base+i*4));
		}
		printf("\n");
	}
}

