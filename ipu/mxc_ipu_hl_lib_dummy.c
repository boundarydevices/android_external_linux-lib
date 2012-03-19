/*
 * Copyright 2009-2012 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 */

/*
 * The code contained herein is licensed under the GNU Lesser General
 * Public License.  You may obtain a copy of the GNU Lesser General
 * Public License Version 2.1 or later at the following locations:
 *
 * http://www.opensource.org/licenses/lgpl-license.html
 * http://www.gnu.org/copyleft/lgpl.html
 */

/*!
 * @file mxc_ipu_hl_lib.c
 *
 * @brief IPU high level library implementation
 *
 * @ingroup IPU
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/videodev2.h>
#include "mxc_ipu_hl_lib.h"

int mxc_ipu_lib_task_init(ipu_lib_input_param_t * input,
		ipu_lib_overlay_param_t * overlay,
		ipu_lib_output_param_t * output,
		int mode, ipu_lib_handle_t * ipu_handle)
{
	return 0;
}

void mxc_ipu_lib_task_uninit(ipu_lib_handle_t * ipu_handle)
{
	return;
}

int mxc_ipu_lib_task_buf_update(ipu_lib_handle_t * ipu_handle,
	dma_addr_t new_inbuf_paddr, dma_addr_t new_ovbuf_paddr,
	dma_addr_t new_ovbuf_alpha_paddr, void (output_callback)(void *, int),
	void * output_cb_arg)
{
	return 0;
}

int mxc_ipu_lib_task_control(int ctl_cmd, void * arg, ipu_lib_handle_t * ipu_handle)
{
	return 0;
}

int mxc_ipu_lib_ipc_init(void)
{
	return 0;
}
