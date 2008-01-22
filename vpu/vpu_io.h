/*
 * Copyright 2004-2007 Freescale Semiconductor, Inc. All Rights Reserved.
 * 
 * Copyright (c) 2006, Chips & Media.  All rights reserved.
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
 * @file vpu_io.h
 *
 * @brief VPU system ioctrl definition
 *
 * @ingroup VPU
 */

#ifndef __VPU__IO__H
#define __VPU__IO__H

/*!
 * @brief  vpu memory description structure
 */
typedef struct vpu_mem_desc {
	int size;		/*!requested memory size */
	unsigned long phy_addr;	/*!physical memory address allocated */
	unsigned long cpu_addr;	/*!cpu addr for system free usage */
	unsigned long virt_uaddr;	/*!virtual user space address */
} vpu_mem_desc;

#define	VPU_IOC_MAGIC		'V'

#define	VPU_IOC_PHYMEM_ALLOC	_IO(VPU_IOC_MAGIC, 0)
#define	VPU_IOC_PHYMEM_FREE	_IO(VPU_IOC_MAGIC, 1)
#define VPU_IOC_WAIT4INT	_IO(VPU_IOC_MAGIC, 2)
#define	VPU_IOC_PHYMEM_DUMP	_IO(VPU_IOC_MAGIC, 3)
#define	VPU_IOC_REG_DUMP	_IO(VPU_IOC_MAGIC, 4)
#define	VPU_IOC_VL2CC_FLUSH	_IO(VPU_IOC_MAGIC, 5)

typedef void (*vpu_callback) (int status);

vpu_mem_desc bit_work_addr;

int IOSystemInit(void *callback);
int IOSystemShutdown(void);
int IOGetPhyMem(vpu_mem_desc * buff);
int IOFreePhyMem(vpu_mem_desc * buff);
int IOGetVirtMem(vpu_mem_desc * buff);
int IOFreeVirtMem(vpu_mem_desc * buff);
int IOWaitForInt(int timeout_in_ms);

unsigned long VpuWriteReg(unsigned long addr, unsigned int data);
unsigned long VpuReadReg(unsigned long addr);

void ResetVpu(void);
int isVpuInitialized(void);
void vl2cc_flush(void);

#endif
