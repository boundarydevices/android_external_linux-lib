/*
 * Copyright 2004-2008 Freescale Semiconductor, Inc. All Rights Reserved.
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
 * @file vpu_io.c
 *
 * @brief VPU system ioctrl implementation
 *
 * @ingroup VPU
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>		/* SIGIO */
#include <fcntl.h>		/* fcntl */
#include <sys/mman.h>		/* mmap */
#include <sys/ioctl.h>		/* fopen/fread */
#include <sys/errno.h>		/* fopen/fread */
#include <sys/types.h>

#include "vpu_reg.h"
#include "vpu_io.h"
#include "vpu_lib.h"

static int vpu_fd = -1;
static unsigned long vpu_reg_base;

#define MX27TO1_VPU			1
#define MX27TO2_VPU			2
#define MX32_VPU			3
#define MXC30031_VPU			4
#define MX37_VPU			5

static int vpu_platform;

int platform_is_mx27to1()
{
	return (vpu_platform == MX27TO1_VPU);
}

int platform_is_mx27to2()
{
	return (vpu_platform == MX27TO2_VPU);
}

int platform_is_mx27()
{
	return (vpu_platform == MX27TO1_VPU || (vpu_platform == MX27TO2_VPU));
}

int platform_is_mx32()
{
	return (vpu_platform == MX32_VPU);
}

int platform_is_mx37()
{
	return (vpu_platform == MX37_VPU);
}

int platform_is_mxc30031()
{
	return (vpu_platform == MXC30031_VPU);
}

int isVpuInitialized(void)
{
	return VpuReadReg(BIT_CUR_PC) != 0;
}

static int get_platform_name()
{
	FILE *fp;
	char buf[1024];
	int nread;
	char *cpu, *tmp, *rev;
	int platform = -1;

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL) {
		perror("/proc/cpuinfo\n");
		return platform;
	}

	nread = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	if ((nread == 0) || (nread == sizeof(buf))) {
		fclose(fp);
		return platform;
	}

	buf[nread] = '\0';

	cpu = strstr(buf, "Hardware");
	if (cpu == NULL) {
		return platform;
	}

	tmp = strstr(cpu, "MX32");
	if (tmp != NULL) {
		platform = MX32_VPU;
		goto out;
	}

	tmp = strstr(cpu, "MX27");
	if (tmp != NULL) {
		rev = strstr(buf, "Revision");
		if (rev != NULL) {
			tmp = strstr(rev, "020");
			if (tmp != NULL) {
				platform = MX27TO2_VPU;
			} else {
				platform = MX27TO1_VPU;
			}
		}
		goto out;
	}

	tmp = strstr(cpu, "MXC300-31");
	if (tmp != NULL) {
		platform = MXC30031_VPU;
		goto out;
	}

	tmp = strstr(cpu, "MX37");
	if (tmp != NULL) {
		platform = MX37_VPU;
		goto out;
	}
	
out:
	return platform;
}

/* make consideration for both register and physical mem access */
inline unsigned long *reg_map(unsigned long offset)
{
	return (unsigned long *)(offset + (unsigned long)vpu_reg_base);
}

/*!
 * @brief IO system initialization.
 *  When user wants to start up the codec system,
 *  this function call is needed, to open the codec device,
 *  map the register into user space,
 *  get the working buffer/code buffer/parameter buffer,
 *  download the firmware, and then set up the interrupt signal path.
 *
 * @param callback vpu interrupt callback.
 *
 * @return
 * @li  0	          System initialization success.
 * @li -1		System initialization failure.
 */
int IOSystemInit(void *callback)
{
	vpu_platform = get_platform_name();
	if (vpu_platform == -1) {
		printf("Error: Unable to obtain platform information\n");
		return -1;
	}

	/* check if the device has been opened */
	if (vpu_fd > 0)
		return 0;

	vpu_fd = open("/dev/mxc_vpu", O_RDWR);
	if (vpu_fd < 0) {
		printf("Can't open /dev/mxc_vpu\n");
		return -1;
	}

	vpu_reg_base = (unsigned long)mmap(NULL, BIT_REG_MARGIN,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED, vpu_fd, 0);

	if ((void *)vpu_reg_base == MAP_FAILED) {
		printf("Can't map register\n");
		close(vpu_fd);
		vpu_fd = -1;
		return -1;
	}

	bit_work_addr.size = WORK_BUF_SIZE + PARA_BUF_SIZE +
	    					CODE_BUF_SIZE + PARA_BUF2_SIZE;

	if (IOGetPhyMem(&bit_work_addr) != 0)
		goto err;

	if (IOGetVirtMem(&bit_work_addr) <= 0)
		goto err;

	vpu_Init(bit_work_addr.phy_addr);
	return 0;

      err:
	printf("Error in IOSystemInit()");
	IOSystemShutdown();
	return -1;
}

/*!
 * @brief IO system shut down.
 *
 * When user wants to stop the codec system, this
 * function call is needed, to release the interrupt
 * signal, free the working buffer/code buffer/parameter
 * buffer, unmap the register into user space, and
 * close the codec device.
 *
 * @param none
 *
 * @return
 * @li   0	System shutting down success.
 * @li   -1		System shutting down failure.
 */
int IOSystemShutdown(void)
{
	IOFreeVirtMem(&bit_work_addr);
	IOFreePhyMem(&bit_work_addr);

	VpuWriteReg(BIT_INT_ENABLE, 0);	/* PIC_RUN irq disable */

	if (munmap((void *)vpu_reg_base, BIT_REG_MARGIN) != 0)
		printf("munmap failed\n");

	if (vpu_fd >= 0) {
		close(vpu_fd);
		vpu_fd = -1;
	}

	return 0;
}

unsigned long VpuWriteReg(unsigned long addr, unsigned int data)
{
	unsigned long *reg_addr = reg_map(addr);
	*(volatile unsigned long *)reg_addr = data;

	return 0;
}

unsigned long VpuReadReg(unsigned long addr)
{
	unsigned long *reg_addr = reg_map(addr);
	return *(volatile unsigned long *)reg_addr;
}

/*!
 * @brief Allocated buffer of requested size
 * When user wants to get massive memory
 * for the system, they needs to fill the required
 * size in buff structure, and if this function
 * succeeds in allocating memory and returns 0,
 * the returned physical memory is filled in
 * phy_addr of buff structure. If the function fails
 * and return -1,  the phy_addr remains the same as before.
 * memory size is in byte.
 *
 * @param buff	the structure contains the memory information to be got;
 *
 * @return
 * @li 0	          Allocation memory success.
 * @li -1		Allocation memory failure.
 */
int IOGetPhyMem(vpu_mem_desc * buff)
{
	if (ioctl(vpu_fd, VPU_IOC_PHYMEM_ALLOC, buff) < 0) {
		printf("mem allocation failed!\n");
		buff->phy_addr = 0;
		buff->cpu_addr = 0;
		return -1;
	}

	return 0;
}

/*!
 * @brief Free specified memory
 * When user wants to free massive memory for the system,
 * they needs to fill the physical address and size to be freed
 * in buff structure.
 *
 * @param buff	the structure containing memory information to be freed;
 *
 * @return
 * @li 0            Freeing memory success.
 * @li -1		Freeing memory failure.
 */
int IOFreePhyMem(vpu_mem_desc * buff)
{
	if (buff->phy_addr != 0) {
		ioctl(vpu_fd, VPU_IOC_PHYMEM_FREE, buff);
	}

	buff->phy_addr = 0;
	buff->cpu_addr = 0;
	return 0;
}

/*!
 * @brief Map physical memory to user space.
 *
 * @param	buff	the structure containing memory information to be mapped.
 *
 * @return	user space address.
 */
int IOGetVirtMem(vpu_mem_desc * buff)
{
	unsigned long va_addr;

	va_addr = (unsigned long)mmap(NULL, buff->size, PROT_READ | PROT_WRITE,
				      MAP_SHARED, vpu_fd, buff->phy_addr);
	if ((void *)va_addr == MAP_FAILED) {
		buff->virt_uaddr = 0;
		return -1;
	}

	buff->virt_uaddr = va_addr;
	return va_addr;
}

/*!
 * @brief Unmap  physical memory to user space.
 *
 * @param	buff	the structure containing memory information to be unmapped;
 *
 * @return
 * @li 0        Success
 * @li Others 	Failure
 */
int IOFreeVirtMem(vpu_mem_desc * buff)
{
	if (buff->virt_uaddr != 0) {
		if (munmap((void *)buff->virt_uaddr, buff->size) != 0)
			printf("munmap failed\n");
	}

	buff->virt_uaddr = 0;
	return 0;
}

int IOWaitForInt(int timeout_in_ms)
{
	int ret = 0;
	if (timeout_in_ms < 0) {
		printf("invalid timeout\n");
		return -1;
	}

	ret = ioctl(vpu_fd, VPU_IOC_WAIT4INT, timeout_in_ms);
	return ret;
}

void vl2cc_flush()
{
	ioctl(vpu_fd, VPU_IOC_VL2CC_FLUSH, NULL);
}

/*!
 * @brief
 * When the system starts up, resetting is needed in advance.
 */
void ResetVpu(void)
{
	unsigned long *reg_addr = reg_map(BIT_CODE_RESET);
	(*(volatile unsigned long *)reg_addr) |= 0x1;
	usleep(10);
	(*(volatile unsigned long *)reg_addr) &= ~0x1;

	return;
}

