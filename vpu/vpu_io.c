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

#include "vpu_debug.h"
#include "vpu_reg.h"
#include "vpu_io.h"
#include "vpu_lib.h"

static int vpu_fd = -1;
static unsigned long vpu_reg_base;

unsigned int system_rev;

enum {
	USE_DBK_INTERNAL_BUF,	/* MPEG-4 and MPEG-2 output deblocking */
	USE_OVL_INTERNAL_BUF,	/* overlap filter */
	USE_IP_INTERNAL_BUF,	/* intra/ACDC prediction */
	USE_BIT_INTERNAL_BUF,	/* MB prediction */
};

Uint32 use_iram_table[] = {
	0x6400,
	0x2000,
	0x1900,
	0x1900,
};

int get_iram_setting(struct iram_t iram, Uint32 array[], int array_size,
			int *use_iram_bits)
{
	int i;
	int total = iram.end - iram.start + 1;

	i = array_size - 1;
	if (total < array[i])
		return  -1;

	while (total > array[i]) {
		i--;
	}
	i++;

	*use_iram_bits = 0;
	while (total > array[i] && i < array_size) {
		if (i == USE_DBK_INTERNAL_BUF) {
			*use_iram_bits |= 1 << 2;
		}

		if (i == USE_OVL_INTERNAL_BUF) {
			*use_iram_bits |= 1 << 3;
		}

		if (i == USE_IP_INTERNAL_BUF) {
			*use_iram_bits |= 1 << 1;
		}

		if (i == USE_BIT_INTERNAL_BUF) {
			*use_iram_bits |= 1 << 0;
		}

		total -= array[i];
		i++;
	}

	return 0;
}

int set_iram(struct iram_t iram, Uint32 array[], int array_size,
			int use_iram_bits)
{
	static int dbk_use_size, ovl_use_size, ip_use_size;

	dprintf(3, "use iram_bits:%08x\n", use_iram_bits);
	VpuWriteReg(BIT_AXI_SRAM_USE, use_iram_bits);


	if ((use_iram_bits & 0x8) == 0x8) {
		VpuWriteReg(BIT_OVL_USE_SRAM_BASE, iram.start);
		ovl_use_size = array[USE_OVL_INTERNAL_BUF];
	}

	if ((use_iram_bits & 0x4) == 0x4) {
		VpuWriteReg(BIT_DBK_USE_SRAM_BASE, iram.start +
				ovl_use_size);
		dbk_use_size = array[USE_DBK_INTERNAL_BUF];
	}

	if ((use_iram_bits & 0x2) == 0x2) {
		VpuWriteReg(BIT_IP_USE_SRAM_BASE, iram.start +
				ovl_use_size + dbk_use_size);
		ip_use_size = array[USE_IP_INTERNAL_BUF];
	}

	if ((use_iram_bits & 0x1) == 0x1) {
		VpuWriteReg(BIT_BIT_USE_SRAM_BASE, iram.start +
				ovl_use_size + dbk_use_size + ip_use_size);
	}

	return 0;
}

int isVpuInitialized(void)
{
	return VpuReadReg(BIT_CUR_PC) != 0;
}

static int get_system_rev()
{
	FILE *fp;
	char buf[1024];
	int nread;
	char *tmp, *rev;
	int ret = -1;

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL) {
		perror("/proc/cpuinfo\n");
		return ret;
	}

	nread = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	if ((nread == 0) || (nread == sizeof(buf))) {
		fclose(fp);
		return ret;
	}

	buf[nread] = '\0';

	tmp = strstr(buf, "Revision");
	if (tmp != NULL) {
		rev = index(tmp, ':');
		if (rev != NULL) {
			rev++;
			system_rev = strtoul(rev, NULL, 16);
			ret = 0;
		}
	}

	return ret;
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
	struct iram_t iram;
	int ret;
	static int use_iram_bits;

	ret = get_system_rev();
	if (ret == -1) {
		printf("Error: Unable to obtain system rev information\n");
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
	if (cpu_is_mx37()) {
		IOGetIramBase(&iram);
		ret = get_iram_setting(iram, use_iram_table, 4, &use_iram_bits);
		if (ret != -1)
			set_iram(iram, use_iram_table, 4, use_iram_bits);
	}

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
static unsigned int sz_alloc;
int IOGetPhyMem(vpu_mem_desc * buff)
{
	if (ioctl(vpu_fd, VPU_IOC_PHYMEM_ALLOC, buff) < 0) {
		printf("mem allocation failed!\n");
		buff->phy_addr = 0;
		buff->cpu_addr = 0;
		return -1;
	}
	sz_alloc += buff->size;
	dprintf(3, "%s: phy addr = %08lx\n", __func__, buff->phy_addr);
	dprintf(3, "%s: alloc=%d, total=%d\n", __func__, buff->size, sz_alloc);

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
		dprintf(3, "%s: phy addr = %08lx\n", __func__, buff->phy_addr);
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

int IOGetIramBase(iram_t * iram)
{
	int ret = 0;

	ret = ioctl(vpu_fd, VPU_IOC_IRAM_BASE, iram);
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

