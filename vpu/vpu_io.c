/*
 * Copyright 2004-2012 Freescale Semiconductor, Inc.
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
#include <pthread.h>
#include <sys/mman.h>		/* mmap */
#include <sys/ioctl.h>		/* fopen/fread */
#include <sys/errno.h>		/* fopen/fread */
#include <sys/types.h>

#include "vpu_debug.h"
#include "vpu_reg.h"
#include "vpu_io.h"
#include "vpu_lib.h"
#include "vpu_util.h"

#ifdef BUILD_FOR_ANDROID
#include <utils/Log.h>
#ifdef USE_ION
#include <linux/ion.h>
#include <ion/ion.h>
#elif USE_GPU
int
gcoOS_AllocateVideoMemory(
    void* Os,
    int InUserSpace,
    int InCacheable,
    int* Bytes,
    int* Physical,
    void** Logical,
    void** Handle);
int
gcoOS_FreeVideoMemory(
    void* Os,
    void* Handle
    );
#else
#include <linux/android_pmem.h>
#endif
#endif

static int vpu_fd = -1;
static unsigned long vpu_reg_base;
static int vpu_active_num = 0;

unsigned int system_rev;
semaphore_t *vpu_semap;
vpu_mem_desc bit_work_addr;

int _IOGetPhyMem(int which, vpu_mem_desc *buff);

int isVpuInitialized(void)
{
	int val;

	IOClkGateSet(true);
	val = VpuReadReg(BIT_CUR_PC);
	IOClkGateSet(false);

	return val != 0;
}

static int get_system_rev(void)
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
	int ret;

	/* Exit directly if already initialized */
	if (vpu_fd > 0) {
		vpu_active_num++;
		return 0;
	}

	ret = get_system_rev();
	if (ret == -1) {
		err_msg("Error: Unable to obtain system rev information\n");
		return -1;
	}

	vpu_fd = open("/dev/mxc_vpu", O_RDWR);
	if (vpu_fd < 0) {
		err_msg("Can't open /dev/mxc_vpu: %s\n", strerror(errno));
		return -1;
	}

	vpu_semap = vpu_semaphore_open();
	if (vpu_semap == NULL) {
		err_msg("Error: Unable to open vpu shared memory file\n");
		close(vpu_fd);
		vpu_fd = -1;
		return -1;
	}

	if (!semaphore_wait(vpu_semap, API_MUTEX)) {
		err_msg("Error: Unable to get mutex\n");
		close (vpu_fd);
		vpu_fd = -1;
		return -1;
	}

	vpu_reg_base = (unsigned long)mmap(NULL, BIT_REG_MARGIN,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED, vpu_fd, 0);

	if ((void *)vpu_reg_base == MAP_FAILED) {
		err_msg("Can't map register\n");
		close(vpu_fd);
		vpu_fd = -1;
		semaphore_post(vpu_semap, API_MUTEX);
		return -1;
	}

	vpu_active_num++;

	IOClkGateSet(true);
#ifdef BUILD_FOR_ANDROID
	unsigned long va_addr;

	/* Special handle the bit work buffer, which reserved in vpu driver probe */
	bit_work_addr.size = TEMP_BUF_SIZE + PARA_BUF_SIZE +
			     CODE_BUF_SIZE + PARA_BUF2_SIZE;
	if (_IOGetPhyMem(VPU_IOC_GET_WORK_ADDR, &bit_work_addr) < 0) {
		err_msg("Get bitwork address failed!\n");
		goto err;
	}

	va_addr = (unsigned long)mmap(NULL, bit_work_addr.size, PROT_READ | PROT_WRITE,
					MAP_SHARED, vpu_fd, bit_work_addr.phy_addr);
	if ((void *)va_addr == MAP_FAILED) {
		bit_work_addr.virt_uaddr = 0;
		goto err;
	}

	bit_work_addr.virt_uaddr = va_addr;
#else
	bit_work_addr.size = TEMP_BUF_SIZE + PARA_BUF_SIZE +
			     CODE_BUF_SIZE + PARA_BUF2_SIZE;
	if (_IOGetPhyMem(VPU_IOC_GET_WORK_ADDR, &bit_work_addr) < 0) {
		err_msg("Get bitwork address failed!\n");
		goto err;
	}

	if (IOGetVirtMem(&bit_work_addr) <= 0)
		goto err;
#endif
	UnlockVpu(vpu_semap);
	return 0;

      err:
	err_msg("Error in IOSystemInit()");
	UnlockVpu(vpu_semap);
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

	/* Exit directly if already shutdown */
	if (vpu_fd == -1)
		return 0;

	/* Make sure real shutdown is done when no instance needs
	   to access vpu in the same process */
	if (vpu_active_num > 1) {
		vpu_active_num--;
		return 0;
	} else if (!vpu_active_num) {
		warn_msg(" No instance is actived\n");
		return 0;
	}

	if (!semaphore_wait(vpu_semap, API_MUTEX)) {
		err_msg("Unable to get mutex\n");
		return -1;
	}

	/*
	 * Do not call IOFreePhyMem/IOFreePhyPicParaMem/IOFreePhyUserDataMem
	 * to free memory, let kernel do.
	 */
#ifdef BUILD_FOR_ANDROID
	if (bit_work_addr.virt_uaddr != 0) {
		if (munmap((void *)bit_work_addr.virt_uaddr, bit_work_addr.size) != 0)
			err_msg("munmap failed\n");
	}
	bit_work_addr.virt_uaddr = 0;
#else
	IOFreeVirtMem(&bit_work_addr);
#endif

	if (munmap((void *)vpu_reg_base, BIT_REG_MARGIN) != 0)
		err_msg("munmap failed\n");

	vpu_active_num--;

	semaphore_post(vpu_semap, API_MUTEX);
	vpu_semaphore_close(vpu_semap);

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
 * When user wants to get massive memory for the system, they needs to fill
 * the required size in buff structure, and if this function succeeds in
 * allocating memory and returns 0, the returned physical memory is filled in
 * phy_addr of buff structure. If the function fails and return -1,
 * the phy_addr remains the same as before.
 *
 * @param buff	the structure contains the memory information to be retrieved;
 *
 * @return
 * @li 0		Allocation memory success.
 * @li -1		Allocation memory failure.
 */
static unsigned int sz_alloc;
int _IOGetPhyMem(int which, vpu_mem_desc *buff)
{
#ifdef BUILD_FOR_ANDROID
	const size_t pagesize = getpagesize();
	int err, fd;
#ifdef USE_ION
	struct ion_handle *handle;
	int share_fd, ret = -1;
	unsigned char *ptr;
#elif USE_GPU
        void *handle, *virt_addr;
        int bytes, phy_addr, ret = -1;
#else
	/* Get memory from pmem space for android */
	struct pmem_region region;
#endif

	if ((!buff) || (!buff->size)) {
		err_msg("Error!_IOGetPhyMem:Invalid parameters");
		return -1;
	}

	buff->cpu_addr = 0;
	buff->phy_addr = 0;
	buff->virt_uaddr = 0;

	if (which == VPU_IOC_GET_WORK_ADDR) {
		if (ioctl(vpu_fd, which, buff) < 0) {
			err_msg("mem allocation failed!\n");
			buff->phy_addr = 0;
			buff->cpu_addr = 0;
			return -1;
		}
		return 0;
	}

	if (which != VPU_IOC_PHYMEM_ALLOC) {
		err_msg("Error!_IOGetPhyMem unsupported memtype: %d", which);
		return -1;
	}

	buff->size = (buff->size + pagesize-1) & ~(pagesize - 1);

#ifdef USE_ION
	fd = ion_open();
	if (fd <= 0) {
		err_msg("ion open failed!\n");
		return -1;
	}

	err = ion_alloc(fd, buff->size, pagesize, 1, &handle);
	if (err) {
		err_msg("ion allocation failed!\n");
		goto error;
	}

	err = ion_map(fd, handle, buff->size,
			    PROT_READ|PROT_WRITE, MAP_SHARED,
			    0, &ptr, &share_fd);
	if (err) {
		err_msg("ion map failed!\n");
		goto error;
	}

	err = ion_phys(fd, handle);
	if (err == 0) {
		err_msg("ion get physical address failed!\n");
		goto error;
	}

	buff->virt_uaddr = (unsigned long)ptr;
	buff->phy_addr = (unsigned long)err;
	buff->cpu_addr = (unsigned long)handle;
	memset((void*)buff->virt_uaddr, 0, buff->size);
	ret = 0;
	info_msg("<ion> alloc handle: 0x%x, paddr: 0x%x, vaddr: 0x%x",
			(unsigned int)handle, (unsigned int)buff->phy_addr,
			(unsigned int)buff->virt_uaddr);
error:
	close(share_fd);
	ion_close(fd);
	return ret;
#elif USE_GPU
        bytes = buff->size + PAGE_SIZE;
        phy_addr = 0; virt_addr = NULL;
        ret = gcoOS_AllocateVideoMemory(NULL, 1, 0, &bytes, &phy_addr,&virt_addr,&handle);
        if(ret != 0) {
            err_msg("%d, gpu allocator failed to alloc buffer with size %d", ret, buff->size);
            return ret;
        }

        buff->virt_uaddr = (unsigned long)virt_addr;
        buff->phy_addr = (unsigned long)phy_addr;
        buff->cpu_addr = (unsigned long)handle;

        //vpu requires page alignment for the address implicitly, round it to page edge
        buff->virt_uaddr = (buff->virt_uaddr + PAGE_SIZE -1) & ~(PAGE_SIZE -1);
        buff->phy_addr = (buff->phy_addr + PAGE_SIZE -1) & ~(PAGE_SIZE -1);

        info_msg("<gpu> alloc handle: 0x%x, paddr: 0x%x, vaddr: 0x%x",
			(unsigned int)handle, (unsigned int)buff->phy_addr,
			(unsigned int)buff->virt_uaddr);
        return 0;
#else
	fd = (unsigned long)open("/dev/pmem_adsp", O_RDWR | O_SYNC);
	if (fd < 0) {
		err_msg("Error!_IOGetPhyMem Error,cannot open pmem");
		return -1;
	}

	err = ioctl(fd, PMEM_GET_TOTAL_SIZE, &region);

	buff->virt_uaddr = (unsigned long)mmap(0, buff->size,
			    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

	if (buff->virt_uaddr == (unsigned long)MAP_FAILED) {
		err_msg("Error!mmap(fd=%d, size=%u) failed (%s)",
			fd, buff->size, strerror(errno));
		close(fd);
		return -1;
	}

	memset(&region, 0, sizeof(region));

	if (ioctl(fd, PMEM_GET_PHYS, &region) == -1) {
		err_msg("Error!Failed to get physical address of source!");
		munmap((void *)buff->virt_uaddr, buff->size);
		close(fd);
		return -1;
	}

	buff->phy_addr = (unsigned long)region.offset;
	buff->cpu_addr = (unsigned long)fd;
	memset((void*)buff->virt_uaddr, 0, buff->size);
#endif
#else
	if (ioctl(vpu_fd, which, buff) < 0) {
		err_msg("mem allocation failed!\n");
		buff->phy_addr = 0;
		buff->cpu_addr = 0;
		return -1;
	}
	sz_alloc += buff->size;
	dprintf(3, "%s: phy addr = %08lx\n", __func__, buff->phy_addr);
	dprintf(3, "%s: alloc=%d, total=%d\n", __func__, buff->size, sz_alloc);
#endif

	return 0;
}

int IOGetPhyMem(vpu_mem_desc * buff)
{
	return _IOGetPhyMem(VPU_IOC_PHYMEM_ALLOC, buff);
}

/* User cannot free physical share memory, this is done in driver */
int IOGetPhyShareMem(vpu_mem_desc * buff)
{
        return _IOGetPhyMem(VPU_IOC_GET_SHARE_MEM, buff);
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
int _IOFreePhyMem(int which, vpu_mem_desc * buff)
{
#ifdef BUILD_FOR_ANDROID
#ifdef USE_ION
	struct ion_handle *handle;
	int fd;

	if (!buff || !(buff->size) || ((unsigned long)buff->cpu_addr == 0)) {
		err_msg("Error!_IOFreePhyMem:Invalid parameters");
		return -1;
	}

	if (which != VPU_IOC_PHYMEM_FREE) {
		err_msg("Error!_IOFreePhyMem unsupported memtype: %d",which);
		return -1;
	}

	handle = (struct ion_handle *)buff->cpu_addr;

	fd = ion_open();
	if (fd <= 0) {
		err_msg("ion open failed!\n");
		return -1;
	}

	ion_free(fd, handle);
	info_msg("<ion> free handle: 0x%x, paddr: 0x%x, vaddr: 0x%x",
			(unsigned int)handle, (unsigned int)buff->phy_addr,
			(unsigned int)buff->virt_uaddr);
	ion_close(fd);

	munmap((void *)buff->virt_uaddr, buff->size);
	memset((void*)buff, 0, sizeof(*buff));
#elif USE_GPU
        int ret = -1;
        void *handle = (void *)buff->cpu_addr;
        if(!handle) {
           warn_msg("%s: Invalid handle 0x%x", __FUNCTION__, (unsigned int)handle);
           return ret;
        }
        ret = gcoOS_FreeVideoMemory(NULL, handle);
        if(ret != 0) {
           err_msg("%d, gpu allocator failed to free handle 0x%x", ret, (unsigned int)handle);
           return ret;
        }

        info_msg("<gpu> free handle: 0x%x, paddr: 0x%x, vaddr: 0x%x",
			(unsigned int)handle, (unsigned int)buff->phy_addr,
			(unsigned int)buff->virt_uaddr);
#else
	int fd_pmem;

	if (!buff || !(buff->size) || ((int)buff->cpu_addr <= 0)) {
		err_msg("Error!_IOFreePhyMem:Invalid parameters");
		return -1;
	}

	if (which != VPU_IOC_PHYMEM_FREE) {
		err_msg("Error!_IOFreePhyMem unsupported memtype: %d",which);
		return -1;
	}

	fd_pmem = (int)buff->cpu_addr;
	if(fd_pmem) {
		munmap((void *)buff->virt_uaddr, buff->size);
		close(fd_pmem);
	}
	memset((void*)buff, 0, sizeof(*buff));
#endif
#else
	if (buff->phy_addr != 0) {
		dprintf(3, "%s: phy addr = %08lx\n", __func__, buff->phy_addr);
		ioctl(vpu_fd, which, buff);
	}

	sz_alloc -= buff->size;
	dprintf(3, "%s: total=%d\n", __func__, sz_alloc);
	memset(buff, 0, sizeof(*buff));
#endif
	return 0;
}

int IOFreePhyMem(vpu_mem_desc * buff)
{
	return _IOFreePhyMem(VPU_IOC_PHYMEM_FREE, buff);
}

/*!
 * @brief check phy memory prepare to pass to vpu is valid or not, we
 * already address some issue that if pass a wrong address to vpu
 * (like virtual address), system will hang.
 *
 * @return true return is a valid phy memory address, false return not.
 */
int IOPhyMemCheck(unsigned long phyaddr, const char *name)
{
	unsigned long va_addr;
	vpu_mem_desc buff;
	int result;

	memset(&buff, 0, sizeof(buff));
	buff.phy_addr = phyaddr;
	if (ioctl(vpu_fd, VPU_IOC_PHYMEM_CHECK, &buff)) {
#ifdef BUILD_FOR_ANDROID
		err_msg("phy memory check failed!:%s\n", strerror(errno));
#endif
		err_msg("phy memory check failed!:%s\n", strerror(errno));
		/* if driver don't support this feature, just ignore
		 * it by return turn to bypass the check. */
		return true;
	}
	/* borrow .size to pass back result. */
	result = buff.size;
	dprintf(3, "memory phy: %s: %lx va:%lx %s phy memory\n",
	     name, buff.phy_addr, buff.virt_uaddr, result ? "is" : "isn't");
#ifdef BUILD_FOR_ANDROID
	if (result == false)
		err_msg("memory phy: %s: %lx va:%lx %s phy memory",
		     name, buff.phy_addr, buff.virt_uaddr, result ? "is" : "isn't");
#endif

	return result;
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
#ifdef BUILD_FOR_ANDROID
       return buff->virt_uaddr;
#else
	unsigned long va_addr;

	va_addr = (unsigned long)mmap(NULL, buff->size, PROT_READ | PROT_WRITE,
				      MAP_SHARED, vpu_fd, buff->phy_addr);
	if ((void *)va_addr == MAP_FAILED) {
		buff->virt_uaddr = 0;
		return -1;
	}

	buff->virt_uaddr = va_addr;
	dprintf(3, "%s: virt addr = %08lx\n", __func__, buff->virt_uaddr);
	return va_addr;
#endif
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
#ifndef BUILD_FOR_ANDROID
	if (buff->virt_uaddr != 0) {
		if (munmap((void *)buff->virt_uaddr, buff->size) != 0)
			err_msg("munmap failed\n");
	}

	buff->virt_uaddr = 0;
#endif
	return 0;
}

/*!
 * @brief map vmalloced share memory to user space.
 *
 * @param       buff    the structure containing memory information to be unmapped;
 *
 * @return      user space address.
 */
int IOGetVShareMem(int size)
{
	unsigned long va_addr;
	vpu_mem_desc buff = { 0, 0, 0, 0 };

	buff.size = size;
	if (ioctl(vpu_fd, VPU_IOC_REQ_VSHARE_MEM, &buff)) {
		err_msg("mem allocation failed!\n");
		return 0;
	}
	va_addr = (unsigned long)mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vpu_fd, buff.cpu_addr);

	if ((void *)va_addr == MAP_FAILED)
		return 0;

	return va_addr;
}

int IOWaitForInt(int timeout_in_ms)
{
	int ret = 0;
	if (timeout_in_ms < 0) {
		err_msg("invalid timeout\n");
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

/*!
 * @brief turn off(/on) the VPU core clock and serial clock to save power
 *
 * @param  on 1 - turn on, 0 - turn off (save power)
 *
 * @return
 * @li 0        Success
 * @li Others 	Failure
 */
int IOClkGateSet(int on)
{
	int ret = 0;

	ret = ioctl(vpu_fd, VPU_IOC_CLKGATE_SETTING, &on);
	dprintf(3, "vpu clock gate setting = %d\n", on);

	return ret;
}

int IOSysSWReset(void)
{
	int ret = 0;

	ret = ioctl(vpu_fd, VPU_IOC_SYS_SW_RESET, 0);
	dprintf(3, "vpu system software reset\n");

	return ret;
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

