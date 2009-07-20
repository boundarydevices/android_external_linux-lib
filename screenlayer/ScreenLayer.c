/*
 * Copyright 2009 Freescale Semiconductor, Inc. All Rights Reserved.
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

#ifdef __cplusplus
extern "C"{
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <semaphore.h>
#include <linux/ipu.h>
#include <linux/mxcfb.h>
#include <linux/videodev.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "ScreenLayer.h"
#include "mxc_ipu_hl_lib.h"

#define DBG_DEBUG		3
#define DBG_INFO		2
#define DBG_WARNING		1
#define DBG_ERR			0

static int debug_level = DBG_ERR;
#define dbg(flag, fmt, args...)	{ if(flag <= debug_level)  printf("%s:%d "fmt, __FILE__, __LINE__,##args); }

/* Indicates the max number which will be supported in the CreateScreenLayer */
#define BUF_POOL_NUMBER		20

/*
**   Privare data will be stored in the shm.
**
**   layour of shared memory
**
**   Primary    Second     Third
**ID:    1          2          3
**  |----------|----------|----------|
*/
typedef struct {
	u8		isPrimary;
	u8 		bufNum;
	u8		curBufIdx;
	dma_addr_t	dispPaddr[2];
	u8		curDispIdx;
	u8		alphaGlobalEnable;
	u8		sepAlphaLocalEnable;
	u8		alpha;
	u8		keyColorEnable;
	u32		keyColor;
	u8		layerEnable;
	s32		fdIpu;
        ipu_mem_info 	* bufMinfo;
	ipu_mem_info 	* bufAlphaMinfo;
        ipu_mem_info 	dispMinfo;
	/* Add for IPC, backup infor from external ScreenLayer */
	SLRect 		screenRect;
	u32 		fmt;
	bool		supportSepLocalAlpha;
	dma_addr_t 	bufPaddr[BUF_POOL_NUMBER];
	dma_addr_t 	bufAlphaPaddr[BUF_POOL_NUMBER];
	char		fbdev[32];

	int		layerID;
	int		preLayerId;
	int		nextLayerId;
} ScreenLayerPriv;
/* variables for semaphore */
sem_t * 	semID;
const  char* 	semName="IPU_SL_SEM_NAME";
static char	shmName[12]="shm_fb0";

/* Indicates how many threads in the current process */
static int pthread_counter=0;

/* virtual address of shared memory in current Process */
static ScreenLayerPriv  * vshmSLPriv = NULL;

static u32 fmt_to_bpp(u32 pixelformat)
{
	u32 bpp;

	switch (pixelformat)
	{
		case IPU_PIX_FMT_RGB565:
		/*interleaved 422*/
		case IPU_PIX_FMT_YUYV:
		case IPU_PIX_FMT_UYVY:
		/*non-interleaved 422*/
		case IPU_PIX_FMT_YUV422P:
		case IPU_PIX_FMT_YVU422P:
			bpp = 16;
			break;
		case IPU_PIX_FMT_BGR24:
		case IPU_PIX_FMT_RGB24:
		case IPU_PIX_FMT_YUV444:
			bpp = 24;
			break;
		case IPU_PIX_FMT_BGR32:
		case IPU_PIX_FMT_BGRA32:
		case IPU_PIX_FMT_RGB32:
		case IPU_PIX_FMT_RGBA32:
		case IPU_PIX_FMT_ABGR32:
			bpp = 32;
			break;
		/*non-interleaved 420*/
		case IPU_PIX_FMT_YUV420P:
		case IPU_PIX_FMT_YUV420P2:
		case IPU_PIX_FMT_NV12:
			bpp = 12;
			break;
		default:
			bpp = 8;
			break;
	}
	return bpp;
}

void yield(void)
{
	usleep(1);
}

SLRetCode _MemAllocSL(ScreenLayer *pSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv + (int)pSL->pPriv-1);
	u8 i;
	u32 width, height, screen_size;

	pSLPriv->fdIpu = open("/dev/mxc_ipu",O_RDWR);
	if(pSLPriv->fdIpu < 0) {
		ret = E_RET_DEV_FAIL;
		goto done;
	}

	/*
 	 * alloc disp buf, for primary layer should be framebuffer from fb device,
 	 * otherwise, a tmp buffer may be allocated.
 	 *
 	 * 3 cases:
 	 *
 	 * a. only primary
 	 * 	PrimarySL(dispBuf)
 	 * b. primary + one overlay
 	 * 	PrimarySL -> OverlaySL0(dispBuf)
 	 * c. primary + two overlay
 	 * 	PrimarySL -> OverlaySL0(tmpDispBuf) -> OverlaySL1(dispBuf)
 	 */
	if (!pSLPriv->isPrimary) {
		ScreenLayerPriv *pPreSLPriv = (ScreenLayerPriv *)(vshmSLPriv + pSLPriv->preLayerId-1);
		ScreenLayerPriv *pPriSLPriv = vshmSLPriv;

		if (pSLPriv->preLayerId != (int)pSL->pPrimary) {
			/* case b -> c
			 * allocate tmpDispBuf from current SL, make it as PreSL's DispBuf.
			 * and use PreSL's DispBuf as currentSL's display buffer.
			 */
			width  = pPriSLPriv->screenRect.right  - pPriSLPriv->screenRect.left;
			height = pPriSLPriv->screenRect.bottom - pPriSLPriv->screenRect.top;
			pSLPriv->dispMinfo.size = width/8*height*fmt_to_bpp(pPriSLPriv->fmt);
			if (ioctl(pSLPriv->fdIpu, IPU_ALOC_MEM, &(pSLPriv->dispMinfo)) < 0) {
				ret = E_RET_MEM_ALOC_FAIL;
				dbg(DBG_ERR, "_MemAllocSL: IPU memory alloc failed! \n");
				goto done;
			}

			pSLPriv->dispPaddr[0] = pPreSLPriv->dispPaddr[0];
			pSLPriv->dispPaddr[1] = pPreSLPriv->dispPaddr[1];
			pSLPriv->curDispIdx = pPreSLPriv->curDispIdx;
			pPreSLPriv->dispPaddr[0] = pSLPriv->dispMinfo.paddr;
			pPreSLPriv->dispPaddr[1] = 0;
			pPreSLPriv->curDispIdx = 0;

			dbg(DBG_DEBUG, "allocate %d memory paddr 0x%x for pre layer\n", pSLPriv->dispMinfo.size, pSLPriv->dispMinfo.paddr);
		} else {
			/* case a -> b */
			pSLPriv->dispPaddr[0] = pPreSLPriv->dispPaddr[0];
			pSLPriv->dispPaddr[1] = pPreSLPriv->dispPaddr[1];
			pSLPriv->curDispIdx = pPreSLPriv->curDispIdx;
			pPreSLPriv->dispPaddr[0] = 0;
			pPreSLPriv->dispPaddr[1] = 0;
			pPreSLPriv->curDispIdx = 0;
		}
	} else {
		/* case a */
		s32 fd_fb;
		struct fb_fix_screeninfo fb_fix;
		struct fb_var_screeninfo fb_var;

		if ((fd_fb = open(pSL->fbdev, O_RDWR, 0)) < 0) {
			memcpy(pSL->fbdev, "/dev/fb", 8);
			if ((fd_fb = open(pSL->fbdev, O_RDWR, 0)) < 0) {
				ret = E_RET_DEV_FAIL;
				goto done;
			}
		}

		if ( ioctl(fd_fb, FBIOGET_FSCREENINFO, &fb_fix) < 0) {
			ret = E_RET_DEV_FAIL;
			close(fd_fb);
			goto done;
		}
		if ( ioctl(fd_fb, FBIOGET_VSCREENINFO, &fb_var) < 0) {
			ret = E_RET_DEV_FAIL;
			close(fd_fb);
			goto done;
		}

		if (fb_var.bits_per_pixel != fmt_to_bpp(pSL->fmt)) {
			dbg(DBG_ERR, "request format should be the same as fb dev!\n");
			ret = E_RET_WRONG_FMT;
			goto done;
		}

		/* make the primary layer the same size as fb device */
		pSL->screenRect.left = pSL->screenRect.top = 0;
		pSL->screenRect.right =  fb_var.xres;
		pSL->screenRect.bottom =  fb_var.yres;

		screen_size = fb_var.yres * fb_fix.line_length;
		pSLPriv->dispPaddr[0] = fb_fix.smem_start;
		pSLPriv->dispPaddr[1] = fb_fix.smem_start + screen_size;

		dbg(DBG_DEBUG, "screen layer display to %s, dispPaddr 0x%x 0x%x\n", pSL->fbdev, pSLPriv->dispPaddr[0], pSLPriv->dispPaddr[1]);

		close(fd_fb);
	}

	width = pSL->screenRect.right - pSL->screenRect.left;
	height = pSL->screenRect.bottom - pSL->screenRect.top;

	pSL->bufPaddr = (dma_addr_t *)malloc(pSLPriv->bufNum * sizeof(dma_addr_t));
	pSL->bufVaddr = (void **)malloc(pSLPriv->bufNum * sizeof(void *));
	pSLPriv->bufMinfo = (ipu_mem_info *)malloc(pSLPriv->bufNum * sizeof(ipu_mem_info));
	pSL->bufSize = width/8*height*fmt_to_bpp(pSL->fmt);
	/* For local alpha blending buffers */
	if (pSL->supportSepLocalAlpha) {
		pSL->bufAlphaPaddr = (dma_addr_t *)malloc(pSLPriv->bufNum * sizeof(dma_addr_t));
		pSL->bufAlphaVaddr = (void **)malloc(pSLPriv->bufNum * sizeof(void *));
		pSLPriv->bufAlphaMinfo = (ipu_mem_info *)malloc(pSLPriv->bufNum * sizeof(ipu_mem_info));
		pSL->bufAlphaSize = width * height;
	}

	for (i=0;i<pSLPriv->bufNum;i++) {
		pSLPriv->bufMinfo[i].size = pSL->bufSize;
		if (ioctl(pSLPriv->fdIpu, IPU_ALOC_MEM, &(pSLPriv->bufMinfo[i])) < 0) {
			ret = E_RET_MEM_ALOC_FAIL;
			goto err;
		}
		pSL->bufPaddr[i] = pSLPriv->bufMinfo[i].paddr;
		/* mmap virtual addr for user*/
		pSL->bufVaddr[i] = mmap (NULL, pSLPriv->bufMinfo[i].size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				pSLPriv->fdIpu, pSLPriv->bufMinfo[i].paddr);
		if (pSL->bufVaddr[i] == MAP_FAILED) {
			ret = E_RET_MMAP_FAIL;
			goto err;
		}

		dbg(DBG_DEBUG, "allocate %d memory paddr 0x%x, mmap to %p for current layer\n", pSLPriv->bufMinfo[i].size, pSL->bufPaddr[i], pSL->bufVaddr[i]);

		/* Allocate local alpha blending buffers */
		if (pSL->supportSepLocalAlpha) {
			pSLPriv->bufAlphaMinfo[i].size = pSL->bufAlphaSize;
			if (ioctl(pSLPriv->fdIpu, IPU_ALOC_MEM,
				  &(pSLPriv->bufAlphaMinfo[i])) < 0) {
				ret = E_RET_MEM_ALOC_FAIL;
				goto err;
			}
			pSL->bufAlphaPaddr[i] = pSLPriv->bufAlphaMinfo[i].paddr;
			/* mmap virtual addr for user*/
			pSL->bufAlphaVaddr[i] = mmap (NULL,
					pSLPriv->bufAlphaMinfo[i].size,
					PROT_READ | PROT_WRITE, MAP_SHARED,
					pSLPriv->fdIpu,
					pSLPriv->bufAlphaMinfo[i].paddr);
			if (pSL->bufAlphaVaddr[i] == MAP_FAILED) {
				ret = E_RET_MMAP_FAIL;
				goto err;
			}

			dbg(DBG_DEBUG, "allocate %d memory paddr 0x%x, mmap to %p for local alpha blending buffers of current layer\n", pSLPriv->bufAlphaMinfo[i].size, pSL->bufAlphaPaddr[i], pSL->bufAlphaVaddr[i]);
		}
	}

	goto done;

err:
	if (pSL->bufPaddr)
		free(pSL->bufPaddr);
	if (pSL->bufVaddr)
		free(pSL->bufVaddr);
	if (pSLPriv->bufMinfo)
		free(pSLPriv->bufMinfo);
	if (pSL->bufAlphaPaddr)
		free(pSL->bufAlphaPaddr);
	if (pSL->bufAlphaVaddr)
		free(pSL->bufAlphaVaddr);
	if (pSLPriv->bufAlphaMinfo)
		free(pSLPriv->bufAlphaMinfo);
done:
	return ret;
}

void _MemFreeSL(ScreenLayer *pSL)
{
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv +(int)pSL->pPriv-1);
	u8 i;

	for (i=0;i<pSLPriv->bufNum;i++) {
		dbg(DBG_DEBUG, "free %d memory paddr 0x%x, mmap to %p for current layer\n", pSLPriv->bufMinfo[i].size, pSL->bufPaddr[i], pSL->bufVaddr[i]);
		if (pSL->bufVaddr[i])
			munmap(pSL->bufVaddr[i], pSLPriv->bufMinfo[i].size);
		ioctl(pSLPriv->fdIpu, IPU_FREE_MEM, &(pSLPriv->bufMinfo[i]));

		/* Free local alpha blending buffers */
		if (pSL->supportSepLocalAlpha) {
			dbg(DBG_DEBUG, "free %d memory paddr 0x%x, mmap to %p for local alpha blending buffers of current layer\n", pSLPriv->bufAlphaMinfo[i].size, pSL->bufAlphaPaddr[i], pSL->bufAlphaVaddr[i]);
			if (pSL->bufAlphaVaddr[i])
				munmap(pSL->bufAlphaVaddr[i],
				       pSLPriv->bufAlphaMinfo[i].size);
			ioctl(pSLPriv->fdIpu, IPU_FREE_MEM,
			      &(pSLPriv->bufAlphaMinfo[i]));
		}
	}

	if (pSLPriv->preLayerId && pSLPriv->nextLayerId) {
		/* case c -> b, destory middle layer, do nothing */
		dbg(DBG_DEBUG, "free middle layer. \n");
	} else if (pSLPriv->preLayerId) {
		ScreenLayerPriv *pPreSLPriv = (ScreenLayerPriv *)(vshmSLPriv + pSLPriv->preLayerId-1);
		if (pSLPriv->preLayerId == (int)pSL->pPrimary) {
			/* case b -> a */
			pPreSLPriv->dispPaddr[0] = pSLPriv->dispPaddr[0];
			pPreSLPriv->dispPaddr[1] = pSLPriv->dispPaddr[1];
			pPreSLPriv->curDispIdx = pSLPriv->curDispIdx;
			pSLPriv->dispPaddr[0] = 0;
			pSLPriv->dispPaddr[1] = 0;
		} else {
			/* case c -> b, destory top layer */
			dbg(DBG_DEBUG, "free %d memory disppaddr 0x%x for pre layer\n", pSLPriv->dispMinfo.size, pSLPriv->dispPaddr[0]);
			ioctl(pSLPriv->fdIpu, IPU_FREE_MEM, &(pSLPriv->dispMinfo));
			pPreSLPriv->dispPaddr[0] = pSLPriv->dispPaddr[0];
			pPreSLPriv->dispPaddr[1] = pSLPriv->dispPaddr[1];
			pPreSLPriv->curDispIdx = pSLPriv->curDispIdx;
			pSLPriv->dispPaddr[0] = 0;
			pSLPriv->dispPaddr[1] = 0;
		}
	}

	if (pSL->bufPaddr)
		free(pSL->bufPaddr);
	if (pSL->bufVaddr)
		free(pSL->bufVaddr);
	if (pSLPriv->bufMinfo)
		free(pSLPriv->bufMinfo);
	if (pSL->bufAlphaPaddr)
		free(pSL->bufAlphaPaddr);
	if (pSL->bufAlphaVaddr)
		free(pSL->bufAlphaVaddr);
	if (pSLPriv->bufAlphaMinfo)
		free(pSLPriv->bufAlphaMinfo);

	close(pSLPriv->fdIpu);
}

SLRetCode PreScreenLayerIPC(char *pFbdev)
{
	SLRetCode ret = E_RET_SUCCESS;
	int	shmID;
	struct	stat shmStat;

	dbg(DBG_DEBUG, "PreScreenLayerIPC begin!\n");
	/* Create one new semaphore or opens an existing semaphore */
	semID = sem_open(semName, O_CREAT, 0666, 1);
	if(SEM_FAILED == semID){
		dbg(DBG_ERR, "can not open the semaphore for : IPU_SL_SEM_NAME!\n");
		ret = E_RET_IPC_SEM_OPEN_FAILED;
		goto pre_err0;
	}

	sem_wait(semID);

	/* Create one new shm or get one existing shm object's ID */
	if(strstr(pFbdev,"fb1"))
		strcpy(shmName, "shm_fb1");
	else if(strstr(pFbdev,"fb2"))
		strcpy(shmName, "shm_fb2");

	shmID = shm_open(shmName, O_RDWR|O_CREAT, 0666);
	if(shmID == -1){
		dbg(DBG_ERR, "can not open the shared memory for : %s!\n",pFbdev);
		ret = E_RET_IPC_SHM_FAILED;
		sem_unlink(semName);
		goto pre_err1;
	}
	/* Get special size shm */
	ftruncate(shmID,3 * sizeof(ScreenLayerPriv));
	/* Connect to the shm */
	fstat(shmID, &shmStat);

	if(vshmSLPriv == NULL)
	{
		vshmSLPriv = (ScreenLayerPriv *)mmap(NULL,shmStat.st_size,PROT_READ|PROT_WRITE,MAP_SHARED,shmID,0);
		dbg(DBG_DEBUG, "PreScreenLayerIPC Memory map done !\n");
	}

	if(vshmSLPriv == MAP_FAILED || vshmSLPriv ==NULL){
		dbg(DBG_ERR, "shm mmap failed!\n");
		ret = E_RET_IPC_SHM_FAILED;
		sem_unlink(semName);
		goto pre_err1;
	}
pre_err1:
	sem_post(semID);
	dbg(DBG_DEBUG, "PreScreenLayerIPC end!\n");
pre_err0:
	return ret;
}
SLRetCode CreateScreenLayer(ScreenLayer *pSL, u8 nBufNum)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv;
	int	curShmPrivID;
	int	i, primaryId = (int)(pSL->pPrimary);

	if ((primaryId != 0) && (primaryId != 1)) {
		dbg(DBG_ERR, "Primary Id error!\n");
		ret = E_RET_PRIMARY_ERR;
		goto done;
	}

	if(vshmSLPriv == NULL)
		ret = PreScreenLayerIPC(pSL->fbdev);
	if(ret != E_RET_SUCCESS)
	{
		dbg(DBG_ERR, "Prepared semaphore & shm failed !\n");
		goto done;
	}
	sem_wait(semID);
	pthread_counter++;

	/* Alloc shared memory for current Layer private struct */
	/*
	**   layour of shared memory
	**
	**   Primary    Second     Third
	**ID:    1          2          3
	**  |----------|----------|----------|
	*/

	if (primaryId == 1) {
		/* Non Primary SL*/
		ScreenLayerPriv *pPriSLPriv = vshmSLPriv;
		ScreenLayerPriv *pCurSLPriv;

		if(pPriSLPriv->nextLayerId == 0){
			/* The seconde layer*/
			pSLPriv = vshmSLPriv + 1;
			curShmPrivID = 2;
		}else{
			/* The third layer */
			pSLPriv = vshmSLPriv + 2;
			curShmPrivID = 3;
		}
		memset(pSLPriv, 0, sizeof(ScreenLayerPriv));
		pSL->pPriv = (void *)curShmPrivID;
		pSLPriv->layerID = curShmPrivID;

		if (!pPriSLPriv->isPrimary) {
			dbg(DBG_ERR, "new screen layer should created based on a primary one!\n");
			ret = E_RET_PRIMARY_ERR;
			goto err;
		}

		if ((pSL->screenRect.left >= pPriSLPriv->screenRect.right) ||
			(pSL->screenRect.right > pPriSLPriv->screenRect.right) ||
			(pSL->screenRect.top  >= pPriSLPriv->screenRect.bottom) ||
			(pSL->screenRect.bottom> pPriSLPriv->screenRect.bottom)) {
			dbg(DBG_ERR, "new screen layer is bigger than primary one!\n");
			ret = E_RET_RECT_OVERFLOW;
			goto err;
		}

		pCurSLPriv = pPriSLPriv;
		while (pCurSLPriv->nextLayerId) {
			pCurSLPriv = vshmSLPriv + (pCurSLPriv->nextLayerId-1);
		}
		pCurSLPriv->nextLayerId = pSLPriv->layerID;
		pSLPriv->preLayerId = pCurSLPriv->layerID ;

		pSLPriv->isPrimary = 0;
	} else {
		/* Primary SL */
		/* shm initialization */
		memset(vshmSLPriv, 0, 3*sizeof(ScreenLayerPriv));

		pSLPriv = vshmSLPriv;
		curShmPrivID = 1;
		pSL->pPriv = (void *)curShmPrivID;
		pSLPriv->layerID = curShmPrivID;

		if (pSL->supportSepLocalAlpha) {
			dbg(DBG_ERR, "primary screen layer should not support local alpha blending!\n");
			ret = E_RET_PRIMARY_ERR;
			goto err;
		}

		pSLPriv->isPrimary = 1;
	}

	pSLPriv->bufNum = nBufNum;

	ret = _MemAllocSL(pSL);
	/* Back up SL infor from external to private struct */
	pSLPriv->screenRect.left = pSL->screenRect.left;
	pSLPriv->screenRect.top  = pSL->screenRect.top;
	pSLPriv->screenRect.right  = pSL->screenRect.right;
	pSLPriv->screenRect.bottom = pSL->screenRect.bottom;
	pSLPriv->fmt = pSL->fmt;
	pSLPriv->supportSepLocalAlpha = pSL->supportSepLocalAlpha;
	strcpy(pSLPriv->fbdev, pSL->fbdev);
	for(i=0;i<nBufNum;i++)
	{
		pSLPriv->bufPaddr[i]      = pSL->bufPaddr[i];
		if (pSL->supportSepLocalAlpha)
			pSLPriv->bufAlphaPaddr[i] = pSL->bufAlphaPaddr[i];
	}
err:
	sem_post(semID);
done:
	return ret;
}

SLRetCode DestoryScreenLayer(ScreenLayer *pSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv + (int)pSL->pPriv-1);
	ScreenLayerPriv *pPreSLPriv, *pNextSLPriv;

	if (pSLPriv->isPrimary && pSLPriv->nextLayerId) {
		dbg(DBG_ERR, "Err: destory primary with sub layer, pls destory sub layer first!\n");
		ret = E_RET_DESTORY_PRI_WITH_SUBSL;
		goto done;
	}

	sem_wait(semID);

	_MemFreeSL(pSL);

	if (pSLPriv->preLayerId) {
		if (pSLPriv->nextLayerId) {
			pPreSLPriv  = (ScreenLayerPriv *)(vshmSLPriv + pSLPriv->preLayerId-1);
			pNextSLPriv = (ScreenLayerPriv *)(vshmSLPriv + pSLPriv->nextLayerId-1);
			pPreSLPriv->nextLayerId = pSLPriv->nextLayerId;
			pNextSLPriv->preLayerId = pSLPriv->preLayerId;
		} else {
			pPreSLPriv = (ScreenLayerPriv *)(vshmSLPriv + pSLPriv->preLayerId-1);
			pPreSLPriv->nextLayerId = 0;
		}
	}
	pthread_counter--;
	if(pthread_counter == 0)
	{
		if(pSLPriv->isPrimary)
		{
			munmap(vshmSLPriv, 3*sizeof(ScreenLayerPriv));
			vshmSLPriv = NULL;
			sem_post(semID);
			sem_close(semID);
			shm_unlink(shmName);
		}
		else
		{
			munmap(vshmSLPriv, 3*sizeof(ScreenLayerPriv));
			vshmSLPriv = NULL;
			sem_post(semID);
		}
		goto done;
	}

	sem_post(semID);
done:
	return ret;
}

SLRetCode LoadScreenLayer(ScreenLayer *pSL, LoadParam *pParam, u8 nBufIdx)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv + (int)pSL->pPriv-1);
	ipu_lib_handle_t ipu_handle;
	ipu_lib_input_param_t input;
	ipu_lib_output_param_t output;
	int mode;

	memset(&ipu_handle, 0, sizeof(ipu_lib_handle_t));
	memset(&input, 0, sizeof(ipu_lib_input_param_t));
	memset(&output, 0, sizeof(ipu_lib_output_param_t));

	if (nBufIdx >= pSLPriv->bufNum) {
		ret = E_RET_BUFIDX_ERR;
		goto done;
	}


	if ((pParam->srcRect.left >=  pParam->srcWidth) ||
		(pParam->srcRect.right > pParam->srcWidth) ||
		(pParam->srcRect.top >= pParam->srcHeight) ||
		(pParam->srcRect.bottom > pParam->srcHeight)){
		dbg(DBG_WARNING, "LoadScreenLayer src rect size not fit!\n")
		pParam->srcRect.left = 0;
		pParam->srcRect.top = 0;
		pParam->srcRect.right = pParam->srcWidth;
		pParam->srcRect.bottom = pParam->srcHeight;
	}

	if ((pParam->destRect.left >=  (pSL->screenRect.right - pSL->screenRect.left)) ||
		(pParam->destRect.right > (pSL->screenRect.right - pSL->screenRect.left)) ||
		(pParam->destRect.top >= (pSL->screenRect.bottom - pSL->screenRect.top)) ||
		(pParam->destRect.bottom > (pSL->screenRect.bottom - pSL->screenRect.top))){
		dbg(DBG_WARNING, "LoadScreenLayer dest rect size not fit!\n")
		pParam->destRect.left = 0;
		pParam->destRect.top = 0;
		pParam->destRect.right = pSL->screenRect.right - pSL->screenRect.left;
		pParam->destRect.bottom = pSL->screenRect.bottom - pSL->screenRect.top;
	}

	mode = OP_NORMAL_MODE | TASK_PP_MODE;
        input.width = pParam->srcWidth;
        input.height = pParam->srcHeight;
	input.input_crop_win.pos.x = pParam->srcRect.left;
	input.input_crop_win.pos.y = pParam->srcRect.top;
	input.input_crop_win.win_w = pParam->srcRect.right - pParam->srcRect.left;
	input.input_crop_win.win_h = pParam->srcRect.bottom - pParam->srcRect.top;
        input.fmt = pParam->srcFmt;
	input.user_def_paddr[0] = pParam->srcPaddr;

	output.width = pSL->screenRect.right -  pSL->screenRect.left;
	output.height = pSL->screenRect.bottom -  pSL->screenRect.top;
	output.output_win.pos.x = pParam->destRect.left;
	output.output_win.pos.y = pParam->destRect.top;
	output.output_win.win_w = pParam->destRect.right - pParam->destRect.left;
	output.output_win.win_h = pParam->destRect.bottom - pParam->destRect.top;
	output.fmt = pSL->fmt;
	output.rot = pParam->destRot;
	output.user_def_paddr[0] = pSL->bufPaddr[nBufIdx];

	sem_wait(semID);
	if (mxc_ipu_lib_task_init(&input, NULL, &output, NULL, mode, &ipu_handle) < 0) {
		ret = E_RET_TASK_SETUP_ERR;
		goto done;
	}

	if (mxc_ipu_lib_task_buf_update(&ipu_handle, 0, 0, 0, 0, 0) < 0) {
		ret = E_RET_TASK_RUN_ERR;
		goto done;
	}

	mxc_ipu_lib_task_uninit(&ipu_handle);
	sem_post(semID);

	yield();
done:
	return ret;
}

SLRetCode LoadAlphaPoint(ScreenLayer *pSL, u32 x, u32 y, u8 alphaVal, u8 nBufIdx)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv +(int)pSL->pPriv-1);
	u8 *pPointAlphaVal;

	if (nBufIdx >= pSLPriv->bufNum) {
		ret = E_RET_BUFIDX_ERR;
		goto err;
	}

	if (!pSLPriv->sepAlphaLocalEnable || !pSL->supportSepLocalAlpha) {
		dbg(DBG_ERR, "local alpha blending is disabled!\n");
		ret = E_RET_LOCAL_ALPHA_BLENDING_DISABLE;
		goto err;
	}

	if (!pSL->bufAlphaVaddr[nBufIdx]) {
		dbg(DBG_ERR, "alpha buffer is not allocated!\n");
		ret = E_RET_ALPHA_BUF_NOT_ALLOC_ERR;
		goto err;
	}

	pPointAlphaVal = (u8 *)(pSL->bufAlphaVaddr[nBufIdx] +
	       (pSL->screenRect.right - pSL->screenRect.left)*y + x);

	*pPointAlphaVal = alphaVal;
err:
	return ret;
}

SLRetCode FlipScreenLayerBuf(ScreenLayer *pSL, u8 nBufIdx)
{
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv + (int)pSL->pPriv-1);

	if (nBufIdx >= pSLPriv->bufNum)
		return E_RET_FLIP_ERR;

	sem_wait(semID);
	pSLPriv->curBufIdx = nBufIdx;
	sem_post(semID);

	return E_RET_SUCCESS;
}

SLRetCode _CopyScreenLayer(ScreenLayerPriv *pSrcSLPriv, ScreenLayerPriv *pTgtSLPriv)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pPriSLPriv;
	ipu_lib_handle_t ipu_handle;
	ipu_lib_input_param_t input;
	ipu_lib_output_param_t output;
	s32 mode;

	memset(&ipu_handle, 0, sizeof(ipu_lib_handle_t));
	memset(&input, 0, sizeof(ipu_lib_input_param_t));
	memset(&output, 0, sizeof(ipu_lib_output_param_t));

	/* Top SL should show to fb */
	if (!pTgtSLPriv->nextLayerId)
		pTgtSLPriv->curDispIdx = pTgtSLPriv->curDispIdx ? 0 : 1;

	pPriSLPriv = vshmSLPriv;

	mode = OP_NORMAL_MODE | TASK_PP_MODE;
        input.width = output.width = pPriSLPriv->screenRect.right - pPriSLPriv->screenRect.left;
        input.height = output.height = pPriSLPriv->screenRect.bottom - pPriSLPriv->screenRect.top;
        input.fmt = output.fmt = pPriSLPriv->fmt;
	if(pSrcSLPriv->isPrimary)
		input.user_def_paddr[0] = pSrcSLPriv->bufPaddr[pSrcSLPriv->curBufIdx];
	else
		input.user_def_paddr[0] = pSrcSLPriv->dispPaddr[pSrcSLPriv->curDispIdx];
	output.user_def_paddr[0] = pTgtSLPriv->dispPaddr[pTgtSLPriv->curDispIdx];

	if (mxc_ipu_lib_task_init(&input, NULL, &output, NULL, mode, &ipu_handle) < 0) {
		ret = E_RET_TASK_SETUP_ERR;
		goto done;
	}

	if (mxc_ipu_lib_task_buf_update(&ipu_handle, 0, 0, 0, 0, 0) < 0) {
		ret = E_RET_TASK_RUN_ERR;
		goto done;
	}

	mxc_ipu_lib_task_uninit(&ipu_handle);

	dbg(DBG_DEBUG, "Copy screen layer in %d %d, from 0x%x to 0x%x\n", input.width, input.height,
			input.user_def_paddr[0], output.user_def_paddr[0]);
done:
	return ret;
}

SLRetCode _CombScreenLayers(ScreenLayerPriv *pBotSLPriv, ScreenLayerPriv *pTopSLPriv)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pPriSLPriv;
	ipu_lib_handle_t ipu_handle;
	ipu_lib_input_param_t input;
	ipu_lib_overlay_param_t overlay;
	ipu_lib_output_param_t output;
	s32 mode;

	memset(&ipu_handle, 0, sizeof(ipu_lib_handle_t));
	memset(&input, 0, sizeof(ipu_lib_input_param_t));
	memset(&overlay, 0, sizeof(ipu_lib_overlay_param_t));
	memset(&output, 0, sizeof(ipu_lib_output_param_t));

	pPriSLPriv = vshmSLPriv;

	if (pTopSLPriv->alphaGlobalEnable && (pTopSLPriv->alpha == 255)
		&& !pTopSLPriv->keyColorEnable) {
		/* this case we can do copy directly, no combination needed*/
		dbg(DBG_DEBUG, "Do copy directly for Comb!\n");

		mode = OP_NORMAL_MODE | TASK_PP_MODE;

		/* top/overlay layer (graphic) */
		input.width = pTopSLPriv->screenRect.right - pTopSLPriv->screenRect.left;
		input.height = pTopSLPriv->screenRect.bottom - pTopSLPriv->screenRect.top;
		input.fmt = pTopSLPriv->fmt;
		input.user_def_paddr[0] = pTopSLPriv->bufPaddr[pTopSLPriv->curBufIdx];

		/* output */
		output.width = pPriSLPriv->screenRect.right - pPriSLPriv->screenRect.left;
		output.height = pPriSLPriv->screenRect.bottom - pPriSLPriv->screenRect.top;
		output.output_win.pos.x = pTopSLPriv->screenRect.left;
		output.output_win.pos.y = pTopSLPriv->screenRect.top;
		output.output_win.win_w = pTopSLPriv->screenRect.right - pTopSLPriv->screenRect.left;
		output.output_win.win_h = pTopSLPriv->screenRect.bottom - pTopSLPriv->screenRect.top;
		output.fmt = pPriSLPriv->fmt;
		output.user_def_paddr[0] = pTopSLPriv->dispPaddr[pTopSLPriv->curDispIdx];

		if (mxc_ipu_lib_task_init(&input, NULL, &output, NULL, mode, &ipu_handle) < 0) {
			ret = E_RET_TASK_SETUP_ERR;
			goto done;
		}
	} else {
		dbg(DBG_DEBUG, "Use IC Comb!\n");

		mode = OP_NORMAL_MODE | TASK_PP_MODE;
		/* bottom layer */
		input.width = pPriSLPriv->screenRect.right - pPriSLPriv->screenRect.left;
		input.height = pPriSLPriv->screenRect.bottom - pPriSLPriv->screenRect.top;
		input.input_crop_win.pos.x = pTopSLPriv->screenRect.left;
		input.input_crop_win.pos.y = pTopSLPriv->screenRect.top;
		input.input_crop_win.win_w = pTopSLPriv->screenRect.right - pTopSLPriv->screenRect.left;
		input.input_crop_win.win_h = pTopSLPriv->screenRect.bottom - pTopSLPriv->screenRect.top;
		input.fmt = pPriSLPriv->fmt;
		if (pBotSLPriv->isPrimary)
			input.user_def_paddr[0] = pBotSLPriv->bufPaddr[pBotSLPriv->curBufIdx];
		else
			input.user_def_paddr[0] = pBotSLPriv->dispPaddr[pBotSLPriv->curDispIdx];

		/* top/overlay layer (graphic) */
		overlay.width = pTopSLPriv->screenRect.right - pTopSLPriv->screenRect.left;
		overlay.height = pTopSLPriv->screenRect.bottom - pTopSLPriv->screenRect.top;
		overlay.fmt = pTopSLPriv->fmt;
		overlay.user_def_paddr[0] = pTopSLPriv->bufPaddr[pTopSLPriv->curBufIdx];
		overlay.global_alpha_en = pTopSLPriv->alphaGlobalEnable;
		if (pTopSLPriv->sepAlphaLocalEnable &&
		    pTopSLPriv->supportSepLocalAlpha) {
			overlay.local_alpha_en = 1;
			overlay.user_def_alpha_paddr[0] = pTopSLPriv->bufAlphaPaddr[pTopSLPriv->curBufIdx];
		}
		overlay.key_color_en = pTopSLPriv->keyColorEnable;
		overlay.alpha = pTopSLPriv->alpha;
		overlay.key_color = pTopSLPriv->keyColor;

		/* output */
		output.width = pPriSLPriv->screenRect.right - pPriSLPriv->screenRect.left;
		output.height = pPriSLPriv->screenRect.bottom - pPriSLPriv->screenRect.top;
		output.output_win.pos.x = pTopSLPriv->screenRect.left;
		output.output_win.pos.y = pTopSLPriv->screenRect.top;
		output.output_win.win_w = pTopSLPriv->screenRect.right - pTopSLPriv->screenRect.left;
		output.output_win.win_h = pTopSLPriv->screenRect.bottom - pTopSLPriv->screenRect.top;
		output.fmt = pPriSLPriv->fmt;
		output.user_def_paddr[0] = pTopSLPriv->dispPaddr[pTopSLPriv->curDispIdx];

		if (mxc_ipu_lib_task_init(&input, &overlay, &output, NULL, mode, &ipu_handle) < 0) {
			ret = E_RET_TASK_SETUP_ERR;
			goto done;
		}
	}

	if (mxc_ipu_lib_task_buf_update(&ipu_handle, 0, 0, 0, 0, 0) < 0) {
		ret = E_RET_TASK_RUN_ERR;
		goto done;
	}

	mxc_ipu_lib_task_uninit(&ipu_handle);

	dbg(DBG_DEBUG, "Comb screen layer in [(%d,%d),(%d,%d)]\n", pTopSLPriv->screenRect.left,
		pTopSLPriv->screenRect.top, pTopSLPriv->screenRect.right, pTopSLPriv->screenRect.bottom);
done:
	return ret;
}

SLRetCode _UpdateFramebuffer(ScreenLayerPriv *pSLPriv)
{
	s32 fd_fb = 0;
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pPriSLPriv;
	struct fb_var_screeninfo fb_var;

	pPriSLPriv = vshmSLPriv;

	if ((fd_fb = open(pPriSLPriv->fbdev, O_RDWR, 0)) < 0) {
		ret = E_RET_DEV_FAIL;
		goto done;
	}

	if (ioctl(fd_fb, FBIOGET_VSCREENINFO, &fb_var) < 0) {
		ret = E_RET_DEV_FAIL;
		goto done;
	}

	if (pSLPriv->curDispIdx == 0)
		fb_var.yoffset = 0;
	else
		fb_var.yoffset = fb_var.yres;

	if (ioctl(fd_fb, FBIOPAN_DISPLAY, &fb_var) < 0) {
		ret = E_RET_DEV_FAIL;
		goto done;
	}
	dbg(DBG_DEBUG, "update fb: pan display offset %d\n", fb_var.yoffset);
done:
	if (fd_fb)
		close(fd_fb);
	return ret;
}

SLRetCode UpdateScreenLayer(ScreenLayer *pSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv + (int)pSL->pPriv-1);
	ScreenLayerPriv *pCurSLPriv;

	sem_wait(semID);
	/* primary update? */
	if (pSLPriv->isPrimary && !pSLPriv->nextLayerId) {
		/* there is only primary, update it only */
		dbg(DBG_DEBUG, "Update primary layer only, just copy!\n");
		pCurSLPriv = pSLPriv;
		ret = _CopyScreenLayer(pCurSLPriv, pCurSLPriv);
		if (ret != E_RET_SUCCESS)
			goto done;
	} else {
		/* update from primary to top SL*/
		dbg(DBG_DEBUG, "Update multi layers, from primary to top!\n");

		pCurSLPriv = vshmSLPriv;
		while(pCurSLPriv->nextLayerId) {
			ret = _CopyScreenLayer(pCurSLPriv, (vshmSLPriv + pCurSLPriv->nextLayerId-1));
			if (ret != E_RET_SUCCESS)
				goto done;

			ret = _CombScreenLayers(pCurSLPriv, (vshmSLPriv + pCurSLPriv->nextLayerId -1));
			if (ret != E_RET_SUCCESS)
				goto done;
			pCurSLPriv = (ScreenLayerPriv *)(vshmSLPriv + pCurSLPriv->nextLayerId -1);
		}
	}

	ret = _UpdateFramebuffer(pCurSLPriv);
	sem_post(semID);

	yield();
done:
	return ret;
}

SLRetCode SetScreenLayer(ScreenLayer *pSL, SetMethodType eType, void *setData)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)(vshmSLPriv + (int)pSL->pPriv-1);

	sem_wait(semID);
	switch (eType) {
	case E_SET_ALPHA:
	{
		MethodAlphaData *data = (MethodAlphaData *)setData;
		if (data->sepLocalAlphaEnable && data->globalAlphaEnable) {
			dbg(DBG_ERR, "global/local alpha blending confliction!\n");
			ret = E_RET_ALPHA_BLENDING_CONFLICT;
			goto err;
		}
		pSLPriv->alphaGlobalEnable = data->globalAlphaEnable;
		pSLPriv->sepAlphaLocalEnable = data->sepLocalAlphaEnable;
		pSLPriv->alpha = data->alpha;
		break;
	}
	case E_SET_COLORKEY:
	{
		MethodColorKeyData *data = (MethodColorKeyData *)setData;
		pSLPriv->keyColorEnable = data->enable;
		pSLPriv->keyColor = data->keyColor;
		break;
	}
	case E_ENABLE_LAYER:
		pSLPriv->layerEnable = *((u8 *)setData);
		break;
	default:
		ret = E_RET_NOSUCH_METHODTYPE;
	}
err:
	sem_post(semID);
	return ret;
}

/*
** Get the handle of Primaray screen layer, which will be used to create the others Non-primary screen layer.
**
** Input  : fbdev, this is the fixed id of frame buffer
** Return : The handle of the Primary Screen Layer
*/
void* GetPrimarySLHandle(char * pFbdev)
{
	SLRetCode ret = E_RET_SUCCESS;

	if(vshmSLPriv == NULL)
		ret = PreScreenLayerIPC(pFbdev);
	if(ret != E_RET_SUCCESS || vshmSLPriv == NULL)
	{
		dbg(DBG_ERR, "Prepared semaphore & shm failed !\n");
		return (void*)0;
	}

	sem_wait(semID);
	if(vshmSLPriv->isPrimary)
	{
		dbg(DBG_DEBUG, "GetPrimarySLHandle is OK!\n");
		sem_post(semID);
		return	(void *)1;
	}
	else
	{
		dbg(DBG_ERR, "GetPrimarySLHandle Error!\n");
		sem_post(semID);
		return  (void *)0;
	}
}

/*
** Get the width of Primary screen layer.
**
** Input  : pPrimaryHandle, this is the handle of primary screen layer
** Return : the width of Primary screen layer
*/
u32   GetPrimarySLWidth(void * pPrimaryHandle)
{
	return (vshmSLPriv->screenRect.left - vshmSLPriv->screenRect.right);
}

/*
** Get the height of Primary screen layer.
**
** Input  : pPrimaryHandle, this is the handle of primary screen layer
** Return : the height of Primary screen layer
*/
u32   GetPrimarySLHeight(void * pPrimaryHandle)
{
	return (vshmSLPriv->screenRect.bottom - vshmSLPriv->screenRect.top);
}
#ifdef __cplusplus
}
#endif

