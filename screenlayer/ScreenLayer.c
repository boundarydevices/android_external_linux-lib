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
#include <pthread.h>
#include <linux/ipu.h>
#include <linux/mxcfb.h>
#include <linux/videodev.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "ScreenLayer.h"
#include "mxc_ipu_hl_lib.h"

#define DBG_DEBUG		3
#define DBG_INFO		2
#define DBG_WARNING		1
#define DBG_ERR			0

static int debug_level = DBG_ERR;
#define dbg(flag, fmt, args...)	{ if(flag <= debug_level)  printf("%s:%d "fmt, __FILE__, __LINE__,##args); }

static pthread_mutex_t SLmutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	u8		isPrimary;
	u8 		bufNum;
	u8		curBufIdx;
	dma_addr_t	dispPaddr[2];
	u8		curDispIdx;
	ScreenLayer 	* pPreLayer;
	ScreenLayer 	* pNextLayer;
	u8		alphaEnable;
	u8		alpha;
	u8		keyColorEnable;
	u32		keyColor;
	u8		layerEnable;
	s32		fdIpu;
        ipu_mem_info 	* bufMinfo;
        ipu_mem_info 	dispMinfo;
} ScreenLayerPriv;

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

SLRetCode _MemAllocSL(ScreenLayer *pSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;
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
		ScreenLayerPriv *pPreSLPriv = (ScreenLayerPriv *)pSLPriv->pPreLayer->pPriv;

		if (pSLPriv->pPreLayer != pSL->pPrimary) {
			/* case b -> c */
			width = ((ScreenLayer *)pSL->pPrimary)->screenRect.right - ((ScreenLayer *)pSL->pPrimary)->screenRect.left;
			height = ((ScreenLayer *)pSL->pPrimary)->screenRect.bottom - ((ScreenLayer *)pSL->pPrimary)->screenRect.top;
			pPreSLPriv->dispMinfo.size = width/8*height*fmt_to_bpp(((ScreenLayer *)pSL->pPrimary)->fmt);
			if (ioctl(pPreSLPriv->fdIpu, IPU_ALOC_MEM, &(pPreSLPriv->dispMinfo)) < 0) {
				ret = E_RET_MEM_ALOC_FAIL;
				goto done;
			}

			pSLPriv->dispPaddr[0] = pPreSLPriv->dispPaddr[0];
			pSLPriv->dispPaddr[1] = pPreSLPriv->dispPaddr[1];
			pSLPriv->curDispIdx = pPreSLPriv->curDispIdx;
			pPreSLPriv->dispPaddr[0] = pPreSLPriv->dispMinfo.paddr;
			pPreSLPriv->dispPaddr[1] = 0;
			pPreSLPriv->curDispIdx = 0;

			dbg(DBG_DEBUG, "allocate %d memory paddr 0x%x for pre layer\n", pPreSLPriv->dispMinfo.size, pPreSLPriv->dispMinfo.paddr);
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
	}

	goto done;

err:
	if (pSL->bufPaddr)
		free(pSL->bufPaddr);
	if (pSL->bufVaddr)
		free(pSL->bufVaddr);
	if (pSLPriv->bufMinfo)
		free(pSLPriv->bufMinfo);
done:
	return ret;
}

void _MemFreeSL(ScreenLayer *pSL)
{
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;
	u8 i;

	for (i=0;i<pSLPriv->bufNum;i++) {
		dbg(DBG_DEBUG, "free %d memory paddr 0x%x, mmap to %p for current layer\n", pSLPriv->bufMinfo[i].size, pSL->bufPaddr[i], pSL->bufVaddr[i]);
		if (pSL->bufVaddr[i])
			munmap(pSL->bufVaddr[i], pSLPriv->bufMinfo[i].size);
		ioctl(pSLPriv->fdIpu, IPU_FREE_MEM, &(pSLPriv->bufMinfo[i]));
	}

	if (pSLPriv->pPreLayer && pSLPriv->pNextLayer) {
		/* case c -> b, destory middle layer */
		dbg(DBG_DEBUG, "free %d memory disppaddr 0x%x for current layer\n", pSLPriv->dispMinfo.size, pSLPriv->dispPaddr[0]);
		ioctl(pSLPriv->fdIpu, IPU_FREE_MEM, &(pSLPriv->dispMinfo));
	} else if (pSLPriv->pPreLayer) {
		ScreenLayerPriv *pPreSLPriv = (ScreenLayerPriv *)pSLPriv->pPreLayer->pPriv;
		if (pSLPriv->pPreLayer == pSL->pPrimary) {
			/* case b -> a */
			pPreSLPriv->dispPaddr[0] = pSLPriv->dispPaddr[0];
			pPreSLPriv->dispPaddr[1] = pSLPriv->dispPaddr[1];
			pPreSLPriv->curDispIdx = pSLPriv->curDispIdx;
			pSLPriv->dispPaddr[0] = 0;
			pSLPriv->dispPaddr[1] = 0;
		} else {
			/* case c -> b, destory top layer */
			dbg(DBG_DEBUG, "free %d memory disppaddr 0x%x for pre layer\n", pPreSLPriv->dispMinfo.size, pPreSLPriv->dispPaddr[0]);
			ioctl(pPreSLPriv->fdIpu, IPU_FREE_MEM, &(pPreSLPriv->dispMinfo));
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

	close(pSLPriv->fdIpu);
}

SLRetCode CreateScreenLayer(ScreenLayer *pSL, u8 nBufNum)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv;

	pSL->pPriv = (void *)malloc(sizeof(ScreenLayerPriv));
	memset(pSL->pPriv, 0, sizeof(ScreenLayerPriv));
	pSLPriv = (ScreenLayerPriv *)pSL->pPriv;

	if (pSL->pPrimary) {
		ScreenLayerPriv *pPriSLPriv = (ScreenLayerPriv *)((ScreenLayer *)pSL->pPrimary)->pPriv;
		ScreenLayerPriv *pCurSLPriv;
		ScreenLayer *pCurSL;

		if (!pPriSLPriv->isPrimary) {
			dbg(DBG_ERR, "new screen layer should created based on a primary one!\n");
			ret = E_RET_PRIMARY_ERR;
			goto done;
		}

		if ((pSL->screenRect.left >= ((ScreenLayer *)pSL->pPrimary)->screenRect.right) ||
			(pSL->screenRect.right > ((ScreenLayer *)pSL->pPrimary)->screenRect.right) ||
			(pSL->screenRect.top >= ((ScreenLayer *)pSL->pPrimary)->screenRect.bottom) ||
			(pSL->screenRect.bottom > ((ScreenLayer *)pSL->pPrimary)->screenRect.bottom)) {
			dbg(DBG_ERR, "new screen layer is bigger than primary one!\n");
			ret = E_RET_RECT_OVERFLOW;
			goto done;
		}

		pCurSL = (ScreenLayer *)pSL->pPrimary;
		pCurSLPriv = pPriSLPriv;
		while (pCurSLPriv->pNextLayer) {
			pCurSL = pCurSLPriv->pNextLayer;
			pCurSLPriv = (ScreenLayerPriv *)pCurSL->pPriv;
		}
		pCurSLPriv->pNextLayer = pSL;
		pSLPriv->pPreLayer = pCurSL;

		pSLPriv->isPrimary = 0;
	} else
		pSLPriv->isPrimary = 1;

	pSLPriv->bufNum = nBufNum;

	ret = _MemAllocSL(pSL);
done:
	return ret;
}

SLRetCode DestoryScreenLayer(ScreenLayer *pSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;
	ScreenLayerPriv *pPreSLPriv, *pNextSLPriv;

	if (pSLPriv->isPrimary && pSLPriv->pNextLayer) {
		dbg(DBG_ERR, "Err: destory primary with sub layer, pls destory sub layer first!\n");
		ret = E_RET_DESTORY_PRI_WITH_SUBSL;
		goto done;
	}

	_MemFreeSL(pSL);

	if (pSLPriv->pPreLayer) {
		if (pSLPriv->pNextLayer) {
			pPreSLPriv = (ScreenLayerPriv *)pSLPriv->pPreLayer->pPriv;
			pNextSLPriv = (ScreenLayerPriv *)pSLPriv->pNextLayer->pPriv;
			pPreSLPriv->pNextLayer = pSLPriv->pNextLayer;
			pNextSLPriv->pPreLayer = pSLPriv->pPreLayer;
		} else {
			pPreSLPriv = (ScreenLayerPriv *)pSLPriv->pPreLayer->pPriv;
			pPreSLPriv->pNextLayer = NULL;
		}
	}
	free(pSLPriv);
done:
	return ret;
}

SLRetCode LoadScreenLayer(ScreenLayer *pSL, LoadParam *pParam, u8 nBufIdx)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;
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

	pthread_mutex_lock(&SLmutex);

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
		pParam->srcRect.bottom = pSL->screenRect.bottom - pSL->screenRect.top;
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
	output.user_def_paddr[0] = pSL->bufPaddr[pSLPriv->curBufIdx];

	if (mxc_ipu_lib_task_init(&input, NULL, &output, NULL, mode, &ipu_handle) < 0) {
		ret = E_RET_TASK_SETUP_ERR;
		pthread_mutex_unlock(&SLmutex);
		goto done;
	}

	if (mxc_ipu_lib_task_buf_update(&ipu_handle, 0, 0, 0, 0) < 0) {
		ret = E_RET_TASK_RUN_ERR;
		pthread_mutex_unlock(&SLmutex);
		goto done;
	}

	mxc_ipu_lib_task_uninit(&ipu_handle);

	pthread_mutex_unlock(&SLmutex);

done:
	return ret;
}

SLRetCode FlipScreenLayerBuf(ScreenLayer *pSL, u8 nBufIdx)
{
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;

	if (nBufIdx >= pSLPriv->bufNum)
		return E_RET_FLIP_ERR;

	pSLPriv->curBufIdx = nBufIdx;

	return E_RET_SUCCESS;
}

SLRetCode _CopyScreenLayer(ScreenLayer *pSrcSL, ScreenLayer *pTgtSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSrcSLPriv = (ScreenLayerPriv *)pSrcSL->pPriv;
	ScreenLayerPriv *pTgtSLPriv = (ScreenLayerPriv *)pTgtSL->pPriv;
	ScreenLayer *pPriSL;
	ipu_lib_handle_t ipu_handle;
	ipu_lib_input_param_t input;
	ipu_lib_output_param_t output;
	s32 mode;

	memset(&ipu_handle, 0, sizeof(ipu_lib_handle_t));
	memset(&input, 0, sizeof(ipu_lib_input_param_t));
	memset(&output, 0, sizeof(ipu_lib_output_param_t));

	/* Top SL should show to fb */
	if (!pTgtSLPriv->pNextLayer)
		pTgtSLPriv->curDispIdx = pTgtSLPriv->curDispIdx ? 0 : 1;

	if (pSrcSLPriv->isPrimary)
		pPriSL = pSrcSL;
	else
		pPriSL = (ScreenLayer *)pSrcSL->pPrimary;

	mode = OP_NORMAL_MODE | TASK_PP_MODE;
        input.width = output.width = pPriSL->screenRect.right - pPriSL->screenRect.left;
        input.height = output.height = pPriSL->screenRect.bottom - pPriSL->screenRect.top;
        input.fmt = output.fmt = pPriSL->fmt;
	if (pSrcSL == pPriSL)
		input.user_def_paddr[0] = pSrcSL->bufPaddr[pSrcSLPriv->curBufIdx];
	else
		input.user_def_paddr[0] = pSrcSLPriv->dispPaddr[pSrcSLPriv->curDispIdx];
	output.user_def_paddr[0] = pTgtSLPriv->dispPaddr[pTgtSLPriv->curDispIdx];

	if (mxc_ipu_lib_task_init(&input, NULL, &output, NULL, mode, &ipu_handle) < 0) {
		ret = E_RET_TASK_SETUP_ERR;
		goto done;
	}

	if (mxc_ipu_lib_task_buf_update(&ipu_handle, 0, 0, 0, 0) < 0) {
		ret = E_RET_TASK_RUN_ERR;
		goto done;
	}

	mxc_ipu_lib_task_uninit(&ipu_handle);

	dbg(DBG_DEBUG, "Copy screen layer in %d %d, from 0x%x to 0x%x\n", input.width, input.height,
			input.user_def_paddr[0], output.user_def_paddr[0]);
done:
	return ret;
}

SLRetCode _CombScreenLayers(ScreenLayer *pBotSL, ScreenLayer *pTopSL)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pBotSLPriv = (ScreenLayerPriv *)pBotSL->pPriv;
	ScreenLayerPriv *pTopSLPriv = (ScreenLayerPriv *)pTopSL->pPriv;
	ScreenLayer *pPriSL;
	ipu_lib_handle_t ipu_handle;
	ipu_lib_input_param_t input;
	ipu_lib_overlay_param_t overlay;
	ipu_lib_output_param_t output;
	s32 mode;

	memset(&ipu_handle, 0, sizeof(ipu_lib_handle_t));
	memset(&input, 0, sizeof(ipu_lib_input_param_t));
	memset(&overlay, 0, sizeof(ipu_lib_overlay_param_t));
	memset(&output, 0, sizeof(ipu_lib_output_param_t));

	if (pBotSLPriv->isPrimary)
		pPriSL = pBotSL;
	else
		pPriSL = (ScreenLayer *)pBotSL->pPrimary;

	if (pTopSLPriv->alphaEnable && (pTopSLPriv->alpha == 255)
		&& !pTopSLPriv->keyColorEnable) {
		/* this case we can do copy directly, no combination needed*/
		dbg(DBG_DEBUG, "Do copy directly for Comb!\n");

		mode = OP_NORMAL_MODE | TASK_PP_MODE;

		/* top/overlay layer (graphic) */
		input.width = pTopSL->screenRect.right - pTopSL->screenRect.left;
		input.height = pTopSL->screenRect.bottom - pTopSL->screenRect.top;
		input.fmt = pTopSL->fmt;
		input.user_def_paddr[0] = pTopSL->bufPaddr[pTopSLPriv->curBufIdx];

		/* output */
		output.width = pPriSL->screenRect.right - pPriSL->screenRect.left;
		output.height = pPriSL->screenRect.bottom - pPriSL->screenRect.top;
		output.output_win.pos.x = pTopSL->screenRect.left;
		output.output_win.pos.y = pTopSL->screenRect.top;
		output.output_win.win_w = pTopSL->screenRect.right - pTopSL->screenRect.left;
		output.output_win.win_h = pTopSL->screenRect.bottom - pTopSL->screenRect.top;
		output.fmt = pPriSL->fmt;
		output.user_def_paddr[0] = pTopSLPriv->dispPaddr[pTopSLPriv->curDispIdx];

		if (mxc_ipu_lib_task_init(&input, NULL, &output, NULL, mode, &ipu_handle) < 0) {
			ret = E_RET_TASK_SETUP_ERR;
			goto done;
		}
	} else {
		dbg(DBG_DEBUG, "Use IC Comb!\n");

		mode = OP_NORMAL_MODE | TASK_PP_MODE;
		/* bottom layer */
		input.width = pPriSL->screenRect.right - pPriSL->screenRect.left;
		input.height = pPriSL->screenRect.bottom - pPriSL->screenRect.top;
		input.input_crop_win.pos.x = pTopSL->screenRect.left;
		input.input_crop_win.pos.y = pTopSL->screenRect.top;
		input.input_crop_win.win_w = pTopSL->screenRect.right - pTopSL->screenRect.left;
		input.input_crop_win.win_h = pTopSL->screenRect.bottom - pTopSL->screenRect.top;
		input.fmt = pPriSL->fmt;
		if (pBotSL == pPriSL)
			input.user_def_paddr[0] = pBotSL->bufPaddr[pBotSLPriv->curBufIdx];
		else
			input.user_def_paddr[0] = pBotSLPriv->dispPaddr[pBotSLPriv->curDispIdx];

		/* top/overlay layer (graphic) */
		overlay.width = pTopSL->screenRect.right - pTopSL->screenRect.left;
		overlay.height = pTopSL->screenRect.bottom - pTopSL->screenRect.top;
		overlay.fmt = pTopSL->fmt;
		overlay.user_def_paddr[0] = pTopSL->bufPaddr[pTopSLPriv->curBufIdx];
		overlay.alpha_en = pTopSLPriv->alphaEnable;
		overlay.key_color_en = pTopSLPriv->keyColorEnable;
		overlay.alpha = pTopSLPriv->alpha;
		overlay.key_color = pTopSLPriv->keyColor;

		/* output */
		output.width = pPriSL->screenRect.right - pPriSL->screenRect.left;
		output.height = pPriSL->screenRect.bottom - pPriSL->screenRect.top;
		output.output_win.pos.x = pTopSL->screenRect.left;
		output.output_win.pos.y = pTopSL->screenRect.top;
		output.output_win.win_w = pTopSL->screenRect.right - pTopSL->screenRect.left;
		output.output_win.win_h = pTopSL->screenRect.bottom - pTopSL->screenRect.top;
		output.fmt = pPriSL->fmt;
		output.user_def_paddr[0] = pTopSLPriv->dispPaddr[pTopSLPriv->curDispIdx];

		if (mxc_ipu_lib_task_init(&input, &overlay, &output, NULL, mode, &ipu_handle) < 0) {
			ret = E_RET_TASK_SETUP_ERR;
			goto done;
		}
	}

	if (mxc_ipu_lib_task_buf_update(&ipu_handle, 0, 0, 0, 0) < 0) {
		ret = E_RET_TASK_RUN_ERR;
		goto done;
	}

	mxc_ipu_lib_task_uninit(&ipu_handle);

	dbg(DBG_DEBUG, "Comb screen layer in [(%d,%d),(%d,%d)]\n", pTopSL->screenRect.left,
		pTopSL->screenRect.top, pTopSL->screenRect.right, pTopSL->screenRect.bottom);
done:
	return ret;
}

SLRetCode _UpdateFramebuffer(ScreenLayer *pSL)
{
	s32 fd_fb = 0;
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;
	ScreenLayer *pPriSL;
	struct fb_var_screeninfo fb_var;

	if (pSLPriv->isPrimary)
		pPriSL = pSL;
	else
		pPriSL = (ScreenLayer *)pSL->pPrimary;

	if ((fd_fb = open(pPriSL->fbdev, O_RDWR, 0)) < 0) {
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
	ScreenLayer *pCurSL;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;
	ScreenLayerPriv *pCurSLPriv;

	pthread_mutex_lock(&SLmutex);

	/* primary update? */
	if (pSLPriv->isPrimary && !pSLPriv->pNextLayer) {
		/* there is only primary, update it only */
		dbg(DBG_DEBUG, "Update primary layer only, just copy!\n");
		pCurSL = pSL;
		ret = _CopyScreenLayer(pCurSL, pCurSL);
		if (ret != E_RET_SUCCESS)
			goto done;
	} else {
		/* update from primary to top SL*/
		dbg(DBG_DEBUG, "Update multi layers, from primary to top!\n");
		if (pSLPriv->isPrimary)
			pCurSL = pSL;
		else
			pCurSL = (ScreenLayer *)pSL->pPrimary;

		pCurSLPriv = (ScreenLayerPriv *)pCurSL->pPriv;
		while(pCurSLPriv->pNextLayer) {
			ret = _CopyScreenLayer(pCurSL, pCurSLPriv->pNextLayer);
			if (ret != E_RET_SUCCESS)
				goto done;

			ret = _CombScreenLayers(pCurSL, pCurSLPriv->pNextLayer);
			if (ret != E_RET_SUCCESS)
				goto done;
			pCurSL = pCurSLPriv->pNextLayer;
			pCurSLPriv = (ScreenLayerPriv *)pCurSL->pPriv;
		}
	}

	ret = _UpdateFramebuffer(pCurSL);

	pthread_mutex_unlock(&SLmutex);
done:
	return ret;
}

SLRetCode SetScreenLayer(ScreenLayer *pSL, SetMethodType eType, void *setData)
{
	SLRetCode ret = E_RET_SUCCESS;
	ScreenLayerPriv *pSLPriv = (ScreenLayerPriv *)pSL->pPriv;

	switch (eType) {
	case E_SET_ALPHA:
	{
		MethodAlphaData *data = (MethodAlphaData *)setData;
		pSLPriv->alphaEnable = data->enable;
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
	return ret;
}

#ifdef __cplusplus
}
#endif

