/*
 * Copyright (c) 2006, Chips & Media.  All rights reserved.
 *
 * Copyright (C) 2004-2016 Freescale Semiconductor, Inc.
 */

/* The following programs are the sole property of Freescale Semiconductor Inc.,
 * and contain its proprietary and confidential information. */

/*!
 * @file vpu_lib.c
 *
 * @brief This file implements codec API funcitons for VPU
 *
 * @ingroup VPU
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "vpu_reg.h"
#include "vpu_lib.h"
#include "vpu_util.h"
#include "vpu_io.h"
#include "vpu_debug.h"
#include "vpu_gdi.h"

#define IMAGE_ENDIAN			0
#define STREAM_ENDIAN			0

#define MAX_PIC_WIDTH			1920
#define MAX_PIC_HEIGHT			1088
/*
 * Alloc buffers of MAX resolution in seqinit,
 * in the case of dynamic resolution change
 */
#define ALLOC_MAX_RESOLUTION

/* If a frame is started, pendingInst is set to the proper instance. */
static CodecInst **ppendingInst;
int vpu_lib_dbg_level = 0;

Uint32 virt_codeBuf;
unsigned long *virt_paraBuf;
unsigned long *virt_paraBuf2;

extern vpu_mem_desc bit_work_addr;
extern semaphore_t *vpu_semap;
extern shared_mem_t *vpu_shared_mem;

extern void vpu_setting_iram();

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static __inline void EnterInit()
{
	pthread_mutex_lock(&lock);
}

static __inline void LeaveInit()
{
	pthread_mutex_unlock(&lock);
}

static __inline int is_mx6x_mjpg_codec(int codecMode)
{
	if (cpu_is_mx6x() && (codecMode == MJPG_DEC ||
			      codecMode == MJPG_ENC))
		return true;
	else
		return false;
}

/*!
 * @brief
 * This functure indicate whether processing(encoding/decoding) a frame
 * is completed or not yet.
 *
 * @return
 * @li 0: VPU hardware is idle.
 * @li Non-zero value: VPU hardware is busy processing a frame.
 */
int vpu_IsBusy()
{
	Uint32 val, vpu_busy = 0, jpu_busy = 0;
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;

	ENTER_FUNC();

	IOClkGateSet(true);

	vpu_busy = VpuReadReg(BIT_BUSY_FLAG);
	if (cpu_is_mx6x()) {
		pCodecInst = *ppendingInst;
		if (pCodecInst &&
		    (pCodecInst->codecMode == MJPG_ENC ||
		     pCodecInst->codecMode == MJPG_DEC)) {
			jpu_busy = 1;
			/* jpu is idle if DONE or ERROR interrupt received */
			val = VpuReadReg(MJPEG_PIC_STATUS_REG);
			if (val & (1 << INT_JPU_DONE) ||
			    val & (1 << INT_JPU_ERROR))
				jpu_busy = 0;
			else if (pCodecInst->codecMode == MJPG_DEC) {
				/* jpu is idle if quitCodec or rollBack is equal 1 */
				pDecInfo = &pCodecInst->CodecInfo.decInfo;
				if (pDecInfo->jpgInfo.quitCodec ||
				    pDecInfo->jpgInfo.rollBack)
					jpu_busy = 0;
			}
		}
	}
	IOClkGateSet(false);

	return (vpu_busy != 0 || jpu_busy != 0);
}

int vpu_WaitForInt(int timeout_in_ms)
{
	int ret;
	Uint32 bbcEnd, status, rdPtr, wrPtr;
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;

	ENTER_FUNC();

	ret = IOWaitForInt(timeout_in_ms);
	dprintf(4, "ret of IOWaitForInt %d\n", ret);

	if (cpu_is_mx6x()) {
		pCodecInst = *ppendingInst;
		if (pCodecInst && (pCodecInst->codecMode == MJPG_DEC)) {
			pDecInfo = &pCodecInst->CodecInfo.decInfo;

			IOClkGateSet(true);
			status = VpuReadReg(MJPEG_PIC_STATUS_REG);
			if (pDecInfo->jpgInfo.lineBufferMode) {

				rdPtr = VpuReadReg(MJPEG_BBC_RD_PTR_REG);
				bbcEnd = VpuReadReg(MJPEG_BBC_END_ADDR_REG);

				dprintf(4, "status 0x%lx, rdPtr 0x%lx, bbcEnd 0x%lx\n", status, rdPtr, bbcEnd);
				if (status & 0x3) {
					dprintf(4, "pic done\n");
					ret = 0;
				} else if (rdPtr > bbcEnd-256-256) {
					warn_msg("pic was forced to be done\n");
					vpu_mx6_hwreset(); /* reset JPU */
					pDecInfo->jpgInfo.quitCodec = 1;
					ret = 0;
				} else {
					dprintf(4, "pic not done, wait\n");
					ret = -1;
				}
			} else {
				rdPtr = VpuReadReg(MJPEG_BBC_RD_PTR_REG);
				bbcEnd = VpuReadReg(MJPEG_BBC_END_ADDR_REG);

				dprintf(4, "status 0x%lx, rdPtr 0x%lx, bbcEnd 0x%lx\n", status, rdPtr, bbcEnd);
				if (status & 1 << INT_JPU_BIT_BUF_EMPTY) {
					/* JPU_EMPTY interrupt is received */
					if (rdPtr == pDecInfo->streamBufEndAddr) {
						dprintf(4, "wrap around in decoding\n");
						VpuWriteReg(MJPEG_BBC_CUR_POS_REG, 0);
						wrPtr = pDecInfo->streamWrPtr;
						if (pDecInfo->streamEndflag) {
							/* set to unreachable position to disable BBC interrupt */
							VpuWriteReg(MJPEG_BBC_END_ADDR_REG, wrPtr+256);
							pDecInfo->jpgInfo.lastRound = 1;
						}
						else
							VpuWriteReg(MJPEG_BBC_END_ADDR_REG,
									wrPtr & 0xFFFFFE00);
					} else if (rdPtr == bbcEnd && !(status & 0x3)) {
						dprintf(4, "need bs, streamEndflag %d\n", pDecInfo->streamEndflag);
						vpu_mx6_hwreset(); /* reset JPU */

						VpuWriteReg(MJPEG_PIC_STATUS_REG,
								1 << INT_JPU_BIT_BUF_EMPTY);
						if (pDecInfo->streamEndflag)
							pDecInfo->jpgInfo.quitCodec = 1;
						else {
							/* Input bitstream isn't enough for one frame */
							pDecInfo->jpgInfo.rollBack = 1;
							pDecInfo->jpgInfo.consumeByte = 0;
						}
						IOClkGateSet(false);
						log_time(pCodecInst->instIndex, PIC_DONE);
						return 0;
					}
					VpuWriteReg(MJPEG_PIC_STATUS_REG, 1 << INT_JPU_BIT_BUF_EMPTY);
					if (status & 0x3)
						ret = 0;
					else
						ret = -1;
				} else if (pDecInfo->streamEndflag && !status && (rdPtr >= bbcEnd-256)) {
					warn_msg("forced to quit\n");
					vpu_mx6_hwreset(); /* reset JPU */

					pDecInfo->jpgInfo.quitCodec = 1;
					ret = 0;
				} else if (status & 0x3) {
					ret = 0;
					dprintf(4, "pic done\n");
				} else {
					ret = -1;
					dprintf(4, "pic not done, wait\n");
				}
			}
			IOClkGateSet(false);
		} else if (pCodecInst && (pCodecInst->codecMode == MJPG_ENC)) {
			IOClkGateSet(true);
			status = VpuReadReg(MJPEG_PIC_STATUS_REG);
			wrPtr = VpuReadReg(MJPEG_BBC_WR_PTR_REG);
			bbcEnd = VpuReadReg(MJPEG_BBC_END_ADDR_REG);

			dprintf(4, "status 0x%lx, wrPtr 0x%lx, bbcEnd 0x%lx\n", status, wrPtr, bbcEnd);
			if (status & 0x3) {
				dprintf(4, "pic done\n");
				ret = 0;
			} else {
				dprintf(4, "pic not done, wait\n");
				ret = -1;
			}
			IOClkGateSet(false);
		} else { /* VPU */
			IOClkGateSet(true);
			if (VpuReadReg(BIT_BUSY_FLAG)) {
				if (ret == 0)
					dprintf(4, "intr received but VPU is still busy\n");
				ret = -1;
			}
			else
				ret = 0;
			IOClkGateSet(false);
		}
	}

	if (ret == 0) {
		pCodecInst = *ppendingInst;
		log_time(pCodecInst->instIndex, PIC_DONE);
	}

	return ret;
}

/*!
 * @brief VPU initialization.
 * This function initializes VPU hardware and proper data structures/resources.
 * The user must call this function only once before using VPU codec.
 *
 * @param  cb  callback function if needed
 *
 * @return  This function always returns RETCODE_SUCCESS.
 */
RetCode vpu_Init(void *cb)
{
	int i, err;
	volatile Uint32 data;
	Uint16 *bit_code = NULL;
	PhysicalAddress tempBuffer, codeBuffer, paraBuffer;
	char *dbg_env;

	dbg_env = getenv("VPU_LIB_DBG");
        if (dbg_env)
                vpu_lib_dbg_level = atoi(dbg_env);
	else
		vpu_lib_dbg_level = 0;

	ENTER_FUNC();
	EnterInit();
	err = IOSystemInit(cb);
	LeaveInit();
	if (err) {
		err_msg("IOSystemInit() failure.\n");
		return RETCODE_FAILURE;
	}

	if (!LockVpu(vpu_semap)) {
		EnterInit();
		err = IOSystemShutdown();
		LeaveInit();
		return RETCODE_FAILURE_TIMEOUT;
	}
	codeBuffer = bit_work_addr.phy_addr;
	tempBuffer = codeBuffer + CODE_BUF_SIZE;
	paraBuffer = tempBuffer + TEMP_BUF_SIZE + PARA_BUF2_SIZE;

	virt_codeBuf = (Uint32) (bit_work_addr.virt_uaddr);
	virt_paraBuf = (unsigned long *)(virt_codeBuf + CODE_BUF_SIZE +
					 TEMP_BUF_SIZE + PARA_BUF2_SIZE);
	virt_paraBuf2 = (unsigned long *)(virt_codeBuf + CODE_BUF_SIZE +
					  TEMP_BUF_SIZE);

	ppendingInst = (CodecInst **) (&vpu_shared_mem->pendingInst);

	if (!isVpuInitialized()) {
		bit_code = malloc(MAX_FW_BINARY_LEN * sizeof(Uint16));
		if (DownloadBitCodeTable((unsigned long *)virt_codeBuf,
				bit_code) != RETCODE_SUCCESS) {
			free(bit_code);
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}

		IOClkGateSet(true);

		for (i = 0; i < 64; i++)
			VpuWriteReg(BIT_CODE_BUF_ADDR + (i * 4), 0);
		VpuWriteReg(BIT_PARA_BUF_ADDR, paraBuffer);
		VpuWriteReg(BIT_CODE_BUF_ADDR, codeBuffer);
		VpuWriteReg(BIT_TEMP_BUF_ADDR, tempBuffer);

		if (cpu_is_mx27())
			VpuWriteReg(BIT_RESET_CTRL, 0);

		VpuWriteReg(BIT_BIT_STREAM_PARAM, 0);

		if (!cpu_is_mx27()) {
			if (VpuReadReg(BIT_CUR_PC) != 0) {
				/* IRQ is disabled during shutdown */
				VpuWriteReg(BIT_INT_ENABLE, 1 << INT_BIT_PIC_RUN);
				IOClkGateSet(false);
				free(bit_code);
				UnlockVpu(vpu_semap);
				return RETCODE_SUCCESS;
			}
		}

		VpuWriteReg(BIT_CODE_RUN, 0);

		/* Download BIT Microcode to Program Memory */
		if (cpu_is_mx6x()) {
			for (i = 0; i < 2048; i += 4) {
				data = bit_code[i+3];
				VpuWriteReg(BIT_CODE_DOWN, (i << 16) | data);
				data = bit_code[i+2];
				VpuWriteReg(BIT_CODE_DOWN, ((i+1) << 16) | data);
				data = bit_code[i+1];
				VpuWriteReg(BIT_CODE_DOWN, ((i+2) << 16) | data);
				data = bit_code[i];
				VpuWriteReg(BIT_CODE_DOWN, ((i+3) << 16) | data);
			}
		} else {
			for (i = 0; i < 2048; ++i) {
				data = bit_code[i];
				VpuWriteReg(BIT_CODE_DOWN, (i << 16) | data);
			}
		}

		data =
		    STREAM_ENDIAN | STREAM_FULL_EMPTY_CHECK_DISABLE <<
		    BIT_BUF_CHECK_DIS;
		data |=
		    BUF_PIC_FLUSH << BIT_BUF_PIC_FLUSH | BUF_PIC_RESET <<
		    BIT_BUF_PIC_RESET;
		VpuWriteReg(BIT_BIT_STREAM_CTRL, data);
		VpuWriteReg(BIT_FRAME_MEM_CTRL, IMAGE_ENDIAN);
		VpuWriteReg(BIT_INT_ENABLE, 1 << INT_BIT_PIC_RUN);
		VpuWriteReg(BIT_AXI_SRAM_USE, 0);	/* init to not use SRAM */

		if (cpu_is_mx27()) {
			ResetVpu();
		}

		VpuWriteReg(BIT_BUSY_FLAG, 1);
		dump_regs(0, 128);
		VpuWriteReg(BIT_CODE_RUN, 1);
		while (VpuReadReg(BIT_BUSY_FLAG));

		IOClkGateSet(false);

		free(bit_code);
	}

	UnlockVpu(vpu_semap);

	EXIT_FUNC();
	return RETCODE_SUCCESS;
}

void vpu_UnInit(void)
{
	EnterInit();
	IOSystemShutdown();
	LeaveInit();
}

/*
 * This function resets the VPU instance specified by handle or index that
 * exists in the current thread. If handle is not NULL, the index will be
 * ignored and the instance of handle will be reset; otherwise, vpu will only
 * clean the instance record per index, not do real vpu reset.
 */
RetCode vpu_SWReset(DecHandle handle, int index)
{
	static unsigned int regBk[64];
	int i = 0;
	CodecInst *pCodecInst;
	RetCode ret;
	unsigned long instIndexSave;

	ENTER_FUNC();

	info_msg("vpu_SWReset\n");
	if (handle == NULL) {
		if (index < 0 || index >= MAX_NUM_INSTANCE)
			return RETCODE_FAILURE;

		/* Free instance info per index */
		pCodecInst = (CodecInst *)(&vpu_shared_mem->codecInstPool[index]);
		if (pCodecInst == NULL)
			warn_msg("The instance is freed\n");
		else {
			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;
			FreeCodecInstance(pCodecInst);
			UnlockVpu(vpu_semap);
		}
		return RETCODE_SUCCESS;
	}

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS) {
		ret = CheckEncInstanceValidity(handle);
		if (ret != RETCODE_SUCCESS)
			return ret;
	}

	pCodecInst = handle;

	if (*ppendingInst && (pCodecInst != *ppendingInst))
		return RETCODE_FAILURE;
	else if (*ppendingInst) {
		*ppendingInst = 0;
	} else {
		if (!LockVpu(vpu_semap))
			return RETCODE_FAILURE_TIMEOUT;
	}

	if (cpu_is_mx6x()) {
		vpu_mx6_hwreset();

		UnlockVpu(vpu_semap);
		return RETCODE_SUCCESS;
	}

	/* Following is for mx5x platforms */
	instIndexSave = VpuReadReg(BIT_RUN_INDEX);
	for (i = 0 ; i < 64 ; i++)
		regBk[i] = VpuReadReg(BIT_CODE_BUF_ADDR + (i * 4));
	IOSysSWReset();
	for (i = 0 ; i < 64 ; i++)
		VpuWriteReg(BIT_CODE_BUF_ADDR + (i * 4), regBk[i]);
	VpuWriteReg(BIT_CODE_RUN, 0);

	Uint32 *p = (Uint32 *)virt_codeBuf;
	Uint32 data;
	Uint16 data_hi;
	Uint16 data_lo;
	if (!cpu_is_mx27()) {
		for (i = 0; i < 2048; i += 4) {
			data = p[(i / 2) + 1];
			data_hi = (data >> 16) & 0xFFFF;
			data_lo = data & 0xFFFF;
			VpuWriteReg(BIT_CODE_DOWN, (i << 16) | data_hi);
			VpuWriteReg(BIT_CODE_DOWN, ((i + 1) << 16) | data_lo);

			data = p[i / 2];
			data_hi = (data >> 16) & 0xFFFF;
			data_lo = data & 0xFFFF;
			VpuWriteReg(BIT_CODE_DOWN, ((i + 2) << 16) | data_hi);
			VpuWriteReg(BIT_CODE_DOWN, ((i + 3) << 16) | data_lo);
		}
	} else {
		for (i = 0; i < 2048; i += 2) {
			data = p[i / 2];
			data_hi = (data >> 16) & 0xFFFF;
			data_lo = data & 0xFFFF;

			VpuWriteReg(BIT_CODE_DOWN, (i << 16) | data_hi);
			VpuWriteReg(BIT_CODE_DOWN, ((i + 1) << 16) | data_lo);
		}
	}

	VpuWriteReg(BIT_BUSY_FLAG, 1);
	VpuWriteReg(BIT_CODE_RUN, 1);
	while (vpu_IsBusy());
	VpuWriteReg(BIT_RUN_INDEX, instIndexSave);

	BitIssueCommand(NULL, VPU_WAKE);
	while (vpu_IsBusy());

	/* The handle cannot be used after restore */
	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Get VPU Firmware Version.
 */
RetCode vpu_GetVersionInfo(vpu_versioninfo * verinfo)
{
	Uint32 ver, fw_code = 0;
	Uint16 pn, version;
	RetCode ret = RETCODE_SUCCESS;
	char productstr[18] = { 0 };

	ENTER_FUNC();

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (!isVpuInitialized()) {
		UnlockVpu(vpu_semap);
		return RETCODE_NOT_INITIALIZED;
	}

	if (VpuReadReg(BIT_BUSY_FLAG))
		err_msg("fatal: VPU is busy in %s\n", __func__);

	VpuWriteReg(RET_VER_NUM, 0);

	BitIssueCommand(NULL, FIRMWARE_GET);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	ver = VpuReadReg(RET_VER_NUM);
	if (cpu_is_mx6x())
		fw_code = VpuReadReg(RET_FW_CODE_REV);
	UnlockVpu(vpu_semap);

	if (ver == 0)
		return RETCODE_FAILURE;

	pn = (Uint16) (ver >> 16);
	version = (Uint16) ver;

	switch (pn) {
	case PRJ_TRISTAN:
	case PRJ_TRISTAN_REV:
		strcpy(productstr, "i.MX27");
		break;
	case PRJ_CODAHX_14:
		strcpy(productstr, "i.MX51");
		break;
	case PRJ_CODA7541:
		strcpy(productstr, "i.MX53");
		break;
	case PRJ_CODA_960:
		strcpy(productstr, "i.MX6Q/D/S");
		break;
	default:
		err_msg("Unknown VPU\n");
		ret = RETCODE_FAILURE;
		break;
	}

	if (verinfo != NULL) {
		verinfo->fw_major = (version >> 12) & 0x0f;
		verinfo->fw_minor = (version >> 8) & 0x0f;
		verinfo->fw_release = version & 0xff;
		verinfo->fw_code = fw_code;
		verinfo->lib_major = (VPU_LIB_VERSION_CODE >> (12)) & 0x0f;
		verinfo->lib_minor = (VPU_LIB_VERSION_CODE >> (8)) & 0x0f;
		verinfo->lib_release = (VPU_LIB_VERSION_CODE) & 0xff;
		info_msg("Product Info: %s\n", productstr);
	}

	return ret;
}

/*!
 * @brief VPU encoder initialization
 *
 * @param pHandle [Output] Pointer to EncHandle type
    where a handle will be written by which you can refer
    to an encoder instance. If no instance is available,
    null handle is returned via pHandle.
 *
 * @param pop  [Input] Pointer to EncOpenParam type
 * which describes parameters necessary for encoding.
 *
 * @return
 * @li RETCODE_SUCCESS: Success in acquisition of an encoder instance.
 * @li RETCODE_FAILURE: Failed in acquisition of an encoder instance.
 * @li RETCODE_INVALID_PARAM: pop is a null pointer, or some parameter
 * passed does not satisfy conditions described in the paragraph for
 * EncOpenParam type.
 */
RetCode vpu_EncOpen(EncHandle * pHandle, EncOpenParam * pop)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	int instIdx, i;
	RetCode ret;
	Uint32 val;

	ENTER_FUNC();

	ret = CheckEncOpenParam(pop);
	if (ret != RETCODE_SUCCESS) {
		return ret;
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (!(cpu_is_mx6x() && pop->bitstreamFormat == STD_MJPG) && !isVpuInitialized()) {
		UnlockVpu(vpu_semap);
		return RETCODE_NOT_INITIALIZED;
	}

	ret = GetCodecInstance(&pCodecInst);
	if (ret == RETCODE_FAILURE) {
		*pHandle = 0;
		UnlockVpu(vpu_semap);
		return RETCODE_FAILURE;
	}
	UnlockVpu(vpu_semap);

	*pHandle = pCodecInst;
	instIdx = pCodecInst->instIndex;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	pCodecInst->contextBufMem.size = SIZE_CONTEXT_BUF;
	if (cpu_is_mx6x() && pop->bitstreamFormat == STD_AVC)
		pCodecInst->contextBufMem.size += PS_SAVE_SIZE;
	ret = IOGetPhyMem(&pCodecInst->contextBufMem);
	if (ret) {
		err_msg("Unable to obtain physical mem\n");
		return RETCODE_FAILURE;
	}
	pEncInfo->openParam = *pop;

	pCodecInst->codecModeAux = 0;
	if ((pop->bitstreamFormat == STD_MPEG4) ||
	    (pop->bitstreamFormat == STD_H263))
		pCodecInst->codecMode = MP4_ENC;
	else if (pop->bitstreamFormat == STD_AVC) {
		pCodecInst->codecMode = AVC_ENC;
		if (cpu_is_mx6x())
			pCodecInst->codecModeAux = pop->EncStdParam.avcParam.mvc_extension;
	} else if (pop->bitstreamFormat == STD_MJPG)
		pCodecInst->codecMode = MJPG_ENC;

	pEncInfo->streamRdPtr = pop->bitstreamBuffer;
	pEncInfo->streamBufStartAddr = pop->bitstreamBuffer;
	pEncInfo->streamBufSize = pop->bitstreamBufferSize;
	pEncInfo->streamBufEndAddr =
	    pop->bitstreamBuffer + pop->bitstreamBufferSize;
	pEncInfo->frameBufPool = 0;

	pEncInfo->rotationEnable = 0;
	pEncInfo->mirrorEnable = 0;
	pEncInfo->mirrorDirection = MIRDIR_NONE;
	pEncInfo->rotationAngle = 0;

	pEncInfo->initialInfoObtained = 0;
	pEncInfo->dynamicAllocEnable = pop->dynamicAllocEnable;
	pEncInfo->ringBufferEnable = pop->ringBufferEnable;
	pEncInfo->cacheConfig.Bypass = 1;		    /* By default, turn off MC cache */
	pEncInfo->subFrameSyncConfig.subFrameSyncOn = 0;    /* By default, turn off SubFrameSync */
	pEncInfo->linear2TiledEnable = pop->linear2TiledEnable;
	pEncInfo->mapType = pop->mapType;

	/* MB Aligned source resolution */
	pEncInfo->srcFrameWidth = (pop->picWidth + 15) & ~15;
	pEncInfo->srcFrameHeight = (pop->picHeight + 15) & ~15;

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = pEncInfo->streamRdPtr;
	pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = pEncInfo->streamBufStartAddr;

	if (!is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		if (instIdx == (int)VpuReadReg(BIT_RUN_INDEX)) {
			VpuWriteReg(BIT_RD_PTR, pEncInfo->streamRdPtr);
			VpuWriteReg(BIT_WR_PTR, pEncInfo->streamBufStartAddr);
		}
	}

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {

		UnlockVpu(vpu_semap);

		pEncInfo->jpgInfo.frameIdx = 0;
		pEncInfo->jpgInfo.seqInited = 0;
		pEncInfo->jpgInfo.enableSofStuffing = 1;
		pEncInfo->jpgInfo.format = pEncInfo->openParam.EncStdParam.mjpgParam.mjpg_sourceFormat;
		pEncInfo->jpgInfo.picWidth= pEncInfo->openParam.picWidth;
		pEncInfo->jpgInfo.picHeight = pEncInfo->openParam.picHeight;
		if (pEncInfo->jpgInfo.format == FORMAT_420 ||
		    pEncInfo->jpgInfo.format == FORMAT_422)
			pEncInfo->jpgInfo.alignedWidth = ((pEncInfo->jpgInfo.picWidth + 15) / 16) * 16;
		else
			pEncInfo->jpgInfo.alignedWidth = ((pEncInfo->jpgInfo.picWidth + 7) / 8) * 8;

		if (pEncInfo->jpgInfo.format == FORMAT_420 ||
		    pEncInfo->jpgInfo.format == FORMAT_224)
			pEncInfo->jpgInfo.alignedHeight = ((pEncInfo->jpgInfo.picHeight + 15) / 16) * 16;
		else
			pEncInfo->jpgInfo.alignedHeight = ((pEncInfo->jpgInfo.picHeight + 7) / 8) * 8;
		pEncInfo->jpgInfo.rstIntval = pEncInfo->openParam.EncStdParam.mjpgParam.mjpg_restartInterval;

		for (i = 0; i < 4; i++) {
			pEncInfo->jpgInfo.pHuffVal[i] = pEncInfo->openParam.EncStdParam.mjpgParam.huffVal[i];
			pEncInfo->jpgInfo.pHuffBits[i] = pEncInfo->openParam.EncStdParam.mjpgParam.huffBits[i];
			pEncInfo->jpgInfo.pQMatTab[i] = pEncInfo->openParam.EncStdParam.mjpgParam.qMatTab[i];
			pEncInfo->jpgInfo.pCInfoTab[i] = pEncInfo->openParam.EncStdParam.mjpgParam.cInfoTab[i];
		}

		return RETCODE_SUCCESS;
	}

	val = VpuReadReg(BIT_BIT_STREAM_CTRL);
	val &= ~BITS_STREAMCTRL_MASK;
	val |=
	    (STREAM_ENDIAN | STREAM_FULL_EMPTY_CHECK_DISABLE <<
	     BIT_BUF_CHECK_DIS);
	if (pEncInfo->ringBufferEnable == 0) {
		if (!cpu_is_mx6x())
			val |=
			    (pEncInfo->dynamicAllocEnable << BIT_ENC_DYN_BUFALLOC_EN);
		val |= 1 << BIT_BUF_PIC_RESET;
	} else
		val |= 1 << BIT_BUF_PIC_FLUSH;

	VpuWriteReg(BIT_BIT_STREAM_CTRL, val);

	val = VpuReadReg(BIT_FRAME_MEM_CTRL);
	val &= ~(1 << 2 | 0x7 << 9);  /* clear the bit firstly */
	if (pEncInfo->mapType)
		val |= pEncInfo->linear2TiledEnable << 11 | 0x03 << 9;

	pCodecInst->ctxRegs[CTX_BIT_FRAME_MEM_CTRL] =
	    val | (pEncInfo->openParam.chromaInterleave << 2);

	if (cpu_is_mx6x())
		VpuWriteReg(GDI_WPROT_RGN_EN, 0);

	info_msg("ringBufferEnable %d, chromaInterleave %d, mapType %d, linear2TiledEnable %d\n",
			pop->ringBufferEnable, pop->chromaInterleave,
			pop->mapType, pop->linear2TiledEnable);

	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Encoder system close.
 *
 * @param encHandle [Input] The handle obtained from vpu_EncOpen().
 *
 * @return
 * @li RETCODE_SUCCESS Successful closing.
 * @li RETCODE_INVALID_HANDLE encHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 */
RetCode vpu_EncClose(EncHandle handle)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	if (*ppendingInst == pCodecInst) {
		return RETCODE_FRAME_NOT_COMPLETE;
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		VpuWriteReg(MJPEG_BBC_FLUSH_CMD_REG, 0);
		goto enc_out;
	}

	if (pEncInfo->initialInfoObtained) {
		BitIssueCommand(pCodecInst, SEQ_END);
		while (VpuReadReg(BIT_BUSY_FLAG)) ;
	}

enc_out:
	/* Free memory allocated for data report functions */
	if (pEncInfo->picParaBaseMem.phy_addr) {
		IOFreeVirtMem(&pEncInfo->picParaBaseMem);
		IOFreePhyMem(&pEncInfo->picParaBaseMem);
	}

	/* Free searchRam if searchRam doesn't use IRAM */
	if ((pEncInfo->secAxiUse.useHostMeEnable == 0) &&
	    (pEncInfo->secAxiUse.searchRamAddr))
		IOFreePhyMem(&pEncInfo->searchRamMem);

	/* Free context buf Mem */
	IOFreePhyMem(&pCodecInst->contextBufMem);

	FreeCodecInstance(pCodecInst);
	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief user could allocate frame buffers
 * according to the information obtained from this function.
 * @param handle [Input] The handle obtained from vpu_EncOpen().
 * @param info [Output] The information required before starting
 * encoding will be put to the data structure pointed to by initialInfo.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_FAILURE There was an error in getting information and
 *                                    configuring the encoder.
 * @li RETCODE_INVALID_HANDLE encHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished
 * @li RETCODE_INVALID_PARAM initialInfo is a null pointer.
 */
RetCode vpu_EncGetInitialInfo(EncHandle handle, EncInitialInfo * info)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	EncOpenParam *pEncOP;
	int picWidth;
	int picHeight;
	Uint32 data, *tableBuf;
	int i;
	SetIramParam iramParam;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	if (info == 0) {
		return RETCODE_INVALID_PARAM;
	}

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;
	pEncOP = &pEncInfo->openParam;

	if (pEncInfo->initialInfoObtained) {
		return RETCODE_CALLED_BEFORE;
	}

	picWidth = pEncOP->picWidth;
	picHeight = pEncOP->picHeight;

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		if (pEncInfo->jpgInfo.format == FORMAT_400) {
			pEncInfo->jpgInfo.compInfo[1] = 0;
			pEncInfo->jpgInfo.compInfo[2] = 0;
		} else {
			pEncInfo->jpgInfo.compInfo[1] = 5;
			pEncInfo->jpgInfo.compInfo[2] = 5;
		}

		pEncInfo->jpgInfo.compNum = (pEncInfo->jpgInfo.format == FORMAT_400) ? 1 : 3;

		if (pEncInfo->jpgInfo.format == FORMAT_420) {
			pEncInfo->jpgInfo.mcuBlockNum = 6;
			pEncInfo->jpgInfo.compInfo[0] = 10;
			pEncInfo->jpgInfo.busReqNum = 2;
		}  else if (pEncInfo->jpgInfo.format == FORMAT_422) {
			pEncInfo->jpgInfo.mcuBlockNum = 4;
			pEncInfo->jpgInfo.busReqNum = 3;
			pEncInfo->jpgInfo.compInfo[0] = 9;
		} else if (pEncInfo->jpgInfo.format == FORMAT_224) {
			pEncInfo->jpgInfo.mcuBlockNum = 4;
			pEncInfo->jpgInfo.busReqNum  = 3;
			pEncInfo->jpgInfo.compInfo[0] = 6;
			pEncInfo->jpgInfo.compInfo[0] = 6;
		} else if (pEncInfo->jpgInfo.format == FORMAT_444) {
			pEncInfo->jpgInfo.mcuBlockNum = 3;
			pEncInfo->jpgInfo.compInfo[0] = 5;
			pEncInfo->jpgInfo.busReqNum = 4;
		} else if (pEncInfo->jpgInfo.format == FORMAT_400) {
			pEncInfo->jpgInfo.mcuBlockNum = 1;
			pEncInfo->jpgInfo.busReqNum = 4;
			pEncInfo->jpgInfo.compInfo[0] = 5;
		}

		info->minFrameBufferCount = 0;

		pEncInfo->initialInfo = *info;
		pEncInfo->initialInfoObtained = 1;

		UnlockVpu(vpu_semap);
		return RETCODE_SUCCESS;
	}

	data = (picWidth << BIT_PIC_WIDTH_OFFSET) | picHeight;
	VpuWriteReg(CMD_ENC_SEQ_SRC_SIZE, data);
	VpuWriteReg(CMD_ENC_SEQ_SRC_F_RATE, pEncOP->frameRateInfo);

	if (pEncOP->bitstreamFormat == STD_MPEG4) {
		pEncInfo->mp4_dataPartitionEnable =
			pEncOP->EncStdParam.mp4Param.mp4_dataPartitionEnable;
		if (cpu_is_mx6x())
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 3);
		else
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 0);
		data = pEncOP->EncStdParam.mp4Param.mp4_intraDcVlcThr << 2 |
		    pEncOP->EncStdParam.mp4Param.mp4_reversibleVlcEnable << 1 |
		    pEncOP->EncStdParam.mp4Param.mp4_dataPartitionEnable;
		data |= ((pEncOP->EncStdParam.mp4Param.mp4_hecEnable > 0)
			 ? 1 : 0) << 5;
		data |= ((pEncOP->EncStdParam.mp4Param.mp4_verid == 2)
			 ? 0 : 1) << 6;
		VpuWriteReg(CMD_ENC_SEQ_MP4_PARA, data);
	} else if (pEncOP->bitstreamFormat == STD_H263) {
		if (cpu_is_mx6x())
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 11);
		else if (cpu_is_mx5x())
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 8);
		else
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 1);
		data = pEncOP->EncStdParam.h263Param.h263_annexIEnable << 3 |
		       pEncOP->EncStdParam.h263Param.h263_annexJEnable << 2 |
		       pEncOP->EncStdParam.h263Param.h263_annexKEnable << 1 |
		       pEncOP->EncStdParam.h263Param.h263_annexTEnable;
		VpuWriteReg(CMD_ENC_SEQ_263_PARA, data);
	} else if (pEncOP->bitstreamFormat == STD_AVC) {
		if (cpu_is_mx6x())
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 0);
		else
			VpuWriteReg(CMD_ENC_SEQ_COD_STD, 2);
		data = (pEncOP->EncStdParam.avcParam.avc_deblkFilterOffsetBeta &
			15) << 12 |
		    (pEncOP->EncStdParam.avcParam.avc_deblkFilterOffsetAlpha
		     & 15) << 8 |
		    pEncOP->EncStdParam.avcParam.avc_disableDeblk << 6 |
		    pEncOP->EncStdParam.avcParam.avc_constrainedIntraPredFlag
		    << 5 | (pEncOP->EncStdParam.avcParam.avc_chromaQpOffset & 31);
		VpuWriteReg(CMD_ENC_SEQ_264_PARA, data);
	} else if (!cpu_is_mx6x() && pEncOP->bitstreamFormat == STD_MJPG) {
		VpuWriteReg(CMD_ENC_SEQ_JPG_PARA,
			    pEncInfo->openParam.EncStdParam.mjpgParam.
			    mjpg_sourceFormat);
		VpuWriteReg(CMD_ENC_SEQ_JPG_RST_INTERVAL,
			    pEncInfo->openParam.EncStdParam.mjpgParam.
			    mjpg_restartInterval);
		VpuWriteReg(CMD_ENC_SEQ_JPG_THUMB_EN,
			    pEncInfo->openParam.EncStdParam.mjpgParam.
			    mjpg_thumbNailEnable);
		data =
		    (pEncInfo->openParam.EncStdParam.mjpgParam.
		     mjpg_thumbNailWidth) << 16 | (pEncInfo->openParam.
						   EncStdParam.mjpgParam.
						   mjpg_thumbNailHeight);
		VpuWriteReg(CMD_ENC_SEQ_JPG_THUMB_SIZE, data);
		VpuWriteReg(CMD_ENC_SEQ_JPG_THUMB_OFFSET, 0);

		tableBuf =
		    (Uint32 *) pEncInfo->openParam.EncStdParam.mjpgParam.
		    mjpg_hufTable;
		for (i = 0; i < 108; i += 2) {
			virt_paraBuf[i + 1] = *tableBuf;
			virt_paraBuf[i] = *(tableBuf + 1);
			tableBuf += 2;
		}
		tableBuf =
		    (Uint32 *) pEncInfo->openParam.EncStdParam.mjpgParam.
		    mjpg_qMatTable;
		for (i = 0; i < 48; i += 2) {
			virt_paraBuf[i + 129] = *tableBuf;
			virt_paraBuf[i + 128] = *(tableBuf + 1);
			tableBuf += 2;
		}
	}

	if (pEncOP->bitstreamFormat != STD_MJPG) {
		data = pEncOP->slicemode.sliceSize << 2 |
		    pEncOP->slicemode.sliceSizeMode << 1 | pEncOP->slicemode.
		    sliceMode;

		VpuWriteReg(CMD_ENC_SEQ_SLICE_MODE, data);
		VpuWriteReg(CMD_ENC_SEQ_GOP_NUM, pEncOP->gopSize);
	}

	if (pEncOP->bitRate) {	/* rate control enabled */
		data = pEncOP->initialDelay << 16 | pEncOP->bitRate << 1 | 1;
		if (cpu_is_mx6x())
			data |= (!pEncInfo->openParam.enableAutoSkip) << 31;
		VpuWriteReg(CMD_ENC_SEQ_RC_PARA, data);
	} else {
		VpuWriteReg(CMD_ENC_SEQ_RC_PARA, 0);
	}

	VpuWriteReg(CMD_ENC_SEQ_RC_BUF_SIZE, pEncOP->vbvBufferSize);
	data = pEncOP->intraRefresh;
	if (pEncOP->intraRefresh > 0)
		data |= pEncInfo->intraRefreshMode << 16;
	VpuWriteReg(CMD_ENC_SEQ_INTRA_REFRESH, data);

	VpuWriteReg(CMD_ENC_SEQ_BB_START, pEncInfo->streamBufStartAddr);
	VpuWriteReg(CMD_ENC_SEQ_BB_SIZE, pEncInfo->streamBufSize / 1024);

	data = 0;
	if (cpu_is_mx27()) {
		data |= (pEncOP->sliceReport << 1) | pEncOP->mbReport;
		data |= (pEncOP->mbQpReport << 3);
	}
	if (pEncOP->rcIntraQp >= 0)
		data |= (1 << 5);
	VpuWriteReg(CMD_ENC_SEQ_INTRA_QP, pEncOP->rcIntraQp);

	if (pCodecInst->codecMode == AVC_ENC) {
		data |= (pEncOP->EncStdParam.avcParam.avc_audEnable << 2);
		if (!cpu_is_mx6x())
			data |= (pEncOP->EncStdParam.avcParam.avc_fmoEnable << 4);
		else if (pCodecInst->codecModeAux == AVC_AUX_MVC) {
			data |= (pEncInfo->openParam.EncStdParam.avcParam.interview_en << 4);
			data |= (pEncInfo->openParam.EncStdParam.avcParam.paraset_refresh_en << 8);
			data |= (pEncInfo->openParam.EncStdParam.avcParam.prefix_nal_en << 9);
		}
	}

	if (cpu_is_mx6x()) {
		if (pEncOP->userQpMaxEnable) {
			data |= (1 << 6);
			VpuWriteReg(CMD_ENC_SEQ_RC_QP_MIN_MAX, pEncInfo->openParam.userQpMax);
		}
		if (pEncOP->userGamma) {
			data |= (1 << 7);
			VpuWriteReg(CMD_ENC_SEQ_RC_GAMMA, pEncOP->userGamma);
		}
	} else {
		if (pEncOP->userQpMinEnable) {
			data |= (1 << 6);
			VpuWriteReg(CMD_ENC_SEQ_RC_QP_MIN_MAX,
			    (pEncOP->userQpMin << 8) | (pEncOP->userQpMax & 0xFF));
		}
		if (pEncOP->userQpMaxEnable) {
			data |= (1 << 7);
			VpuWriteReg(CMD_ENC_SEQ_RC_QP_MIN_MAX,
				    (pEncOP->userQpMin << 8) | (pEncOP->userQpMax & 0xFF));
		}

		if (pEncOP->userGamma) {
			data |= (1 << 8);
			VpuWriteReg(CMD_ENC_SEQ_RC_GAMMA, pEncOP->userGamma);
		}
	}

	if (!cpu_is_mx6x() && pCodecInst->codecMode == AVC_ENC) {
		if (pEncOP->avcIntra16x16OnlyModeEnable)
			data |= (1 << 9);
	}

	VpuWriteReg(CMD_ENC_SEQ_OPTION, data);

	VpuWriteReg(CMD_ENC_SEQ_RC_INTERVAL_MODE,
			(pEncInfo->openParam.MbInterval << 2) |
			pEncInfo->openParam.RcIntervalMode);

	if (cpu_is_mx27() && (pCodecInst->codecMode == AVC_ENC)) {
		data = (pEncOP->EncStdParam.avcParam.avc_fmoType << 4) |
		    (pEncOP->EncStdParam.avcParam.avc_fmoSliceNum & 0x0f);
		data |= (FMO_SLICE_SAVE_BUF_SIZE << 7);
		VpuWriteReg(CMD_ENC_SEQ_FMO, data);
	}

	/* Set secondAXI IRAM */
	iramParam.width = pEncOP->picWidth;
	SetEncSecondAXIIRAM(&pEncInfo->secAxiUse, &iramParam);

	if (!cpu_is_mx6x()) {
		/* Use external memory if IRAM is disabled for searchMe*/
		if (pEncInfo->secAxiUse.useHostMeEnable == 0) {
			pEncInfo->searchRamMem.size = pEncInfo->secAxiUse.searchRamSize;
			IOGetPhyMem(&pEncInfo->searchRamMem);
			pEncInfo->secAxiUse.searchRamAddr = pEncInfo->searchRamMem.phy_addr;
		}

		VpuWriteReg(CMD_ENC_SEARCH_BASE, pEncInfo->secAxiUse.searchRamAddr);
		VpuWriteReg(CMD_ENC_SEARCH_SIZE, pEncInfo->secAxiUse.searchRamSize);
	} else {
		VpuWriteReg(CMD_ENC_SEQ_ME_OPTION, pEncInfo->openParam.MEUseZeroPmv << 2 |
				pEncInfo->openParam.MESearchRange);
		VpuWriteReg(CMD_ENC_SEQ_INTRA_WEIGHT, pEncInfo->openParam.IntraCostWeight);
	}

	BitIssueCommand(pCodecInst, SEQ_INIT);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	if (cpu_is_mx6x() && VpuReadReg(RET_ENC_SEQ_ENC_SUCCESS) & (1 << 31)) {
		UnlockVpu(vpu_semap);
		return RETCODE_MEMORY_ACCESS_VIOLATION;
	}

	if (VpuReadReg(RET_ENC_SEQ_ENC_SUCCESS) == 0) {
		UnlockVpu(vpu_semap);
		return RETCODE_FAILURE;
	}

	/* Backup wr pointer to ctx */
	pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = VpuReadReg(BIT_WR_PTR);

	UnlockVpu(vpu_semap);

	if (pCodecInst->codecMode == MJPG_ENC)
		info->minFrameBufferCount = 0;
	else {
		if (pCodecInst->codecMode == AVC_ENC &&
		    pCodecInst->codecModeAux == AVC_AUX_MVC)
			info->minFrameBufferCount = 3; /* reconstructed frame + 2 reference frame */
		else
			info->minFrameBufferCount = 2;	/* reconstructed frame + reference frame */
	}

	info->reportBufSize.sliceInfoBufSize = SIZE_SLICE_INFO;
	info->reportBufSize.mbInfoBufSize = SIZE_MB_DATA;
	info->reportBufSize.mvInfoBufSize = SIZE_MV_DATA;

	pEncInfo->initialInfo = *info;
	pEncInfo->initialInfoObtained = 1;

	if (cpu_is_mx6x()) {
		SetTiledMapTypeInfo(pEncInfo->mapType, &pEncInfo->sTiledInfo);
		/* Enable 2-D cache */
		SetMaverickCache(&pEncInfo->cacheConfig, 0,
				 pEncInfo->openParam.chromaInterleave);
	}

	return RETCODE_SUCCESS;
}

/*!
 * @brief Registers frame buffers
 * @param handle [Input] The handle obtained from vpu_EncOpen().
 * @param bufArray [Input] Pointer to the first element of an array
 *			of FrameBuffer data structures.
 * @param num [Input] Number of elements of the array.
 * @param stride [Input] Stride value of frame buffers being registered.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE encHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished
 * @li RETCODE_WRONG_CALL_SEQUENCE Function call in wrong sequence.
 * @li RETCODE_INVALID_FRAME_BUFFER pBuffer is a null pointer.
 * @li RETCODE_INSUFFICIENT_FRAME_BUFFERS num is smaller than requested.
 * @li RETCODE_INVALID_STRIDE stride is smaller than the picture width.
 */
RetCode vpu_EncRegisterFrameBuffer(EncHandle handle, FrameBuffer * bufArray,
				   int num, int frameBufStride, int sourceBufStride,
				   PhysicalAddress subSampBaseA, PhysicalAddress subSampBaseB,
				   EncExtBufInfo *pBufInfo)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	int i;
	Uint32 val;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	if (pEncInfo->frameBufPool) {
		return RETCODE_CALLED_BEFORE;
	}

	if (!pEncInfo->initialInfoObtained) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	if (bufArray == 0) {
		return RETCODE_INVALID_FRAME_BUFFER;
	}

	if (num < pEncInfo->initialInfo.minFrameBufferCount) {
		return RETCODE_INSUFFICIENT_FRAME_BUFFERS;
	}

	if (frameBufStride % 8 != 0 || frameBufStride == 0) {
		return RETCODE_INVALID_STRIDE;
	}

	pEncInfo->frameBufPool = bufArray;
	pEncInfo->numFrameBuffers = num;
	pEncInfo->stride = frameBufStride;

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode))
		return RETCODE_SUCCESS;

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (!cpu_is_mx27()) {
		if (pCodecInst->codecMode != MJPG_ENC) {
			/* Need to swap word between Dword(64bit) */
			for (i = 0; i < num; i += 2) {
				virt_paraBuf[i * 3] = bufArray[i].bufCb;
				virt_paraBuf[i * 3 + 1] = bufArray[i].bufY;
				virt_paraBuf[i * 3 + 3] = bufArray[i].bufCr;
				if (i + 1 < num) {
					virt_paraBuf[i * 3 + 2] =
					    bufArray[i + 1].bufY;
					virt_paraBuf[i * 3 + 4] =
					    bufArray[i + 1].bufCr;
					virt_paraBuf[i * 3 + 5] =
					    bufArray[i + 1].bufCb;
				}
			}
		}
	} else {
		/* Let the codec know the addresses of the frame buffers. */
		for (i = 0; i < num; ++i) {
			virt_paraBuf[i * 3] = bufArray[i].bufY;
			virt_paraBuf[i * 3 + 1] = bufArray[i].bufCb;
			virt_paraBuf[i * 3 + 2] = bufArray[i].bufCr;
		}
	}

	/* Tell the codec how much frame buffers were allocated. */
	VpuWriteReg(CMD_SET_FRAME_BUF_NUM, num);
	VpuWriteReg(CMD_SET_FRAME_BUF_STRIDE, frameBufStride);

	if (!cpu_is_mx6x())
		VpuWriteReg(CMD_SET_FRAME_SOURCE_BUF_STRIDE, sourceBufStride);

	if (cpu_is_mx6x()) {
		/* Maverick Cache Configuration */
		val = (pEncInfo->cacheConfig.luma.cfg.PageSizeX << 28) |
		      (pEncInfo->cacheConfig.luma.cfg.PageSizeY << 24) |
		      (pEncInfo->cacheConfig.luma.cfg.CacheSizeX << 20) |
		      (pEncInfo->cacheConfig.luma.cfg.CacheSizeY << 16) |
		      (pEncInfo->cacheConfig.chroma.cfg.PageSizeX << 12) |
		      (pEncInfo->cacheConfig.chroma.cfg.PageSizeY << 8) |
		      (pEncInfo->cacheConfig.chroma.cfg.CacheSizeX << 4) |
		      (pEncInfo->cacheConfig.chroma.cfg.CacheSizeY << 0);
		VpuWriteReg(CMD_SET_FRAME_CACHE_SIZE, val);

		val = (pEncInfo->cacheConfig.Bypass << 4) |
		      (pEncInfo->cacheConfig.DualConf << 2) |
		      (pEncInfo->cacheConfig.PageMerge << 0);
		val = val << 24;
		val |= (pEncInfo->cacheConfig.LumaBufferSize << 16) |
		       (pEncInfo->cacheConfig.CbBufferSize << 8) |
		       (pEncInfo->cacheConfig.CrBufferSize);
		VpuWriteReg(CMD_SET_FRAME_CACHE_CONFIG, val);
	}

	if (!cpu_is_mx27()) {
		VpuWriteReg(CMD_SET_FRAME_AXI_BIT_ADDR, pEncInfo->secAxiUse.bufBitUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_IPACDC_ADDR, pEncInfo->secAxiUse.bufIpAcDcUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_DBKY_ADDR, pEncInfo->secAxiUse.bufDbkYUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_DBKC_ADDR, pEncInfo->secAxiUse.bufDbkCUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_OVL_ADDR, pEncInfo->secAxiUse.bufOvlUse);
	}

	if (cpu_is_mx6x()) {
		VpuWriteReg(CMD_SET_FRAME_AXI_BTP_ADDR, pEncInfo->secAxiUse.bufBtpUse);

		/*
		 * Magellan Encoder specific : Subsampling ping-pong Buffer
		 * Set Sub-Sampling buffer for ME-Reference and DBK-Reconstruction
		 * BPU will swap below two buffer internally every pic by pic
		 */
		VpuWriteReg(CMD_SET_FRAME_SUBSAMP_A, subSampBaseA);
		VpuWriteReg(CMD_SET_FRAME_SUBSAMP_B, subSampBaseB);

		if (pCodecInst->codecMode == AVC_ENC &&
		    pCodecInst->codecModeAux == AVC_AUX_MVC) {
			if (pBufInfo == NULL ||
			    !pBufInfo->subSampBaseAMvc ||
			    !pBufInfo->subSampBaseBMvc) {
				UnlockVpu(vpu_semap);
				return RETCODE_INVALID_PARAM;
			}
			VpuWriteReg(CMD_SET_FRAME_SUBSAMP_A_MVC, pBufInfo->subSampBaseAMvc);
			VpuWriteReg(CMD_SET_FRAME_SUBSAMP_B_MVC, pBufInfo->subSampBaseBMvc);
		}

		if (pCodecInst->codecMode == MP4_ENC) {
			if (pEncInfo->mp4_dataPartitionEnable) {
				if (pBufInfo == NULL) {
					UnlockVpu(vpu_semap);
					return RETCODE_INVALID_PARAM;
				}
				/* MPEG4 Encoder Data-Partitioned bitstream temporal buffer */
				VpuWriteReg(CMD_SET_FRAME_DP_BUF_BASE, pBufInfo->scratchBuf.bufferBase);
				VpuWriteReg(CMD_SET_FRAME_DP_BUF_SIZE, pBufInfo->scratchBuf.bufferSize);
			} else {
				VpuWriteReg(CMD_SET_FRAME_DP_BUF_BASE, 0);
				VpuWriteReg(CMD_SET_FRAME_DP_BUF_SIZE, 0);
			}
		}
	}

	BitIssueCommand(pCodecInst, SET_FRAME_BUF);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	if (cpu_is_mx6x() && VpuReadReg(RET_SET_FRAME_SUCCESS) & (1 << 31)) {
		UnlockVpu(vpu_semap);
		return RETCODE_MEMORY_ACCESS_VIOLATION;
	}

	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

RetCode vpu_EncGetBitstreamBuffer(EncHandle handle,
				  PhysicalAddress * prdPtr,
				  PhysicalAddress * pwrPtr, Uint32 * size)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	PhysicalAddress rdPtr;
	PhysicalAddress wrPtr;
	int instIndex;
	Uint32 room;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	if (prdPtr == 0 || pwrPtr == 0 || size == 0) {
		return RETCODE_INVALID_PARAM;
	}

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	LockVpuReg(vpu_semap);

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		if (!pEncInfo->ringBufferEnable) {
			err_msg("Don't call %s in line buffer mode!\n", __func__);
			UnlockVpuReg(vpu_semap);
			return RETCODE_WRONG_CALL_SEQUENCE;
		}

		if (((VpuReadReg(MJPEG_PIC_STATUS_REG) & (1 << INT_JPU_BIT_BUF_FULL)) == 0)
				&& pEncInfo->jpgInfo.inProcess) {
			*prdPtr = *pwrPtr = pEncInfo->streamRdPtr;
			*size = *pwrPtr - *prdPtr;
		} else {
			*prdPtr = pEncInfo->streamRdPtr;
			*pwrPtr = (pEncInfo->jpgInfo.inProcess) ?
				VpuReadReg(MJPEG_BBC_WR_PTR_REG) :
				pCodecInst->ctxRegs[CTX_BIT_WR_PTR];
			*size = *pwrPtr - *prdPtr;
		}
		UnlockVpuReg(vpu_semap);
		return RETCODE_SUCCESS;
	}

	rdPtr = pEncInfo->streamRdPtr;

	/* Check current instance is in running or not, if not
	   Get the pointer from back context regs */
	instIndex = (int)VpuReadReg(BIT_RUN_INDEX);
	wrPtr = (pCodecInst->instIndex == instIndex) ?
		    VpuReadReg(BIT_WR_PTR) :
		    pCodecInst->ctxRegs[CTX_BIT_WR_PTR];
	UnlockVpuReg(vpu_semap);

	if (pEncInfo->ringBufferEnable == 1) {
		if (wrPtr >= rdPtr) {
			room = wrPtr - rdPtr;
		} else {
			room = (pEncInfo->streamBufEndAddr - rdPtr) +
			    (wrPtr - pEncInfo->streamBufStartAddr);
		}
	} else {
		if (rdPtr == pEncInfo->streamBufStartAddr && wrPtr >= rdPtr)
			room = wrPtr - rdPtr;
		else
			return RETCODE_INVALID_PARAM;
	}

	*prdPtr = rdPtr;
	*pwrPtr = wrPtr;
	*size = room;

	return RETCODE_SUCCESS;
}

RetCode vpu_EncUpdateBitstreamBuffer(EncHandle handle, Uint32 size)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	PhysicalAddress wrPtr;
	PhysicalAddress rdPtr;
	RetCode ret;
	int room = 0, instIndex;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	LockVpuReg(vpu_semap);
	rdPtr = pEncInfo->streamRdPtr;
	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		if (!pEncInfo->ringBufferEnable) {
			err_msg("Don't call %s in line buffer mode!\n", __func__);
			UnlockVpuReg(vpu_semap);
			return RETCODE_WRONG_CALL_SEQUENCE;
		}

		rdPtr = pEncInfo->streamRdPtr;
		rdPtr += size;
		wrPtr = pEncInfo->jpgInfo.inProcess ?
			VpuReadReg(MJPEG_BBC_WR_PTR_REG) :
			pCodecInst->ctxRegs[CTX_BIT_WR_PTR];

		if (rdPtr < wrPtr) {
			pEncInfo->streamRdPtr = rdPtr;
			pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = rdPtr;
			if (pEncInfo->jpgInfo.inProcess)
				VpuWriteReg(MJPEG_BBC_RD_PTR_REG, rdPtr);
		}
		else if (rdPtr == wrPtr) {
			if ((VpuReadReg(MJPEG_PIC_STATUS_REG) & (1 << INT_JPU_BIT_BUF_FULL))
					|| !pEncInfo->jpgInfo.inProcess)
			{
				pEncInfo->streamRdPtr = pEncInfo->streamBufStartAddr;
				pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = pEncInfo->streamBufStartAddr;
				pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = pEncInfo->streamBufStartAddr;
				if (pEncInfo->jpgInfo.inProcess) {
					VpuWriteReg(MJPEG_BBC_CUR_POS_REG, 0);
					VpuWriteReg(MJPEG_BBC_EXT_ADDR_REG, pEncInfo->streamBufStartAddr);
					VpuWriteReg(MJPEG_BBC_RD_PTR_REG, pEncInfo->streamBufStartAddr);
					VpuWriteReg(MJPEG_BBC_WR_PTR_REG, pEncInfo->streamBufStartAddr);
					VpuWriteReg(MJPEG_PIC_STATUS_REG, 1 << INT_JPU_BIT_BUF_FULL);
				}
			}
		}

		UnlockVpuReg(vpu_semap);
		return RETCODE_SUCCESS;
	}

	instIndex = (int)VpuReadReg(BIT_RUN_INDEX);
	wrPtr = (pCodecInst->instIndex == instIndex) ?
		    VpuReadReg(BIT_WR_PTR) :
		    pCodecInst->ctxRegs[CTX_BIT_WR_PTR];
	UnlockVpuReg(vpu_semap);

	if (rdPtr < wrPtr) {
		if (rdPtr + size > wrPtr)
			return RETCODE_INVALID_PARAM;
	}

	if (pEncInfo->ringBufferEnable == 1) {
		rdPtr += size;
		if (rdPtr > pEncInfo->streamBufEndAddr) {
			room = rdPtr - pEncInfo->streamBufEndAddr;
			rdPtr = pEncInfo->streamBufStartAddr;
			rdPtr += room;
		}
		if (rdPtr == pEncInfo->streamBufEndAddr) {
			rdPtr = pEncInfo->streamBufStartAddr;
		}
	} else {
		rdPtr = pEncInfo->streamBufStartAddr;
	}

	pEncInfo->streamRdPtr = rdPtr;

	LockVpuReg(vpu_semap);
	instIndex = (int)VpuReadReg(BIT_RUN_INDEX);
	if (pCodecInst->instIndex == instIndex)
		VpuWriteReg(BIT_RD_PTR, rdPtr);
	pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = rdPtr;
	UnlockVpuReg(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Starts encoding one frame.
 *
 * @param handle [Input] The handle obtained from vpu_EncOpen().
 * @param pParam [Input] Pointer to EncParam data structure.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE encHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 * @li RETCODE_WRONG_CALL_SEQUENCE Wrong calling sequence.
 * @li RETCODE_INVALID_PARAM pParam is invalid.
 * @li RETCODE_INVALID_FRAME_BUFFER skipPicture in EncParam is 0
 * and sourceFrame in EncParam is a null pointer.
 */
RetCode vpu_EncStartOneFrame(EncHandle handle, EncParam * param)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	FrameBuffer *pSrcFrame;
	Uint32 rotMirEnable = 0;
	Uint32 rotMirMode = 0;
	Uint32 val;
	RetCode ret;

	ENTER_FUNC();

	/* When doing pre-rotation, mirroring is applied first and rotation
	 * later, vice versa when doing post-rotation.
	 * For consistency, pre-rotation is converted to post-rotation
	 * orientation.
	 */
	static Uint32 rotatorModeConversion[] = {
		0, 1, 2, 3, 4, 7, 6, 5,
		6, 5, 4, 7, 2, 3, 0, 1
	};

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	/* This means frame buffers have not been registered. */
	if (!is_mx6x_mjpg_codec(pCodecInst->codecMode) && pEncInfo->frameBufPool == 0) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	ret = CheckEncParam(pCodecInst, param);
	if (ret != RETCODE_SUCCESS) {
		return ret;
	}

	pSrcFrame = param->sourceFrame;

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	/* Workaround for RTL bug of H264 encoder on mx6q */
	if (cpu_is_mx6q() && (pCodecInst->codecMode == AVC_ENC))
		vpu_mx6_swreset(0);

	if (pEncInfo->rotationEnable) {
		if (pCodecInst->codecMode == MJPG_ENC)
			rotMirEnable = 0x10;    /* Enable rotator */
		switch (pEncInfo->rotationAngle) {
		case 0:
			rotMirMode |= 0x0;
			break;

		case 90:
			rotMirMode |= 0x1;
			break;

		case 180:
			rotMirMode |= 0x2;
			break;

		case 270:
			rotMirMode |= 0x3;
			break;
		}
	}
	if (pEncInfo->mirrorEnable) {
		if (pCodecInst->codecMode == MJPG_ENC)
			rotMirEnable = 0x10;    /* Enable mirror */
		switch (pEncInfo->mirrorDirection) {
		case MIRDIR_NONE:
			rotMirMode |= 0x0;
			break;

		case MIRDIR_VER:
			rotMirMode |= 0x4;
			break;

		case MIRDIR_HOR:
			rotMirMode |= 0x8;
			break;

		case MIRDIR_HOR_VER:
			rotMirMode |= 0xc;
			break;

		}
	}

	/* Set GDI related registers per tiled map info for mx6 */
	if (cpu_is_mx6x())
		SetGDIRegs(&pEncInfo->sTiledInfo);

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		VpuWriteReg(GDI_WPROT_ERR_CLR, 1);
		VpuWriteReg(GDI_WPROT_RGN_EN, 0);
#ifdef MEM_PROTECT
		VpuWriteReg(GDI_WPROT_ERR_RSN, 0);
		VpuWriteReg(GDI_WPROT_RGN0_STA, pEncInfo->streamBufStartAddr >> 12);	/* round down */
		VpuWriteReg(GDI_WPROT_RGN0_END, (pEncInfo->streamBufEndAddr + 0xFFF) >> 12);	/* round up */
		VpuWriteReg(GDI_WPROT_RGN_EN, 1);
#endif

		VpuWriteReg(MJPEG_BBC_BAS_ADDR_REG, pEncInfo->streamBufStartAddr);
		VpuWriteReg(MJPEG_BBC_END_ADDR_REG, pEncInfo->streamBufEndAddr);
		VpuWriteReg(MJPEG_BBC_WR_PTR_REG, pEncInfo->streamBufStartAddr);
		VpuWriteReg(MJPEG_BBC_RD_PTR_REG, pEncInfo->streamBufStartAddr);
		VpuWriteReg(MJPEG_BBC_CUR_POS_REG, 0);
		VpuWriteReg(MJPEG_BBC_DATA_CNT_REG, 256 / 4);
		VpuWriteReg(MJPEG_BBC_EXT_ADDR_REG, pEncInfo->streamBufStartAddr);
		VpuWriteReg(MJPEG_BBC_INT_ADDR_REG, 0);

		VpuWriteReg(MJPEG_GBU_BT_PTR_REG, 0);
		VpuWriteReg(MJPEG_GBU_WD_PTR_REG, 0);
		VpuWriteReg(MJPEG_GBU_BBSR_REG, 0);
		VpuWriteReg(MJPEG_BBC_STRM_CTRL_REG, 0);
		VpuWriteReg(MJPEG_GBU_CTRL_REG, 0);
		VpuWriteReg(MJPEG_GBU_FF_RPTR_REG, 0);

		VpuWriteReg(MJPEG_GBU_BBER_REG, ((256 / 4) * 2) - 1);
		VpuWriteReg(MJPEG_GBU_BBIR_REG, 256 / 4);
		VpuWriteReg(MJPEG_GBU_BBHR_REG, 256 / 4);

		VpuWriteReg(MJPEG_PIC_CTRL_REG, 0x18);

		VpuWriteReg(MJPEG_PIC_SIZE_REG, pEncInfo->jpgInfo.alignedWidth << 16 |
						pEncInfo->jpgInfo.alignedHeight);
		VpuWriteReg(MJPEG_ROT_INFO_REG, 0);

		VpuWriteReg(MJPEG_MCU_INFO_REG, pEncInfo->jpgInfo.mcuBlockNum << 16 |
						pEncInfo->jpgInfo.compNum << 12 |
						pEncInfo->jpgInfo.compInfo[0] << 8 |
						pEncInfo->jpgInfo.compInfo[1] << 4 |
						pEncInfo->jpgInfo.compInfo[2]);

		VpuWriteReg(MJPEG_SCL_INFO_REG, 0);
		VpuWriteReg(MJPEG_DPB_CONFIG_REG,
			    pEncInfo->openParam.chromaInterleave);
		VpuWriteReg(MJPEG_RST_INTVAL_REG, pEncInfo->jpgInfo.rstIntval);
		VpuWriteReg(MJPEG_BBC_CTRL_REG, 1);

		VpuWriteReg(MJPEG_OP_INFO_REG, pEncInfo->jpgInfo.busReqNum);

		if (!JpgEncLoadHuffTab(pEncInfo)) {
			UnlockVpu(vpu_semap);
			return RETCODE_INVALID_PARAM;
		}

		if (!JpgEncLoadQMatTab(pEncInfo)) {
			UnlockVpu(vpu_semap);
			return RETCODE_INVALID_PARAM;
		}

		if (rotMirMode & 1)
			VpuWriteReg(MJPEG_PIC_SIZE_REG,
				pEncInfo->jpgInfo.alignedHeight << 16 |
				pEncInfo->jpgInfo.alignedWidth);
		else
			VpuWriteReg(MJPEG_PIC_SIZE_REG,
				pEncInfo->jpgInfo.alignedWidth << 16 |
				pEncInfo->jpgInfo.alignedHeight);
		VpuWriteReg(MJPEG_ROT_INFO_REG, (rotMirEnable|rotMirMode));

		if (rotMirEnable)
			pEncInfo->jpgInfo.format = (pEncInfo->jpgInfo.format == FORMAT_422) ?
					 FORMAT_224 : (pEncInfo->jpgInfo.format == FORMAT_224) ?
					 FORMAT_422 : pEncInfo->jpgInfo.format;

		if (pEncInfo->jpgInfo.format == FORMAT_422)
			pEncInfo->jpgInfo.compInfo[0] = (rotMirMode & 1) ? 6 : 9;
		else if (pEncInfo->jpgInfo.format == FORMAT_224)
			pEncInfo->jpgInfo.compInfo[0] = (rotMirMode & 1) ? 9 : 6;

		VpuWriteReg(MJPEG_MCU_INFO_REG,
				pEncInfo->jpgInfo.mcuBlockNum << 16 |
				pEncInfo->jpgInfo.compNum << 12 |
				pEncInfo->jpgInfo.compInfo[0] << 8 |
				pEncInfo->jpgInfo.compInfo[1] << 4 |
				pEncInfo->jpgInfo.compInfo[2]);

		val = 0;
		VpuWriteReg(GDI_CONTROL, 1);
		while(!val)
			val = VpuReadReg(GDI_STATUS);
		if (pEncInfo->mapType)
			val = 3 << 20;
		else
			val = 0;
		VpuWriteReg(GDI_INFO_CONTROL, ((pEncInfo->jpgInfo.format & 0x07) << 17) |
					       (pEncInfo->openParam.chromaInterleave << 16) |
					       val | pSrcFrame->strideY);
		VpuWriteReg(GDI_INFO_PIC_SIZE, (pEncInfo->jpgInfo.alignedWidth << 16) |
						pEncInfo->jpgInfo.alignedHeight);
		VpuWriteReg(GDI_INFO_BASE_Y,  pSrcFrame->bufY);
		VpuWriteReg(GDI_INFO_BASE_CB, pSrcFrame->bufCb);
		VpuWriteReg(GDI_INFO_BASE_CR, pSrcFrame->bufCr);

		VpuWriteReg(MJPEG_DPB_BASE00_REG, 0);
		VpuWriteReg(GDI_CONTROL, 0);
		VpuWriteReg(GDI_PIC_INIT_HOST, 1);

		VpuWriteReg(MJPEG_PIC_START_REG, 1);

		*ppendingInst = pCodecInst;
		pEncInfo->jpgInfo.inProcess = 1;
		return RETCODE_SUCCESS;
	}

	if (!cpu_is_mx6x())
		rotMirMode = rotatorModeConversion[rotMirMode];
	rotMirMode |= rotMirEnable;
	VpuWriteReg(CMD_ENC_PIC_ROT_MODE, rotMirMode);

	VpuWriteReg(CMD_ENC_PIC_QS, param->quantParam);

	if (param->skipPicture) {
		VpuWriteReg(CMD_ENC_PIC_OPTION,
			    (pEncInfo->encReportSliceInfo.enable << 5) |
			    (pEncInfo->encReportMVInfo.enable << 4) |
			    (pEncInfo->encReportMBInfo.enable << 3) | 1);
	} else {
		if (cpu_is_mx6x()) {
			VpuWriteReg(CMD_ENC_PIC_SRC_INDEX, pSrcFrame->myIndex);
			VpuWriteReg(CMD_ENC_PIC_SRC_STRIDE, pSrcFrame->strideY);
		}
		VpuWriteReg(CMD_ENC_PIC_SRC_ADDR_Y, pSrcFrame->bufY +
			    param->encTopOffset * pSrcFrame->strideY + param->encLeftOffset);
		VpuWriteReg(CMD_ENC_PIC_SRC_ADDR_CB, pSrcFrame->bufCb +
			    param->encTopOffset/2 * pSrcFrame->strideC + param->encLeftOffset/2);
		VpuWriteReg(CMD_ENC_PIC_SRC_ADDR_CR, pSrcFrame->bufCr +
			    param->encTopOffset/2 * pSrcFrame->strideC + param->encLeftOffset/2);

		val = (pEncInfo->encReportSliceInfo.enable << 5) |
		      (pEncInfo->encReportMVInfo.enable << 4) |
		      (pEncInfo->encReportMBInfo.enable << 3) |
		      (param->forceIPicture << 1 & 0x2);
		if (!cpu_is_mx6x())
			val |= (!param->enableAutoSkip) << 2;
		VpuWriteReg(CMD_ENC_PIC_OPTION, val);
	}

	if (pEncInfo->dynamicAllocEnable == 1) {
		VpuWriteReg(CMD_ENC_PIC_BB_START, param->picStreamBufferAddr);
		VpuWriteReg(CMD_ENC_PIC_BB_SIZE,
			    param->picStreamBufferSize / 1024);
	}

	if (pEncInfo->encReportMBInfo.enable || pEncInfo->encReportMVInfo.enable ||
	    pEncInfo->encReportSliceInfo.enable) {
		Uint32 *virt_addr, phy_addr;

		if (!pEncInfo->picParaBaseMem.phy_addr) {
			pEncInfo->picParaBaseMem.size = ENC_ADDR_END_OF_RPT_BUF;
			ret = IOGetPhyMem(&pEncInfo->picParaBaseMem);
			if (ret) {
				err_msg("Unable to obtain physical mem\n");
				return RETCODE_FAILURE;
			}
			if (IOGetVirtMem(&pEncInfo->picParaBaseMem) == -1) {
				IOFreePhyMem(&pEncInfo->picParaBaseMem);
				pEncInfo->picParaBaseMem.phy_addr = 0;
				err_msg("Unable to obtain virtual mem\n");
				return RETCODE_FAILURE;
			}
		}

		VpuWriteReg(CMD_ENC_PIC_PARA_BASE_ADDR, pEncInfo->picParaBaseMem.phy_addr);

		virt_addr = (Uint32 *)pEncInfo->picParaBaseMem.virt_uaddr;
		phy_addr = pEncInfo->picParaBaseMem.phy_addr;
		/* Set mbParam buffer address */
		if (pEncInfo->encReportMBInfo.enable) {
			*virt_addr = phy_addr + ADDR_MB_BASE_OFFSET;
		}
		/* Set mvParam buffer address */
		if (pEncInfo->encReportMVInfo.enable) {
			*(virt_addr + 2) = phy_addr + ADDR_MV_BASE_OFFSET;
		}
		/* Set slice info address */
		if (pEncInfo->encReportSliceInfo.enable) {
			*(virt_addr + 4) = phy_addr + ADDR_SLICE_BASE_OFFSET;
		}
	}

	if (cpu_is_mx6x()) {
		val = (pEncInfo->secAxiUse.useBitEnable |
		       pEncInfo->secAxiUse.useIpEnable << 1 |
		       pEncInfo->secAxiUse.useDbkEnable << 2 |
		       pEncInfo->secAxiUse.useDbkEnable << 3 |
		       pEncInfo->secAxiUse.useOvlEnable << 4 |
		       pEncInfo->secAxiUse.useBtpEnable << 5 |
		       pEncInfo->secAxiUse.useHostBitEnable << 8 |
		       pEncInfo->secAxiUse.useHostIpEnable << 9 |
		       pEncInfo->secAxiUse.useHostDbkEnable << 10 |
		       pEncInfo->secAxiUse.useHostDbkEnable << 11 |
		       pEncInfo->secAxiUse.useHostOvlEnable << 12 |
		       pEncInfo->secAxiUse.useHostBtpEnable << 13);
	} else {
		val = (pEncInfo->secAxiUse.useBitEnable |
		       pEncInfo->secAxiUse.useIpEnable << 1 |
		       pEncInfo->secAxiUse.useDbkEnable << 2 |
		       pEncInfo->secAxiUse.useOvlEnable << 3 |
		       pEncInfo->secAxiUse.useMeEnable << 4 |
		       pEncInfo->secAxiUse.useHostBitEnable << 7 |
		       pEncInfo->secAxiUse.useHostIpEnable << 8 |
		       pEncInfo->secAxiUse.useHostDbkEnable << 9 |
		       pEncInfo->secAxiUse.useHostOvlEnable << 10 |
		       pEncInfo->secAxiUse.useHostMeEnable << 11);
	}
	VpuWriteReg(BIT_AXI_SRAM_USE, val);

	if (cpu_is_mx6x()) {
		val = (pEncInfo->subFrameSyncConfig.subFrameSyncOn << 15 |
		       pEncInfo->subFrameSyncConfig.sourceBufNumber << 8 |
		       pEncInfo->subFrameSyncConfig.sourceBufIndexBase << 0);
		VpuWriteReg(CMD_ENC_PIC_SUB_FRAME_SYNC, val);
	}

	BitIssueCommand(pCodecInst, PIC_RUN);

	*ppendingInst = pCodecInst;

	return RETCODE_SUCCESS;
}

/*!
 * @brief Get information of the output of encoding.
 *
 * @param encHandle [Input] The handle obtained from vpu_EncOpen().
 * @param info [Output] Pointer to EncOutputInfo data structure.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE encHandle is invalid.
 * @li RETCODE_WRONG_CALL_SEQUENCE Wrong calling sequence.
 * @li RETCODE_INVALID_PARAM info is a null pointer.
 */
RetCode vpu_EncGetOutputInfo(EncHandle handle, EncOutputInfo * info)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	RetCode ret;
	PhysicalAddress rdPtr;
	PhysicalAddress wrPtr;
	Uint32 val;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	if (info == 0) {
		return RETCODE_INVALID_PARAM;
	}

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	if (*ppendingInst == 0) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	if (pCodecInst != *ppendingInst) {
		return RETCODE_INVALID_HANDLE;
	}

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
#ifdef MEM_PROTECT
		if (VpuReadReg(GDI_WPROT_ERR_RSN)) {
			err_msg("ERR_CLR: 0x%lx, ERR_RSN: 0x%lx, ERR_ADR: 0x%lx\n",
					VpuReadReg(GDI_WPROT_ERR_CLR),
					VpuReadReg(GDI_WPROT_ERR_RSN),
					VpuReadReg(GDI_WPROT_ERR_ADR));
			*ppendingInst = 0;
			pEncInfo->jpgInfo.inProcess = 0;
			UnlockVpu(vpu_semap);
			return RETCODE_MEMORY_ACCESS_VIOLATION;
		}
#endif
		val = VpuReadReg(MJPEG_PIC_STATUS_REG);
		if ((val & 0x4) >> 2) {
			*ppendingInst = 0;
			pEncInfo->jpgInfo.inProcess = 0;
			UnlockVpu(vpu_semap);
			return RETCODE_WRONG_CALL_SEQUENCE;
		}

		if (val != 0)
			VpuWriteReg(MJPEG_PIC_STATUS_REG, val);

		info->bitstreamBuffer = pEncInfo->streamBufStartAddr;
		info->bitstreamSize = VpuReadReg(MJPEG_BBC_WR_PTR_REG) -
					pEncInfo->streamBufStartAddr;
		VpuWriteReg(MJPEG_BBC_FLUSH_CMD_REG, 0);
		info->picType = 0;
		info->numOfSlices = 0;
		*ppendingInst = 0;
		pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = VpuReadReg(MJPEG_BBC_WR_PTR_REG);
		pEncInfo->jpgInfo.inProcess = 0;

		/* Workaround to reset JPU after each encoder: decoder may be blocked
		 * after encoder randomly if not do reset. Fixme later */
		vpu_mx6_hwreset();

		UnlockVpu(vpu_semap);
		return RETCODE_SUCCESS;
	}

	if (cpu_is_mx6x() && VpuReadReg(RET_ENC_PIC_SUCCESS) & (1 << 31)) {
		*ppendingInst = 0;
		UnlockVpu(vpu_semap);
		return RETCODE_MEMORY_ACCESS_VIOLATION;
	}

	val = VpuReadReg(RET_ENC_PIC_TYPE);
	info->skipEncoded = (val >> 2) & 0x01;
	info->picType = val & 0x03;

	if (pEncInfo->ringBufferEnable == 0) {
		if (pEncInfo->dynamicAllocEnable == 1)
			rdPtr = VpuReadReg(CMD_ENC_PIC_BB_START);
		else
			rdPtr = pEncInfo->streamBufStartAddr;

		wrPtr = VpuReadReg(BIT_WR_PTR);
		info->bitstreamBuffer = rdPtr;
		info->bitstreamSize = wrPtr - rdPtr;
	}

	info->numOfSlices = VpuReadReg(RET_ENC_PIC_SLICE_NUM);
	info->bitstreamWrapAround = VpuReadReg(RET_ENC_PIC_FLAG);
	info->reconFrameIndex = VpuReadReg(RET_ENC_PIC_FRAME_IDX);

	if (cpu_is_mx27()) {
		info->pSliceInfo = (Uint32 *)((Uint32)virt_paraBuf + 0x1200);
		info->pMBInfo = virt_paraBuf;
		if (pCodecInst->codecMode == MP4_ENC &&
		    pEncInfo->openParam.mbQpReport == 1) {
			int widthInMB, heightInMB, readPnt, writePnt;
			Uint32 *virt_mbQpAddr;
			int i, j;
			Uint32 val1, val2;

			virt_mbQpAddr = (Uint32 *)((Uint32) virt_paraBuf + 0x1300);
			widthInMB = pEncInfo->openParam.picWidth / 16;
			heightInMB = pEncInfo->openParam.picHeight / 16;
			writePnt = 0;
			for (i = 0; i < heightInMB; ++i) {
				readPnt = i * 32;
				for (j = 0; j < widthInMB; j += 4) {
					val1 = virt_mbQpAddr[readPnt];
					readPnt++;
					val2 = virt_mbQpAddr[readPnt];
					readPnt++;
					val = (val1 << 8 & 0xff000000) | (val1 << 16) |
				    	      (val2 >> 8) | (val2 & 0x000000ff);
					virt_paraBuf2[writePnt] = val;
					writePnt++;
				}
			}
			info->pMBQpInfo = virt_paraBuf2;
		}
	}

	if (pEncInfo->encReportMBInfo.enable) {
		int size = 0;
		Uint32 tempBuf[2];
		Uint8 *dst_addr = NULL, *src_addr = NULL;
		Uint32 virt_addr = pEncInfo->picParaBaseMem.virt_uaddr;

		memcpy((char *)tempBuf, (void *)virt_addr, 8);
		val = *(tempBuf + 1);
		info->mbInfo.size = val & 0xFFFF;
		info->mbInfo.enable = (val >> 24) & 0xFF;
		info->mbInfo.addr = pEncInfo->encReportMBInfo.addr;
		if (info->mbInfo.addr && info->mbInfo.size) {
			size = (info->mbInfo.size + 7) / 8 * 8;
			dst_addr = (Uint8 *)info->mbInfo.addr;
			src_addr = (Uint8 *)(virt_addr + ADDR_MB_BASE_OFFSET);
			CopyBufferData(dst_addr, src_addr, size);
		}
	}

	if (pEncInfo->encReportMVInfo.enable) {
		int size = 0;
		Uint32 tempBuf[2];
		Uint8 *dst_addr = NULL, *src_addr = NULL;
		Uint32 virt_addr = pEncInfo->picParaBaseMem.virt_uaddr;

		memcpy((char *)tempBuf, (void *)(virt_addr + 8), 8);
		val = *(tempBuf + 1);
		info->mvInfo.size = val & 0xFFFF;
		info->mvInfo.enable = (val >> 24) & 0xFF;
		info->mvInfo.type = (val >> 16) & 0xFF;
		info->mvInfo.addr = pEncInfo->encReportMVInfo.addr;
		if (info->mvInfo.addr && info->mvInfo.size) {
			size = (info->mvInfo.size + 7) / 8 * 8;
			dst_addr = (Uint8 *)info->mvInfo.addr;
			src_addr = (Uint8 *)(virt_addr + ADDR_MV_BASE_OFFSET);
			CopyBufferData(dst_addr, src_addr, size);
		}
	}

	if (pEncInfo->encReportSliceInfo.enable) {
		int size = 0;
		Uint32 tempBuf[2];
		Uint8 *dst_addr = NULL, *src_addr = NULL;
		Uint32 virt_addr = pEncInfo->picParaBaseMem.virt_uaddr;

		memcpy((char *)tempBuf, (void *)(virt_addr + 16), 8);
		val = *(tempBuf + 1);

		info->sliceInfo.size = val & 0xFFFF;
		info->sliceInfo.enable = (val >> 24) & 0xFF;
		info->sliceInfo.type = (val >> 16) & 0xFF;
		info->sliceInfo.addr = pEncInfo->encReportSliceInfo.addr;
		if (info->sliceInfo.addr && info->sliceInfo.size) {
			size = (info->sliceInfo.size + 7) / 8 * 8;
			dst_addr = (Uint8 *)info->sliceInfo.addr;
			src_addr = (Uint8 *)(virt_addr + ADDR_SLICE_BASE_OFFSET);
			CopyBufferData(dst_addr, src_addr, size);
		}
	}

	/* Backup context regs */
	pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = VpuReadReg(BIT_WR_PTR);
	pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] = VpuReadReg(BIT_BIT_STREAM_PARAM);
	*ppendingInst = 0;
	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief This function gives a command to the encoder.
 *
 * @param encHandle [Input] The handle obtained from vpu_EncOpen().
 * @param cmd [Intput] user command.
 * @param param [Intput/Output] param  for cmd.
 *
 * @return
 * @li RETCODE_INVALID_COMMAND cmd is not one of 8 values above.
 * @li RETCODE_INVALID_HANDLE encHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished
 */
RetCode vpu_EncGiveCommand(EncHandle handle, CodecCommand cmd, void *param)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckEncInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS) {
		return ret;
	}

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	switch (cmd) {
	case ENABLE_ROTATION:
		{
			pEncInfo->rotationEnable = 1;
			break;
		}

	case DISABLE_ROTATION:
		{
			pEncInfo->rotationEnable = 0;
			break;
		}

	case ENABLE_MIRRORING:
		{
			pEncInfo->mirrorEnable = 1;
			break;
		}

	case DISABLE_MIRRORING:
		{
			pEncInfo->mirrorEnable = 0;
			break;
		}

	case SET_MIRROR_DIRECTION:
		{
			int mirDir;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			mirDir = *(int*) param;
			if (mirDir < MIRDIR_NONE || mirDir > MIRDIR_HOR_VER) {
				return RETCODE_INVALID_PARAM;
			}

			pEncInfo->mirrorDirection = (MirrorDirection)mirDir;
			break;
		}

	case SET_ROTATION_ANGLE:
		{
			int angle;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			angle = *(int *)param;
			if (angle != 0 && angle != 90 &&
			    angle != 180 && angle != 270) {
				return RETCODE_INVALID_PARAM;
			}

			if (pEncInfo->initialInfoObtained &&
			    (angle == 90 || angle == 270)) {
				return RETCODE_INVALID_PARAM;
			}

			pEncInfo->rotationAngle = angle;
			break;
		}

	case ENC_GET_SPS_RBSP:
		{
			if (pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			GetParaSet(handle, 0, param);
			UnlockVpu(vpu_semap);
			break;
		}

	case ENC_GET_PPS_RBSP:
		{
			if (pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			GetParaSet(handle, 1, param);
			UnlockVpu(vpu_semap);
			break;
		}

	case ENC_PUT_MP4_HEADER:
		{
			EncHeaderParam *encHeaderParam;

			if (pCodecInst->codecMode != MP4_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			encHeaderParam = (EncHeaderParam *) param;
			if (!(VOL_HEADER <= encHeaderParam->headerType &&
			      encHeaderParam->headerType <= VIS_HEADER)) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			EncodeHeader(handle, encHeaderParam);
			UnlockVpu(vpu_semap);
			break;
		}

	case ENC_PUT_AVC_HEADER:
		{
			EncHeaderParam *encHeaderParam;

			if (pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			encHeaderParam = (EncHeaderParam *) param;
			if (!(SPS_RBSP <= encHeaderParam->headerType &&
			      encHeaderParam->headerType <= PPS_RBSP_MVC)) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			EncodeHeader(handle, encHeaderParam);
			UnlockVpu(vpu_semap);
			break;
		}

	case ENC_SET_SEARCHRAM_PARAM:
		{
			/* dummy this command for none mx27 platform */
			if (!cpu_is_mx27())
				break;

			SearchRamParam *scRamParam = NULL;
			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			scRamParam = (SearchRamParam *) param;

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			VpuWriteReg(BIT_SEARCH_RAM_BASE_ADDR,
				    scRamParam->searchRamAddr);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_GET_VIDEO_HEADER:
		{
			int iNaluLen, iflagRot, iSliceNum;

			EncHeaderParam *encHeaderParam;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}
			encHeaderParam = (EncHeaderParam *)param;

			if (pCodecInst->codecMode == AVC_ENC) {
				if (!((SPS_RBSP == encHeaderParam->headerType)
						&& (pCodecInst->codecModeAux == AVC_AUX_AVC)
						&& (pEncInfo->ringBufferEnable == 0))) {
					return RETCODE_INVALID_PARAM;
				}
			}
			else
				return RETCODE_INVALID_PARAM;

			iflagRot = 0;
			iSliceNum = 0;
			if (pEncInfo->openParam.slicemode.sliceMode == 1
					&& pEncInfo->openParam.slicemode.sliceSizeMode == 1)
				iSliceNum = pEncInfo->openParam.slicemode.sliceSize;

			if (pEncInfo->rotationEnable) {
				if (pEncInfo->rotationAngle == 90 || pEncInfo->rotationAngle == 270)
					iflagRot = 1;
			}
			iNaluLen = (int)MakeSPS(encHeaderParam->pBuf, &pEncInfo->openParam,
					iflagRot, pEncInfo->openParam.bitRate, iSliceNum);
			if ((iNaluLen < 0) || (iNaluLen > encHeaderParam->size))
				return RETCODE_INVALID_PARAM;
			encHeaderParam->size = iNaluLen;

			break;
		}

	case ENC_GET_VOS_HEADER:
		{
			if (pCodecInst->codecMode != MP4_ENC) {
				return RETCODE_INVALID_COMMAND;
			}
			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			GetParaSet(handle, 1, param);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_GET_VO_HEADER:
		{
			if (pCodecInst->codecMode != MP4_ENC) {
				return RETCODE_INVALID_COMMAND;
			}
			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			GetParaSet(handle, 2, param);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_GET_VOL_HEADER:
		{
			if (pCodecInst->codecMode != MP4_ENC) {
				return RETCODE_INVALID_COMMAND;
			}
			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			GetParaSet(handle, 0, param);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_GET_JPEG_HEADER:
		{
			if (!is_mx6x_mjpg_codec(pCodecInst->codecMode))
				return RETCODE_INVALID_COMMAND;
			if (param == 0)
				return RETCODE_INVALID_PARAM;
			if (!JpgEncEncodeHeader(handle, param))
				return RETCODE_INVALID_PARAM;

			break;
		}

	case ENC_SET_GOP_NUMBER:
		{
			int *pGopNumber = (int *)param;
			if (pCodecInst->codecMode != MP4_ENC &&
			    pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (*pGopNumber < 0 || *pGopNumber > 32767) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetGopNumber(handle, (Uint32 *) pGopNumber);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_SET_INTRA_QP:
		{
			int *pIntraQp = (int *)param;
			if (pCodecInst->codecMode != MP4_ENC &&
			    pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (pCodecInst->codecMode == MP4_ENC) {
				if (*pIntraQp < 1 || *pIntraQp > 31)
					return RETCODE_INVALID_PARAM;
			}

			if (pCodecInst->codecMode == AVC_ENC) {
				if (*pIntraQp < 0 || *pIntraQp > 51)
					return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetIntraQp(handle, (Uint32 *) pIntraQp);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_SET_BITRATE:
		{
			int *pBitrate = (int *)param;
			if (pCodecInst->codecMode != MP4_ENC &&
			    pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (*pBitrate < 0 || *pBitrate > 32767) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetBitrate(handle, (Uint32 *) pBitrate);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_SET_FRAME_RATE:
		{
			int *pFramerate = (int *)param;
			if (pCodecInst->codecMode != MP4_ENC &&
			    pCodecInst->codecMode != AVC_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (*pFramerate <= 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetFramerate(handle, (Uint32 *) pFramerate);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_SET_INTRA_MB_REFRESH_NUMBER:
		{
			int *pIntraRefreshNum = (int *)param;

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetIntraRefreshNum(handle, (Uint32 *) pIntraRefreshNum);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_SET_SLICE_INFO:
		{
			EncSliceMode *pSliceMode = (EncSliceMode *) param;
			if (pSliceMode->sliceMode < 0 ||
			    pSliceMode->sliceMode > 1) {
				return RETCODE_INVALID_PARAM;
			}

			if (pSliceMode->sliceSizeMode < 0
			    || pSliceMode->sliceSizeMode > 1) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetSliceMode(handle, (EncSliceMode *) pSliceMode);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_ENABLE_HEC:
		{
			if (pCodecInst->codecMode != MP4_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetHecMode(handle, 1);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_DISABLE_HEC:
		{
			if (pCodecInst->codecMode != MP4_ENC) {
				return RETCODE_INVALID_COMMAND;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetHecMode(handle, 0);
			UnlockVpu(vpu_semap);

			break;
		}

	case ENC_SET_REPORT_MBINFO:
		{
			if (param == 0)
				return  RETCODE_INVALID_PARAM;
			pEncInfo->encReportMBInfo = *(EncReportInfo *)param;

			if (pEncInfo->encReportMBInfo.enable && !pEncInfo->encReportMBInfo.addr)
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case ENC_SET_REPORT_MVINFO:
		{
			if (param == 0)
				return  RETCODE_INVALID_PARAM;
			pEncInfo->encReportMVInfo = *(EncReportInfo *)param;

			if (pEncInfo->encReportMVInfo.enable && !pEncInfo->encReportMVInfo.addr)
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case ENC_SET_REPORT_SLICEINFO:
		{
			if (param == 0)
				return  RETCODE_INVALID_PARAM;
			pEncInfo->encReportSliceInfo = *(EncReportInfo *)param;

			if (pEncInfo->encReportSliceInfo.enable && !pEncInfo->encReportSliceInfo.addr)
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case ENC_SET_SUB_FRAME_SYNC:
		{
			EncSubFrameSyncConfig *subFrameSyncConfig;

			if (param == 0)
				return RETCODE_INVALID_PARAM;

			subFrameSyncConfig = (EncSubFrameSyncConfig *)param;
			pEncInfo->subFrameSyncConfig.subFrameSyncOn = subFrameSyncConfig->subFrameSyncOn;
			pEncInfo->subFrameSyncConfig.sourceBufNumber = subFrameSyncConfig->sourceBufNumber;
			pEncInfo->subFrameSyncConfig.sourceBufIndexBase = subFrameSyncConfig->sourceBufIndexBase;
			break;
		}

	case ENC_ENABLE_SUB_FRAME_SYNC:
		{
			pEncInfo->subFrameSyncConfig.subFrameSyncOn = 1;
			break;
		}

	case ENC_DISABLE_SUB_FRAME_SYNC:
		{
			pEncInfo->subFrameSyncConfig.subFrameSyncOn = 0;
			break;
		}

	case ENC_SET_INTRA_REFRESH_MODE:
		{
			pEncInfo->intraRefreshMode = *(int *)param;
			break;
		}

	case ENC_ENABLE_SOF_STUFF:
		{
			pEncInfo->jpgInfo.enableSofStuffing = *(int *)param;
			break;
		}

	default:
		err_msg("Invalid encoder command\n");
		return RETCODE_INVALID_COMMAND;
	}

	return RETCODE_SUCCESS;
}

/*!
 * @brief Decoder initialization
 *
 * @param pHandle [Output] Pointer to DecHandle type
 * @param pop [Input] Pointer to DecOpenParam type.
 *
 * @return
 * @li RETCODE_SUCCESS Success in acquisition of a decoder instance.
 * @li RETCODE_FAILURE Failed in acquisition of a decoder instance.
 * @li RETCODE_INVALID_PARAM pop is a null pointer or invalid.
 */
RetCode vpu_DecOpen(DecHandle * pHandle, DecOpenParam * pop)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	int instIdx;
	Uint32 val;
	RetCode ret;
#ifdef MEM_PROTECT
	int i;
#endif

	ENTER_FUNC();

	ret = CheckDecOpenParam(pop);
	if (ret != RETCODE_SUCCESS) {
		return ret;
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (!(cpu_is_mx6x() && pop->bitstreamFormat == STD_MJPG) && !isVpuInitialized()) {
		UnlockVpu(vpu_semap);
		return RETCODE_NOT_INITIALIZED;
	}

	ret = GetCodecInstance(&pCodecInst);
	if (ret == RETCODE_FAILURE) {
		*pHandle = 0;
		UnlockVpu(vpu_semap);
		return RETCODE_FAILURE;
	}
	UnlockVpu(vpu_semap);

	*pHandle = pCodecInst;
	instIdx = pCodecInst->instIndex;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	/* Allocate context buffer */
	pCodecInst->contextBufMem.size = SIZE_CONTEXT_BUF;
	if (cpu_is_mx6x() && pop->bitstreamFormat == STD_AVC)
		pCodecInst->contextBufMem.size += PS_SAVE_SIZE;
	ret = IOGetPhyMem(&pCodecInst->contextBufMem);
	if (ret) {
		err_msg("Unable to obtain physical mem\n");
		return RETCODE_FAILURE;
	}

	pDecInfo->openParam = *pop;

	if (cpu_is_mx27()) {
		pCodecInst->codecMode =
		    pop->bitstreamFormat == STD_AVC ? AVC_DEC : MP4_DEC;
	} else {
		switch (pop->bitstreamFormat) {
		case STD_MPEG4:
			pCodecInst->codecMode = MP4_DEC;
			pCodecInst->codecModeAux = MP4_AUX_MPEG4;
			break;
		case STD_AVC:
			pCodecInst->codecMode = AVC_DEC;
			if (cpu_is_mx6x())
				pCodecInst->codecModeAux = pop->avcExtension;
			break;
		case STD_VC1:
			pCodecInst->codecMode = VC1_DEC;
			break;
		case STD_MPEG2:
			pCodecInst->codecMode = MP2_DEC;
			break;
		case STD_DIV3:
			pCodecInst->codecMode = DV3_DEC;
			pCodecInst->codecModeAux = MP4_AUX_DIVX3;
			break;
		case STD_RV:
			pCodecInst->codecMode = RV_DEC;
			break;
		case STD_AVS:
			pCodecInst->codecMode = AVS_DEC;
			break;
		case STD_VP8:
			pCodecInst->codecMode = VPX_DEC;
			pCodecInst->codecModeAux = VPX_AUX_VP8;
			break;
		case STD_MJPG:
			pCodecInst->codecMode = MJPG_DEC;
			break;
		default:
			break;
		}
	}

	pDecInfo->streamWrPtr = pop->bitstreamBuffer;
	pDecInfo->streamBufStartAddr = pop->bitstreamBuffer;
	pDecInfo->streamBufSize = pop->bitstreamBufferSize;
	pDecInfo->streamBufEndAddr =
	    pop->bitstreamBuffer + pop->bitstreamBufferSize;
	pDecInfo->jpgInfo.pVirtBitStream = pop->pBitStream;
	pDecInfo->jpgInfo.frameOffset = 0;
	pDecInfo->jpgInfo.lineBufferMode = pop->jpgLineBufferMode;

	pDecInfo->frameBufPool = 0;

	pDecInfo->rotationEnable = 0;
	pDecInfo->mirrorEnable = 0;
	pDecInfo->mirrorDirection = MIRDIR_NONE;
	pDecInfo->rotationAngle = 0;
	pDecInfo->rotatorOutputValid = 0;
	pDecInfo->rotatorStride = 0;
	pDecInfo->deringEnable = 0;

	pDecInfo->filePlayEnable = pop->filePlayEnable;
	if (!cpu_is_mx6x() && pop->filePlayEnable == 1) {
		pDecInfo->picSrcSize =
		    (pop->picWidth << BIT_PIC_WIDTH_OFFSET) | pop->picHeight;
		pDecInfo->dynamicAllocEnable = pop->dynamicAllocEnable;
	}

	if (pCodecInst->codecMode == VPX_DEC)
		pDecInfo->picSrcSize = (pop->picWidth << 16) | pop->picHeight;

	pDecInfo->initialInfoObtained = 0;
	pDecInfo->vc1BframeDisplayValid = 0;

	pDecInfo->decReportFrameBufStat.enable = 0;
	pDecInfo->decReportMBInfo.enable = 0;
	pDecInfo->decReportMVInfo.enable = 0;
	pDecInfo->decReportUserData.enable = 0;
	pDecInfo->decReportUserData.size = 0;

	pDecInfo->frame_delay = -1;

	if (cpu_is_mx6x()) {
		pDecInfo->mapType = pop->mapType;
		pDecInfo->tiledLinearEnable = pop->tiled2LinearEnable;
		pDecInfo->cacheConfig.Bypass = 1;
#ifdef MEM_PROTECT
		for (i = 0; i < 6; i++)
			pDecInfo->writeMemProtectCfg.region[i].enable = 0;
#endif
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = pDecInfo->streamBufStartAddr;
	pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = pDecInfo->streamWrPtr;
	pCodecInst->ctxRegs[CTX_BIT_FRM_DIS_FLG] = 0;
	pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] = 0;

#ifdef MEM_PROTECT
	if (cpu_is_mx6x())
	{
		WriteMemProtectCfg *pCfg = NULL;
		pCfg = &pCodecInst->CodecInfo.decInfo.writeMemProtectCfg;
		/* Temp buf */
		pCfg->region[0].enable = 1;
		pCfg->region[0].is_secondary = 0;
		pCfg->region[0].start_address = bit_work_addr.phy_addr + CODE_BUF_SIZE;
		pCfg->region[0].end_address = bit_work_addr.phy_addr + CODE_BUF_SIZE + TEMP_BUF_SIZE;
		info_msg("Protection Region 0: Temp buf, start 0x%lx, end 0x%lx\n",
				pCfg->region[0].start_address,
				pCfg->region[0].end_address);
		/* Context buf */
		pCfg->region[1].enable = 1;
		pCfg->region[1].is_secondary = 0;
		pCfg->region[1].start_address = pCodecInst->contextBufMem.phy_addr;
		pCfg->region[1].end_address = pCodecInst->contextBufMem.phy_addr
			+ pCodecInst->contextBufMem.size;
		info_msg("Protection Region 1: Context buf, start 0x%lx, end 0x%lx\n",
				pCfg->region[1].start_address,
				pCfg->region[1].end_address);
	}
#endif

	LockVpuReg(vpu_semap);

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		pDecInfo->jpgInfo.seqInited = 0;
		pDecInfo->jpgInfo.quitCodec = 0;
		pDecInfo->jpgInfo.rollBack = 0;
	} else {
		if (instIdx == (int)VpuReadReg(BIT_RUN_INDEX)) {
			VpuWriteReg(BIT_RD_PTR, pDecInfo->streamBufStartAddr);
			VpuWriteReg(BIT_WR_PTR, pDecInfo->streamWrPtr);
			VpuWriteReg(BIT_FRM_DIS_FLG, 0);
		}
	}
	UnlockVpuReg(vpu_semap);

	val = VpuReadReg(BIT_FRAME_MEM_CTRL);
	val &= ~(1 << 2 | 1 << 3); /* clear the bit firstly */
	val &= 0x3f;
	if (cpu_is_mx6x()) {
		if (pDecInfo->openParam.bitstreamMode)
			pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] |= 1 << 3;

		if (pDecInfo->mapType)
			val |= (pDecInfo->tiledLinearEnable << 11 | 0x03 << 9);
	}
	pCodecInst->ctxRegs[CTX_BIT_FRAME_MEM_CTRL] =
		    val | (pDecInfo->openParam.chromaInterleave << 2);

	info_msg("bitstreamMode %d, chromaInterleave %d, mapType %d, tiled2LinearEnable %d\n",
			pop->bitstreamMode, pop->chromaInterleave, pop->mapType, pop->tiled2LinearEnable);

	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Decoder close function
 *
 * @param  handle [Input] The handle obtained from vpu_DecOpen().
 *
 * @return
 * @li RETCODE_SUCCESS Successful closing.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 */
RetCode vpu_DecClose(DecHandle handle)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	if (*ppendingInst == pCodecInst) {
		return RETCODE_FRAME_NOT_COMPLETE;
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode))
		goto dec_out;

	if (pDecInfo->initialInfoObtained) {
		BitIssueCommand(pCodecInst, SEQ_END);
		while (VpuReadReg(BIT_BUSY_FLAG)) ;
	}

dec_out:
	/* Free memory allocated for data report functions */
	if (pDecInfo->picParaBaseMem.phy_addr) {
		IOFreeVirtMem(&pDecInfo->picParaBaseMem);
		IOFreePhyMem(&pDecInfo->picParaBaseMem);
	}
	if (pDecInfo->userDataBufMem.phy_addr) {
		IOFreeVirtMem(&pDecInfo->userDataBufMem);
		IOFreePhyMem(&pDecInfo->userDataBufMem);
	}
	/* Free context buf Mem */
	IOFreePhyMem(&pCodecInst->contextBufMem);

	FreeCodecInstance(pCodecInst);
	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

RetCode vpu_DecSetEscSeqInit(DecHandle handle, int escape)
{
	CodecInst *pCodecInst;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode))
		return RETCODE_SUCCESS;

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (escape == 0)
		pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] &= ~0x01;
	else
		pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] |= 0x01;

	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Get header information of bitstream.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 * @param info [Output] Pointer to DecInitialInfo data structure.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_FAILURE There was an error in getting initial information.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_INVALID_PARAM info is an invalid pointer.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 * @li RETCODE_WRONG_CALL_SEQUENCE Wrong calling sequence.
 */
RetCode vpu_DecGetInitialInfo(DecHandle handle, DecInitialInfo * info)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	Uint32 val, val2;
#ifndef MEM_PROTECT
	SetIramParam iramParam;
#endif
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS) {
		return ret;
	}

	if (info == 0) {
		return RETCODE_INVALID_PARAM;
	}

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {

		if (!LockVpu(vpu_semap))
			return RETCODE_FAILURE_TIMEOUT;

		/* set tiled map type info */
		SetTiledMapTypeInfo(pDecInfo->mapType, &pDecInfo->sTiledInfo);

		if (pDecInfo->jpgInfo.lineBufferMode) {
			pDecInfo->jpgInfo.pVirtJpgChunkBase = pDecInfo->jpgInfo.pVirtBitStream;
			pDecInfo->jpgInfo.chunkSize = pDecInfo->streamBufSize;
		}
		if (!JpegDecodeHeader(pDecInfo)) {
			UnlockVpu(vpu_semap);
			err_msg("JpegDecodeHeader failure\n");
			return RETCODE_FAILURE;
		}

		info->picWidth = pDecInfo->jpgInfo.picWidth;
		info->picHeight = pDecInfo->jpgInfo.picHeight;
		info->minFrameBufferCount = 1;
		info->mjpg_sourceFormat = pDecInfo->jpgInfo.format;
		info->streamInfoObtained = 1;
		pDecInfo->initialInfo = *info;
		pDecInfo->initialInfoObtained = 1;
		pDecInfo->jpgInfo.frameOffset = 0;

		if (pDecInfo->openParam.mjpg_thumbNailDecEnable == 1) {
			if((pDecInfo->jpgInfo.ThumbInfo.ThumbType != JFXX_JPG)
				&& (pDecInfo->jpgInfo.ThumbInfo.ThumbType != EXIF_JPG)) {
				info->mjpg_thumbNailEnable = 0;
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			}
			else {
				info->mjpg_thumbNailEnable = 1;
			}
		}

		UnlockVpu(vpu_semap);
		return RETCODE_SUCCESS;
	}

	if (pDecInfo->initialInfoObtained) {
		return RETCODE_CALLED_BEFORE;
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (DecBitstreamBufEmpty(handle)) {
		warn_msg("rd 0x%lx, rd reg 0x%lx, wr 0x%lx, wr reg 0x%lx, idx %d, idx reg %ld\n",
				pCodecInst->ctxRegs[CTX_BIT_RD_PTR], VpuReadReg(BIT_RD_PTR),
				pCodecInst->ctxRegs[CTX_BIT_WR_PTR], VpuReadReg(BIT_WR_PTR),
				pCodecInst->instIndex, VpuReadReg(BIT_RUN_INDEX));

		UnlockVpu(vpu_semap);
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	VpuWriteReg(CMD_DEC_SEQ_BB_START, pDecInfo->streamBufStartAddr);
	VpuWriteReg(CMD_DEC_SEQ_BB_SIZE, pDecInfo->streamBufSize / 1024);

	if (!cpu_is_mx6x() && pDecInfo->filePlayEnable == 1) {
		VpuWriteReg(CMD_DEC_SEQ_START_BYTE,
			    pDecInfo->openParam.streamStartByteOffset);
	}

	if (pCodecInst->codecMode == VPX_DEC)
		VpuWriteReg(CMD_DEC_SEQ_START_BYTE, 0);

	val = 0;
	if (!cpu_is_mx6x())
		val = ((pDecInfo->dynamicAllocEnable << 3) & 0x8) |
			((pDecInfo->filePlayEnable << 2) & 0x4);

	val |= ((pDecInfo->openParam.reorderEnable << 1) & 0x2);
	if (pCodecInst->codecMode == MJPG_DEC) {
		val |= 1 << 10; /* force not interrupt mode */
		val |= pDecInfo->decReportUserData.enable << 5;
	}

	if (pDecInfo->decReportUserData.enable &&
	    !pDecInfo->userDataBufMem.phy_addr) {
		pDecInfo->userDataBufMem.size = pDecInfo->decReportUserData.size;
		ret = IOGetPhyMem(&pDecInfo->userDataBufMem);
		if (ret) {
			err_msg("Unable to obtain physical mem\n");
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}
		if (IOGetVirtMem(&pDecInfo->userDataBufMem) == -1) {
			IOFreePhyMem(&pDecInfo->userDataBufMem);
			pDecInfo->userDataBufMem.phy_addr = 0;
			err_msg("Unable to obtain virtual mem\n");
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}
		VpuWriteReg(CMD_DEC_PIC_USER_DATA_BASE_ADDR, pDecInfo->userDataBufMem.phy_addr);
		VpuWriteReg(CMD_DEC_PIC_USER_DATA_BUF_SIZE, pDecInfo->decReportUserData.size);
	}

	if (cpu_is_mx27()) {
		val |= (pDecInfo->openParam.qpReport & 0x1);
	} else {
		val |= (pDecInfo->openParam.mp4DeblkEnable & 0x1);
	}

	VpuWriteReg(CMD_DEC_SEQ_OPTION, val);

	if(pCodecInst->codecMode == VC1_DEC) {
		VpuWriteReg(CMD_DEC_SEQ_VC1_STREAM_FMT, 0);
	}

	if(pCodecInst->codecMode == MP4_DEC) {
		VpuWriteReg(CMD_DEC_SEQ_MP4_ASP_CLASS, pDecInfo->openParam.mp4Class);
	}

	if (pCodecInst->codecMode == AVC_DEC) {
		if (cpu_is_mx6x())
			VpuWriteReg(CMD_DEC_SEQ_X264_MV_EN, 0);
		else {
			VpuWriteReg(CMD_DEC_SEQ_PS_BB_START,
				    pDecInfo->openParam.psSaveBuffer);
			VpuWriteReg(CMD_DEC_SEQ_PS_BB_SIZE,
				    (pDecInfo->openParam.psSaveBufferSize / 1024));
		}
	}

	if (pCodecInst->codecMode == MJPG_DEC) {
		VpuWriteReg(CMD_DEC_SEQ_JPG_THUMB_EN,
			    pDecInfo->openParam.mjpg_thumbNailDecEnable);
	}

	if (!cpu_is_mx6x())
		VpuWriteReg(CMD_DEC_SEQ_SRC_SIZE, pDecInfo->picSrcSize);
	else if (cpu_is_mx6x() && (pCodecInst->codecMode == AVC_DEC))
		VpuWriteReg(CMD_DEC_SEQ_SPP_CHUNK_SIZE, 512);

	BitIssueCommand(pCodecInst, SEQ_INIT);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	if (cpu_is_mx6x() && pDecInfo->openParam.bitstreamMode) {
		/* check once more in roll back mode, in case
		 * BIT_BUSY_FLAG=0 is caused by reset */
		while (VpuReadReg(BIT_BUSY_FLAG)) ;
	}

	/* Backup rd pointer to ctx */
	pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = VpuReadReg(BIT_RD_PTR);
	pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] = VpuReadReg(BIT_BIT_STREAM_PARAM);

	val = VpuReadReg(RET_DEC_SEQ_SUCCESS);

	if (cpu_is_mx6x()) {
#ifdef MEM_PROTECT
		if (val & (1 << 31)) {
			err_msg("access violation in vpu_DecGetInitialInfo\n");
			err_msg("PC: 0x%lx, ERR_CLR: 0x%lx, ERR_RSN: 0x%lx, ERR_ADR: 0x%lx\n",
					VpuReadReg(BIT_CUR_PC),
					VpuReadReg(GDI_WPROT_ERR_CLR),
					VpuReadReg(GDI_WPROT_ERR_RSN),
					VpuReadReg(GDI_WPROT_ERR_ADR));
			vpu_mx6_swreset(0);
			UnlockVpu(vpu_semap);
			return RETCODE_MEMORY_ACCESS_VIOLATION;
		}
#endif
		if (pDecInfo->openParam.bitstreamMode && (val & (1 << 4))) {
			VpuWriteReg(BIT_RUN_INDEX, pCodecInst->instIndex);
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}
	}

	if (val == 0) {
		val = VpuReadReg(RET_DEC_SEQ_ERR_REASON);
		info->errorcode = val;

		UnlockVpu(vpu_semap);
		return RETCODE_FAILURE;
	}

	val = VpuReadReg(RET_DEC_SEQ_SRC_SIZE);
	if (!cpu_is_mx27()) {
		info->picWidth = ((val >> 16) & 0xffff);
		info->picHeight = (val & 0xffff);
	} else {
		info->picWidth = ((val >> 10) & 0x3ff);
		info->picHeight = (val & 0x3ff);
	}

	if (pCodecInst->codecMode  == MJPG_DEC) {
		if (info->picWidth < 16 || info->picHeight < 16) {
			UnlockVpu(vpu_semap);
			return RETCODE_NOT_SUPPORTED;
		}
	}
	else {
		if (info->picWidth < 64 || info->picHeight < 64) {
			UnlockVpu(vpu_semap);
			return RETCODE_NOT_SUPPORTED;
		}
	}

	if (cpu_is_mx6x()) {
		info->frameRateRes = VpuReadReg(RET_DEC_SEQ_FRATE_NR);
		info->frameRateDiv = VpuReadReg(RET_DEC_SEQ_FRATE_DR);
		info->bitRate = VpuReadReg(RET_DEC_SEQ_BIT_RATE);
	} else
		info->frameRateInfo = VpuReadReg(RET_DEC_SEQ_SRC_F_RATE);

	if (pCodecInst->codecMode == MP4_DEC) {
		val = VpuReadReg(RET_DEC_SEQ_INFO);
		info->mp4_shortVideoHeader = (val >> 2) & 1;
		info->mp4_dataPartitionEnable = val & 1;
		info->mp4_reversibleVlcEnable =
		    info->mp4_dataPartitionEnable ? ((val >> 1) & 1) : 0;
		info->h263_annexJEnable = (val >> 3) & 1;
	} else if (pCodecInst->codecMode == VPX_DEC &&
		   pCodecInst->codecModeAux == VPX_AUX_VP8) {
        /* h_scale[31:30] v_scale[29:28] pic_width[27:14] pic_height[13:0] */
		val = VpuReadReg(RET_DEC_SEQ_VP8_SCALE_INFO);
		info->vp8ScaleInfo.hScaleFactor = (val >> 30) & 0x03;
		info->vp8ScaleInfo.vScaleFactor = (val >> 28) & 0x03;
		info->vp8ScaleInfo.picWidth = (val >> 14) & 0x3FFF;
		info->vp8ScaleInfo.picHeight = (val >> 0) & 0x3FFF;
	}

	info->minFrameBufferCount = VpuReadReg(RET_DEC_SEQ_FRAME_NEED);
	info->frameBufDelay = VpuReadReg(RET_DEC_SEQ_FRAME_DELAY);

	if (pCodecInst->codecMode == AVC_DEC) {
		val = VpuReadReg(RET_DEC_SEQ_CROP_LEFT_RIGHT);
		val2 = VpuReadReg(RET_DEC_SEQ_CROP_TOP_BOTTOM);
		if (val == 0 && val2 == 0) {
			info->picCropRect.left = 0;
			info->picCropRect.right = 0;
			info->picCropRect.top = 0;
			info->picCropRect.bottom = 0;
		} else {
			if (!cpu_is_mx27()) {
				info->picCropRect.left =
				    ((val >> 16) & 0xFFFF);
				info->picCropRect.right =
				    info->picWidth - ((val & 0xFFFF));
				info->picCropRect.top =
				    ((val2 >> 16) & 0xFFFF);
				info->picCropRect.bottom =
				    info->picHeight - ((val2 & 0xFFFF));

			} else {
				info->picCropRect.left =
				    ((val >> 10) & 0x3FF) * 2;
				info->picCropRect.right =
				    info->picWidth - ((val & 0x3FF) * 2);
				info->picCropRect.top =
				    ((val2 >> 10) & 0x3FF) * 2;
				info->picCropRect.bottom =
				    info->picHeight - ((val2 & 0x3FF) * 2);
			}
		}

#ifdef ALLOC_MAX_RESOLUTION
		val = MAX_PIC_WIDTH * MAX_PIC_HEIGHT;
#else
		val = info->picWidth * info->picHeight;
#endif
		info->normalSliceSize = (val * 3 / 2) / 1024 / 4;
		info->worstSliceSize = ((val / 256) * 3200 / 8  + 512)/ 1024;
	} else {
		info->picCropRect.left = 0;
		info->picCropRect.right = 0;
		info->picCropRect.top = 0;
		info->picCropRect.bottom = 0;
	}

	if (!cpu_is_mx6x() && pCodecInst->codecMode == MJPG_DEC) {
		info->mjpg_thumbNailEnable =
			(VpuReadReg(RET_DEC_SEQ_JPG_THUMB_IND) & 0x01);
		info->mjpg_sourceFormat =
			(VpuReadReg(RET_DEC_SEQ_JPG_PARA) & 0x07);
		if (pDecInfo->openParam.mjpg_thumbNailDecEnable == 1)
			if (info->mjpg_thumbNailEnable == 0) {
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			}
	}

	if (!cpu_is_mx27()) {
		val = VpuReadReg(RET_DEC_SEQ_HEADER_REPORT);
		info->profile =	(val >> 0) & 0xFF;
		info->level = (val >> 8) & 0xFF;
		info->interlace  = (val >> 16) & 0x01;
		info->direct8x8Flag = (val >> 17) & 0x01;
		info->vc1_psf =	(val >> 18) & 0x01;
		info->constraint_set_flag[0] = (val >> 19) & 0x01;
		info->constraint_set_flag[1] = (val >> 20) & 0x01;
		info->constraint_set_flag[2] = (val >> 21) & 0x01;
		info->constraint_set_flag[3] = (val >> 22) & 0x01;
	}

	val = VpuReadReg(RET_DEC_SEQ_ASPECT);
	info->aspectRateInfo = val;

	if (cpu_is_mx6x() && (pCodecInst->codecMode == AVC_DEC)) {
		val = VpuReadReg(RET_DEC_SEQ_VUI_INFO);
		info->avcVuiInfo.fixedFrameRateFlag    = val &1;
		info->avcVuiInfo.timingInfoPresent     = (val>>1) & 0x01;
		info->avcVuiInfo.chromaLocBotField     = (val>>2) & 0x07;
		info->avcVuiInfo.chromaLocTopField     = (val>>5) & 0x07;
		info->avcVuiInfo.chromaLocInfoPresent  = (val>>8) & 0x01;
		info->avcVuiInfo.colorPrimaries        = (val>>16) & 0xff;
		info->avcVuiInfo.colorDescPresent      = (val>>24) & 0x01;
		info->avcVuiInfo.isExtSAR              = (val>>25) & 0x01;
		info->avcVuiInfo.vidFullRange          = (val>>26) & 0x01;
		info->avcVuiInfo.vidFormat             = (val>>27) & 0x07;
		info->avcVuiInfo.vidSigTypePresent     = (val>>30) & 0x01;
		info->avcVuiInfo.vuiParamPresent       = (val>>31) & 0x01;

		val = VpuReadReg(RET_DEC_SEQ_VUI_PIC_STRUCT);
		info->avcVuiInfo.vuiPicStructPresent = (val & 0x1);
		info->avcVuiInfo.vuiPicStruct = (val>>1);
	}

	info->reportBufSize.frameBufStatBufSize = SIZE_FRAME_BUF_STAT;
	info->reportBufSize.mbInfoBufSize = SIZE_MB_DATA;
	info->reportBufSize.mvInfoBufSize = SIZE_MV_DATA;

	if (!cpu_is_mx27())
		info->streamInfoObtained = 1;
	else
		info->streamInfoObtained = 0;

	UnlockVpu(vpu_semap);

	pDecInfo->initialInfo = *info;
	pDecInfo->initialInfoObtained = 1;

	/* Set secondAXI IRAM */
	if (!cpu_is_mx27()) {
#ifndef MEM_PROTECT /* use temp buf via pri AXI to save a protection region */
#ifdef ALLOC_MAX_RESOLUTION
		iramParam.width = (MAX_PIC_WIDTH + 15) & ~15;
		iramParam.height = (MAX_PIC_HEIGHT + 15) & ~15;
#else
		iramParam.width = (info->picWidth + 15) & ~15;
		iramParam.height = (info->picHeight + 15) & ~15;
#endif
		iramParam.profile = info->profile;
		iramParam.codecMode = pCodecInst->codecMode;
		SetDecSecondAXIIRAM(&pDecInfo->secAxiUse, &iramParam);
#endif
	}

	if (cpu_is_mx6x()) {
		SetTiledMapTypeInfo(pDecInfo->mapType, &pDecInfo->sTiledInfo);
		/* Enable 2-D cache */
		SetMaverickCache(&pDecInfo->cacheConfig, pDecInfo->mapType,
			    pDecInfo->openParam.chromaInterleave);
	}

	return RETCODE_SUCCESS;
}

/*!
 * @brief Register decoder frame buffers.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 * @param bufArray [Input] Pointer to the first element of an array of FrameBuffer.
 * @param num [Input] Number of elements of the array.
 * @param stride [Input] Stride value of frame buffers being registered.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 * @li RETCODE_WRONG_CALL_SEQUENCE Wrong calling sequence.
 * @li RETCODE_INVALID_FRAME_BUFFER Buffer is an invalid pointer.
 * @li RETCODE_INSUFFICIENT_FRAME_BUFFERS num is less than
 * the value requested by vpu_DecGetInitialInfo().
 * @li RETCODE_INVALID_STRIDE stride is less than the picture width.
 */
RetCode vpu_DecRegisterFrameBuffer(DecHandle handle,
				   FrameBuffer * bufArray, int num, int stride,
				   DecBufInfo * pBufInfo)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	int temp_baseAddr, i;
	Uint32 val;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	if (pDecInfo->frameBufPool) {
		return RETCODE_CALLED_BEFORE;
	}

	if (!pDecInfo->initialInfoObtained) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	if (bufArray == 0) {
		return RETCODE_INVALID_FRAME_BUFFER;
	}

	if (num < pDecInfo->initialInfo.minFrameBufferCount) {
		return RETCODE_INSUFFICIENT_FRAME_BUFFERS;
	}

	if (!is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		if (stride < pDecInfo->initialInfo.picWidth || stride % 8 != 0)
			return RETCODE_INVALID_STRIDE;
	}

	pDecInfo->frameBufPool = bufArray;
	pDecInfo->numFrameBuffers = num;
	pDecInfo->stride = stride;

	if (pDecInfo->openParam.bitstreamFormat == STD_MJPG)
		return RETCODE_SUCCESS;

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

#ifdef MEM_PROTECT
	if (cpu_is_mx6x())
	{
		WriteMemProtectCfg *pCfg = NULL;
		Uint32 minFB = 0xFFFFFFFF, maxFB = 0;
		Uint32 minMV = 0xFFFFFFFF, maxMV = 0;
		int align;
		int picheight;
		pCfg = &pCodecInst->CodecInfo.decInfo.writeMemProtectCfg;
		/* Frame buf */
		if ((pDecInfo->openParam.bitstreamFormat == STD_MPEG2
			|| pDecInfo->openParam.bitstreamFormat == STD_VC1
			|| pDecInfo->openParam.bitstreamFormat == STD_AVC
			|| pDecInfo->openParam.bitstreamFormat == STD_VP8)
			&& pDecInfo->initialInfo.interlace == 1) {
			align = 32;
		}
		else {
			align = 16;
		}

		picheight = ((pDecInfo->initialInfo.picHeight + align - 1) & ~(align - 1));
		for (i = 0; i < num; i++) {
			info_msg("[%d] bufY 0x%lx, bufCb 0x%lx, bufCr 0x%lx, bufMvCol 0x%lx\n",
				i, bufArray[i].bufY, bufArray[i].bufCb,
				bufArray[i].bufCr, bufArray[i].bufMvCol);
			/* Caution: Y/Cb/Cr is assumed to be contiguous */
			/* not for Tiled format */
			if (minFB > bufArray[i].bufY) minFB = bufArray[i].bufY;
			if (maxFB < bufArray[i].bufY) maxFB = bufArray[i].bufY;
			if (minMV > bufArray[i].bufMvCol) minMV = bufArray[i].bufMvCol;
			if (maxMV < bufArray[i].bufMvCol) maxMV = bufArray[i].bufMvCol;
		}
		pCfg->region[2].enable = 1;
		pCfg->region[2].is_secondary = 0;
		pCfg->region[2].start_address = minFB;
		pCfg->region[2].end_address = maxFB+stride*picheight*3/2;
		info_msg("Protection Region 2: Frame buf, start 0x%lx, end 0x%lx\n",
				pCfg->region[2].start_address,
				pCfg->region[2].end_address);
		pCfg->region[3].enable = 1;
		pCfg->region[3].is_secondary = 0;
		pCfg->region[3].start_address = minMV;
		pCfg->region[3].end_address = maxMV+stride*picheight/4;
		info_msg("Protection Region 3: MvCol buf, start 0x%lx, end 0x%lx\n",
				pCfg->region[3].start_address,
				pCfg->region[3].end_address);

		/* AVC Slice save buf */
		if (pCodecInst->codecMode == AVC_DEC) {
			pCfg->region[4].enable = 1;
			pCfg->region[4].is_secondary = 0;
			pCfg->region[4].start_address = pBufInfo->avcSliceBufInfo.bufferBase;
			pCfg->region[4].end_address = pBufInfo->avcSliceBufInfo.bufferBase
				+ pBufInfo->avcSliceBufInfo.bufferSize;
			info_msg("Protection Region 4: AVC Slice save buf, start 0x%lx, end 0x%lx\n",
					pCfg->region[4].start_address,
					pCfg->region[4].end_address);
		}

		/* AVC Ps save buf (moved to temp buf by FW) */
	}
#endif

	if (cpu_is_mx27()) {
		/* Let the codec know the addresses of the frame buffers. */
		for (i = 0; i < num; ++i) {
			virt_paraBuf[i * 3] = bufArray[i].bufY;
			virt_paraBuf[i * 3 + 1] = bufArray[i].bufCb;
			virt_paraBuf[i * 3 + 2] = bufArray[i].bufCr;
		}
	} else {
		/* none mx27 platform case need to swap word */
		for (i = 0; i < num; i += 2) {
			if (pDecInfo->mapType == LINEAR_FRAME_MAP) {
				if (!(IOPhyMemCheck(bufArray[i].bufY, "bufY")
				   && IOPhyMemCheck(bufArray[i].bufCb, "bufCb"))) {
					UnlockVpu(vpu_semap);
					return RETCODE_INVALID_FRAME_BUFFER;
				}
				if (pDecInfo->openParam.chromaInterleave == 0) {
					if (!IOPhyMemCheck(bufArray[i].bufCr, "bufCr")) {
						UnlockVpu(vpu_semap);
						return RETCODE_INVALID_FRAME_BUFFER;
					}
				}
			}
			virt_paraBuf[i * 3] = bufArray[i].bufCb;
			virt_paraBuf[i * 3 + 1] = bufArray[i].bufY;
			virt_paraBuf[i * 3 + 3] = bufArray[i].bufCr;
			if (pDecInfo->openParam.bitstreamFormat == STD_AVC)
				virt_paraBuf[96 + i + 1] = bufArray[i].bufMvCol;
			if (i + 1 < num) {
				virt_paraBuf[i * 3 + 2] = bufArray[i + 1].bufY;
				virt_paraBuf[i * 3 + 4] = bufArray[i + 1].bufCr;
				virt_paraBuf[i * 3 + 5] = bufArray[i + 1].bufCb;
				if (pDecInfo->openParam.bitstreamFormat ==
				    STD_AVC)
					virt_paraBuf[96 + i] =
					    bufArray[i + 1].bufMvCol;
			}
		}
		if (pDecInfo->openParam.bitstreamFormat == STD_VC1 ||
		    pDecInfo->openParam.bitstreamFormat == STD_MPEG4 ||
		    pDecInfo->openParam.bitstreamFormat == STD_AVS ||
		    pDecInfo->openParam.bitstreamFormat == STD_RV)
			virt_paraBuf[97] = bufArray[0].bufMvCol;
	}

	/* Tell the decoder how much frame buffers were allocated. */
	VpuWriteReg(CMD_SET_FRAME_BUF_NUM, num);
	VpuWriteReg(CMD_SET_FRAME_BUF_STRIDE, stride);

	if (!cpu_is_mx27()) {
		VpuWriteReg(CMD_SET_FRAME_AXI_BIT_ADDR, pDecInfo->secAxiUse.bufBitUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_IPACDC_ADDR, pDecInfo->secAxiUse.bufIpAcDcUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_DBKY_ADDR, pDecInfo->secAxiUse.bufDbkYUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_DBKC_ADDR, pDecInfo->secAxiUse.bufDbkCUse);
		VpuWriteReg(CMD_SET_FRAME_AXI_OVL_ADDR, pDecInfo->secAxiUse.bufOvlUse);
		if (cpu_is_mx6x())
			VpuWriteReg(CMD_SET_FRAME_AXI_BTP_ADDR, pDecInfo->secAxiUse.bufBtpUse);
	} else
		VpuWriteReg(BIT_AXI_SRAM_USE, 0);       /* not use SRAM */

	if (cpu_is_mx6x())
		VpuWriteReg(CMD_SET_FRAME_DELAY, pDecInfo->frame_delay);

	if (cpu_is_mx6x()) {
		/* Maverick Cache Configuration */
		val = (pDecInfo->cacheConfig.luma.cfg.PageSizeX << 28) |
		      (pDecInfo->cacheConfig.luma.cfg.PageSizeY << 24) |
		      (pDecInfo->cacheConfig.luma.cfg.CacheSizeX << 20) |
		      (pDecInfo->cacheConfig.luma.cfg.CacheSizeY << 16) |
		      (pDecInfo->cacheConfig.chroma.cfg.PageSizeX << 12) |
		      (pDecInfo->cacheConfig.chroma.cfg.PageSizeY << 8) |
		      (pDecInfo->cacheConfig.chroma.cfg.CacheSizeX << 4) |
		      (pDecInfo->cacheConfig.chroma.cfg.CacheSizeY << 0);
		VpuWriteReg(CMD_SET_FRAME_CACHE_SIZE, val);

		val = (pDecInfo->cacheConfig.Bypass << 4) |
		      (pDecInfo->cacheConfig.DualConf << 2) |
		      (pDecInfo->cacheConfig.PageMerge << 0);
		val = val << 24;
		val |= (pDecInfo->cacheConfig.LumaBufferSize << 16) |
		       (pDecInfo->cacheConfig.CbBufferSize << 8) |
		       (pDecInfo->cacheConfig.CrBufferSize);
		VpuWriteReg(CMD_SET_FRAME_CACHE_CONFIG, val);
	}

	if (pCodecInst->codecMode == VPX_DEC &&
	    pCodecInst->codecModeAux == VPX_AUX_VP8) {
		VpuWriteReg(CMD_SET_FRAME_MB_BUF_BASE,
				pBufInfo->vp8MbDataBufInfo.bufferBase);
	}

	if (pCodecInst->codecMode == AVC_DEC) {
		if (cpu_is_mx5x()) {
			temp_baseAddr = VpuReadReg(BIT_TEMP_BUF_ADDR);
			VpuWriteReg(CMD_SET_FRAME_SLICE_BB_START, temp_baseAddr + 0x18300);
		} else {
			VpuWriteReg( CMD_SET_FRAME_SLICE_BB_START, pBufInfo->avcSliceBufInfo.bufferBase);
		}
		VpuWriteReg(CMD_SET_FRAME_SLICE_BB_SIZE,
			    (pBufInfo->avcSliceBufInfo.bufferSize /
			     1024));
	}

	if (cpu_is_mx6x()) {
		/* To align with mx5x */
		if (pBufInfo->maxDecFrmInfo.maxMbNum == 0) {
			pBufInfo->maxDecFrmInfo.maxMbX = MAX_PIC_WIDTH/16;
			pBufInfo->maxDecFrmInfo.maxMbY = MAX_PIC_HEIGHT/16;
			pBufInfo->maxDecFrmInfo.maxMbNum = pBufInfo->maxDecFrmInfo.maxMbX
				* pBufInfo->maxDecFrmInfo.maxMbY;
		}
	}

	VpuWriteReg(CMD_SET_FRAME_MAX_DEC_SIZE,
			(pBufInfo->maxDecFrmInfo.maxMbNum << 16 |
			 pBufInfo->maxDecFrmInfo.maxMbX << 8 |
			 pBufInfo->maxDecFrmInfo.maxMbY));

	BitIssueCommand(pCodecInst, SET_FRAME_BUF);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;

#ifdef MEM_PROTECT
	if (cpu_is_mx6x() && VpuReadReg(RET_SET_FRAME_SUCCESS) & (1 << 31)) {
		err_msg("access violation in vpu_DecRegisterFrameBuffer\n");
		err_msg("PC: 0x%lx, ERR_CLR: 0x%lx, ERR_RSN: 0x%lx, ERR_ADR: 0x%lx\n",
				VpuReadReg(BIT_CUR_PC),
				VpuReadReg(GDI_WPROT_ERR_CLR),
				VpuReadReg(GDI_WPROT_ERR_RSN),
				VpuReadReg(GDI_WPROT_ERR_ADR));
		vpu_mx6_swreset(0);
		UnlockVpu(vpu_semap);
		return RETCODE_MEMORY_ACCESS_VIOLATION;
	}
#endif

	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Get bitstream for decoder.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 * @param bufAddr [Output] Bitstream buffer physical address.
 * @param size [Output] Bitstream size.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_INVALID_PARAM buf or size is invalid.
 */
RetCode vpu_DecGetBitstreamBuffer(DecHandle handle,
				  PhysicalAddress * paRdPtr,
				  PhysicalAddress * paWrPtr, Uint32 * size)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	PhysicalAddress rdPtr;
	PhysicalAddress wrPtr;
	int instIndex;
	Uint32 room;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	if (paRdPtr == 0 || paWrPtr == 0 || size == 0)
		return RETCODE_INVALID_PARAM;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;
	wrPtr = pDecInfo->streamWrPtr;

	LockVpuReg(vpu_semap);

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		int wroffset = 0;

		if (pDecInfo->jpgInfo.inProcess) {
			err_msg("Don't call %s in the middle of decoding!\n", __func__);
			UnlockVpuReg(vpu_semap);
			return RETCODE_WRONG_CALL_SEQUENCE;
		}

		rdPtr = pCodecInst->ctxRegs[CTX_BIT_RD_PTR];

		wroffset = wrPtr - pDecInfo->streamBufStartAddr;
		if (wroffset < pDecInfo->jpgInfo.frameOffset)
			room = pDecInfo->jpgInfo.frameOffset - wroffset - 1;
		else
			room = (pDecInfo->streamBufEndAddr - wrPtr) +
				    pDecInfo->jpgInfo.frameOffset - 1;

		UnlockVpuReg(vpu_semap);

		*paRdPtr = rdPtr;
		*paWrPtr = wrPtr;
		*size = room;
		return RETCODE_SUCCESS;
	}

	/* Check current instance is in running or not, if not
	   Get the pointer from back context regs */
	instIndex = (int)VpuReadReg(BIT_RUN_INDEX);
	rdPtr = (pCodecInst->instIndex == instIndex) ?
		    VpuReadReg(BIT_RD_PTR) :
		    pCodecInst->ctxRegs[CTX_BIT_RD_PTR];
	UnlockVpuReg(vpu_semap);

	if (wrPtr < rdPtr) {
		room = rdPtr - wrPtr - VPU_GBU_SIZE*2 - 1;
	} else {
		room = (pDecInfo->streamBufEndAddr - wrPtr) +
		    (rdPtr - pDecInfo->streamBufStartAddr) - VPU_GBU_SIZE*2 - 1;
	}

	*paRdPtr = rdPtr;
	*paWrPtr = wrPtr;
	*size = room;

	return RETCODE_SUCCESS;
}

/*!
 * @brief Update the current bit stream position.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 * @param size [Input] Size of bit stream you put.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_INVALID_PARAM Invalid input parameters.
 */
RetCode vpu_DecUpdateBitstreamBuffer(DecHandle handle, Uint32 size)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	PhysicalAddress wrPtr;
	PhysicalAddress rdPtr;
	RetCode ret;
	int room = 0, instIndex, wrOffset;
	Uint32 val = 0;

	ENTER_FUNC();
	dprintf(4, "Update bitstream buffer size %ld\n", size);

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;
	wrPtr = pDecInfo->streamWrPtr;

	LockVpuReg(vpu_semap);
	instIndex = (int)VpuReadReg(BIT_RUN_INDEX);

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		wrOffset = wrPtr - pDecInfo->streamBufStartAddr;

		if (pDecInfo->jpgInfo.inProcess) {
			err_msg("Don't call %s in the middle of decoding!\n", __func__);
			UnlockVpuReg(vpu_semap);
			return RETCODE_WRONG_CALL_SEQUENCE;
		}

		rdPtr = pCodecInst->ctxRegs[CTX_BIT_RD_PTR];
		if (size == 0) {
			val = wrOffset / 256;
			if (wrOffset % 256)
				val += 1;
			pDecInfo->jpgInfo.curPosStreamEnd = val;
			val = (1 << 31 | val);
			pDecInfo->jpgInfo.bbcStreamCtl = val;
			pDecInfo->streamEndflag = 1;
		} else {
			wrPtr += size;
			if (wrPtr > pDecInfo->streamBufEndAddr) {
				room = wrPtr - pDecInfo->streamBufEndAddr;
				wrPtr = pDecInfo->streamBufStartAddr;
				wrPtr += room;
			}

			if (wrPtr == pDecInfo->streamBufEndAddr)
				wrPtr = pDecInfo->streamBufStartAddr;

			pDecInfo->streamWrPtr = wrPtr;
			pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = wrPtr;
		}

		if (wrOffset < pDecInfo->jpgInfo.frameOffset)
			pDecInfo->jpgInfo.bbcEndAddr = pDecInfo->streamBufEndAddr;
		else if (pDecInfo->streamEndflag) {
			pDecInfo->jpgInfo.bbcEndAddr = wrPtr+256;
			pDecInfo->jpgInfo.lastRound = 1;
		}
		else
			pDecInfo->jpgInfo.bbcEndAddr = wrPtr & 0xFFFFFE00;

		UnlockVpuReg(vpu_semap);
		return RETCODE_SUCCESS;
	}

	val = pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM];
	/* Set stream end flag if size == 0; otherwise, clear the flag */
	val = (size == 0) ? (val | 1 << 2) : (val & ~(1 << 2));
	/* Backup to context reg */
	pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] = val;

	if (pCodecInst->instIndex == instIndex)
		VpuWriteReg(BIT_BIT_STREAM_PARAM, val); /* Write to vpu hardware */

	if (size == 0) {
		UnlockVpuReg(vpu_semap);
		return RETCODE_SUCCESS;
	}

	rdPtr = (pCodecInst->instIndex == instIndex) ?
		    VpuReadReg(BIT_RD_PTR) :
		    pCodecInst->ctxRegs[CTX_BIT_RD_PTR];

	if ((!cpu_is_mx6x() && pDecInfo->filePlayEnable != 1) ||
	    cpu_is_mx6x()) {
		if (wrPtr < rdPtr) {
			if (rdPtr <= wrPtr + size) {
				UnlockVpuReg(vpu_semap);
				return RETCODE_INVALID_PARAM;
			}
		}
	}

	wrPtr += size;

	if (wrPtr > pDecInfo->streamBufEndAddr) {
		room = wrPtr - pDecInfo->streamBufEndAddr;
		wrPtr = pDecInfo->streamBufStartAddr;
		wrPtr += room;
	}

	if (wrPtr == pDecInfo->streamBufEndAddr) {
		wrPtr = pDecInfo->streamBufStartAddr;
	}

	pDecInfo->streamWrPtr = wrPtr;

	if (pCodecInst->instIndex == instIndex)
		VpuWriteReg(BIT_WR_PTR, wrPtr);
	pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = wrPtr;
	UnlockVpuReg(vpu_semap);

	return RETCODE_SUCCESS;
}

/*!
 * @brief Start decoding one frame.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 * @li RETCODE_WRONG_CALL_SEQUENCE Wrong calling sequence.
 */
RetCode vpu_DecStartOneFrame(DecHandle handle, DecParam * param)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	DecParam *pDecParam;
	Uint32 rotMir, reg = 0;
	int val = 0;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;
	pDecParam = &pCodecInst->CodecParam.decParam;
	memcpy(pDecParam, param, sizeof(*pDecParam));

	/* This means frame buffers have not been registered. */
	if (!is_mx6x_mjpg_codec(pCodecInst->codecMode) && pDecInfo->frameBufPool == 0) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	rotMir = 0;
	if (pDecInfo->rotationEnable) {
		rotMir |= 0x10;	/* Enable rotator */
		switch (pDecInfo->rotationAngle) {
		case 0:
			rotMir |= 0x0;
			break;

		case 90:
			rotMir |= 0x1;
			break;

		case 180:
			rotMir |= 0x2;
			break;

		case 270:
			rotMir |= 0x3;
			break;
		}
	}

	if (pDecInfo->mirrorEnable) {
		rotMir |= 0x10;	/* Enable mirror */
		switch (pDecInfo->mirrorDirection) {
		case MIRDIR_NONE:
			rotMir |= 0x0;
			break;

		case MIRDIR_VER:
			rotMir |= 0x4;
			break;

		case MIRDIR_HOR:
			rotMir |= 0x8;
			break;

		case MIRDIR_HOR_VER:
			rotMir |= 0xc;
			break;

		}
	}

	log_time(pCodecInst->instIndex, START_TRY_LOCK);
	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	log_time(pCodecInst->instIndex, START_GET_LOCK);
	/* Set GDI related registers per tiled map info for mx6 */
	if (cpu_is_mx6x())
		SetGDIRegs(&pDecInfo->sTiledInfo);

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		pDecInfo->jpgInfo.iHorScaleMode = param->mjpegScaleDownRatioWidth;
		pDecInfo->jpgInfo.iVerScaleMode = param->mjpegScaleDownRatioHeight;
		if (pDecInfo->jpgInfo.lineBufferMode) {
			if (param->chunkSize <= 0) {
				UnlockVpu(vpu_semap);
				return RETCODE_INVALID_PARAM;
			}

			pDecInfo->jpgInfo.pVirtJpgChunkBase = param->virtJpgChunkBase;
			pDecInfo->jpgInfo.chunkSize = param->chunkSize;
			val = JpegDecodeHeader(pDecInfo);
			if (val == 0) {
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			} else if ((val == -1) || (val == -3)) {
				UnlockVpu(vpu_semap);
				return RETCODE_JPEG_BIT_EMPTY;
			}

			pDecInfo->streamBufStartAddr = param->phyJpgChunkBase;
			VpuWriteReg(MJPEG_BBC_WR_PTR_REG, pDecInfo->streamBufStartAddr + param->chunkSize);
			VpuWriteReg(MJPEG_BBC_BAS_ADDR_REG, pDecInfo->streamBufStartAddr);
			// never issue BBC interrupt in line buffer mode
			VpuWriteReg(MJPEG_BBC_END_ADDR_REG, pDecInfo->streamBufStartAddr + param->chunkSize+256*3+256);

			val = (param->chunkSize) / 256;
			if ((param->chunkSize) % 256)
				val = val + 1;
			// reserve 256*3B margin for error clip stop condition
			val += 3;
			VpuWriteReg(MJPEG_BBC_STRM_CTRL_REG, (1 << 31 | val));
		} else {
			if (pDecInfo->jpgInfo.frameOffset < 0) {
				UnlockVpu(vpu_semap);
				return RETCODE_JPEG_EOS;
			}

			val = JpegDecodeHeader(pDecInfo);
			if (val == 0) {
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			} else if (val == -3) {
				UnlockVpu(vpu_semap);
				return RETCODE_JPEG_BIT_EMPTY;
			} else if (val == -2) { /* wrap around in header case */
				pDecInfo->jpgInfo.frameOffset = 0;
				pDecInfo->jpgInfo.ecsPtr = 0;
				val = JpegDecodeHeader(pDecInfo);
				if (val == 0) {
					UnlockVpu(vpu_semap);
					return RETCODE_FAILURE;
				} else if (val == -3) {
					UnlockVpu(vpu_semap);
					return RETCODE_JPEG_BIT_EMPTY;
				} else if (val == -1) {
					UnlockVpu(vpu_semap);
					if (pDecInfo->streamEndflag == 1) {
						pDecInfo->jpgInfo.frameOffset = -1;
						return RETCODE_JPEG_EOS;
					}
					return RETCODE_JPEG_BIT_EMPTY;
				}
			} else if (val == -1) { /* stream empty case */
				UnlockVpu(vpu_semap);
				if (pDecInfo->streamEndflag == 1) {
					pDecInfo->jpgInfo.frameOffset = -1;
					return RETCODE_JPEG_EOS;
				}
				return RETCODE_JPEG_BIT_EMPTY;
			}

			VpuWriteReg(MJPEG_BBC_BAS_ADDR_REG, pDecInfo->streamBufStartAddr);
			VpuWriteReg(MJPEG_BBC_STRM_CTRL_REG, pDecInfo->jpgInfo.bbcStreamCtl);
			VpuWriteReg(MJPEG_BBC_WR_PTR_REG, pDecInfo->streamWrPtr);
			VpuWriteReg(MJPEG_BBC_END_ADDR_REG, pDecInfo->jpgInfo.bbcEndAddr);
		}

		VpuWriteReg(MJPEG_GBU_TT_CNT_REG, 0);
		VpuWriteReg(MJPEG_GBU_TT_CNT_REG + 4, 0);
		VpuWriteReg(MJPEG_PIC_CTRL_REG, pDecInfo->jpgInfo.huffAcIdx << 10 |
						pDecInfo->jpgInfo.huffDcIdx << 7 |
						pDecInfo->jpgInfo.userHuffTab << 6);
		VpuWriteReg(MJPEG_PIC_SIZE_REG, pDecInfo->jpgInfo.alignedWidth << 16 |
						pDecInfo->jpgInfo.alignedHeight);

		VpuWriteReg(MJPEG_ROT_INFO_REG, 0);
		VpuWriteReg(MJPEG_OP_INFO_REG, pDecInfo->jpgInfo.busReqNum);
		VpuWriteReg(MJPEG_MCU_INFO_REG, pDecInfo->jpgInfo.mcuBlockNum << 16 |
						pDecInfo->jpgInfo.compNum << 12 |
						pDecInfo->jpgInfo.compInfo[0] << 8 |
						pDecInfo->jpgInfo.compInfo[1] << 4 |
						pDecInfo->jpgInfo.compInfo[2]);
		if (pDecInfo->jpgInfo.iHorScaleMode | pDecInfo->jpgInfo.iVerScaleMode)
			reg = ((pDecInfo->jpgInfo.iHorScaleMode & 0x3) << 2) |
				((pDecInfo->jpgInfo.iVerScaleMode & 0x3)) | 0x10 ;
		else
			reg = 0;
		VpuWriteReg(MJPEG_SCL_INFO_REG, reg);
		VpuWriteReg(MJPEG_DPB_CONFIG_REG,
			    pDecInfo->openParam.chromaInterleave);
		VpuWriteReg(MJPEG_RST_INTVAL_REG, pDecInfo->jpgInfo.rstIntval);

		if (pDecInfo->jpgInfo.userHuffTab) {
			if (!JpgDecHuffTabSetUp(pDecInfo)) {
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			}
		}

		if (!JpgDecQMatTabSetUp(pDecInfo)) {
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}

		JpgDecGramSetup(pDecInfo);

		VpuWriteReg(MJPEG_RST_INDEX_REG, 0);
		VpuWriteReg(MJPEG_RST_COUNT_REG, 0);

		VpuWriteReg(MJPEG_DPCM_DIFF_Y_REG, 0);
		VpuWriteReg(MJPEG_DPCM_DIFF_CB_REG, 0);
		VpuWriteReg(MJPEG_DPCM_DIFF_CR_REG, 0);

		VpuWriteReg(MJPEG_GBU_FF_RPTR_REG, pDecInfo->jpgInfo.bitPtr);
		VpuWriteReg(MJPEG_GBU_CTRL_REG, 3);

		VpuWriteReg(MJPEG_ROT_INFO_REG, rotMir);

		if (rotMir & 1) {
		        pDecInfo->jpgInfo.format = (pDecInfo->jpgInfo.format==FORMAT_422) ?
						    FORMAT_224 :
						    (pDecInfo->jpgInfo.format==FORMAT_224) ?
						    FORMAT_422 : pDecInfo->jpgInfo.format;
		}

		val = 0;
		VpuWriteReg(GDI_CONTROL, 1);
		while (!val)
			val = (int)VpuReadReg(GDI_STATUS);

		if (pDecInfo->mapType)
			val = 3 << 20;
		else
			val = 0;
		VpuWriteReg(GDI_INFO_CONTROL, ((pDecInfo->jpgInfo.format & 0x07) << 17) |
					       (pDecInfo->openParam.chromaInterleave << 16) |
					       val | pDecInfo->rotatorStride);
		VpuWriteReg(GDI_INFO_PIC_SIZE, (pDecInfo->jpgInfo.alignedWidth << 16) |
						pDecInfo->jpgInfo.alignedHeight);
		VpuWriteReg(GDI_INFO_BASE_Y,  pDecInfo->rotatorOutput.bufY);
		VpuWriteReg(GDI_INFO_BASE_CB,  pDecInfo->rotatorOutput.bufCb);
		VpuWriteReg(GDI_INFO_BASE_CR,  pDecInfo->rotatorOutput.bufCr);
		VpuWriteReg(MJPEG_DPB_BASE00_REG, 0);

		VpuWriteReg(GDI_CONTROL, 0);
		VpuWriteReg(GDI_PIC_INIT_HOST, 1);
		dump_regs(NPT_BASE, 256);
		VpuWriteReg(MJPEG_PIC_START_REG, 1);

		*ppendingInst = pCodecInst;
		pDecInfo->jpgInfo.inProcess = 1;
		return RETCODE_SUCCESS;
	}

	if (cpu_is_mx6x() && pDecInfo->tiledLinearEnable) {
		rotMir |= 0x10;
	}

	if (!cpu_is_mx27() && pDecInfo->deringEnable) {
		rotMir |= 0x20;	/* Enable Dering Filter */
	}

	if ((rotMir & 0x30) ||  /* rotator or dering enabled */
	    (!cpu_is_mx6x() && pCodecInst->codecMode == MJPG_DEC)) {
		if (cpu_is_mx6x())
			VpuWriteReg(CMD_DEC_PIC_ROT_INDEX,
					pDecInfo->rotatorOutput.myIndex);

		VpuWriteReg(CMD_DEC_PIC_ROT_ADDR_Y,
			    pDecInfo->rotatorOutput.bufY);
		VpuWriteReg(CMD_DEC_PIC_ROT_ADDR_CB,
			    pDecInfo->rotatorOutput.bufCb);
		VpuWriteReg(CMD_DEC_PIC_ROT_ADDR_CR,
			    pDecInfo->rotatorOutput.bufCr);
		VpuWriteReg(CMD_DEC_PIC_ROT_STRIDE, pDecInfo->rotatorStride);
	}

	VpuWriteReg(CMD_DEC_PIC_ROT_MODE, rotMir);

	/* Not support decoder param info report for mx6 vpu */
	if (cpu_is_mx6x()) {
		pDecInfo->decReportMBInfo.enable = 0;
		pDecInfo->decReportMVInfo.enable = 0;
		pDecInfo->decReportFrameBufStat.enable = 0;
	}

	if (pDecInfo->decReportMBInfo.enable || pDecInfo->decReportMVInfo.enable ||
	    pDecInfo->decReportFrameBufStat.enable) {
		if (!pDecInfo->picParaBaseMem.phy_addr) {
			pDecInfo->picParaBaseMem.size = DEC_ADDR_END_OF_RPT_BUF;
			ret = IOGetPhyMem(&pDecInfo->picParaBaseMem);
			if (ret) {
				err_msg("Unable to obtain physical mem\n");
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			}
			if (IOGetVirtMem(&pDecInfo->picParaBaseMem) == -1) {
				IOFreePhyMem(&pDecInfo->picParaBaseMem);
				pDecInfo->picParaBaseMem.phy_addr = 0;
				err_msg("Unable to obtain virtual mem\n");
				UnlockVpu(vpu_semap);
				return RETCODE_FAILURE;
			}
		}

		VpuWriteReg(CMD_DEC_PIC_PARA_BASE_ADDR, pDecInfo->picParaBaseMem.phy_addr);

		if (!cpu_is_mx27()) {
			Uint32 *virt_addr, phy_addr;

			virt_addr = (Uint32 *)pDecInfo->picParaBaseMem.virt_uaddr;
			phy_addr = pDecInfo->picParaBaseMem.phy_addr;
			/* Set frameStat buffer address */
			if (pDecInfo->decReportFrameBufStat.enable) {
				*virt_addr = phy_addr + ADDR_FRAME_BUF_STAT_BASE_OFFSET;
			}
			/* Set mbParam buffer address */
			if (pDecInfo->decReportMBInfo.enable) {
				*(virt_addr + 2) = phy_addr + ADDR_MB_BASE_OFFSET;
			}
			/* Set mvParam buffer address */
			if (pDecInfo->decReportMVInfo.enable) {
				*(virt_addr + 4) = phy_addr + ADDR_MV_BASE_OFFSET;
			}
		}
	}

	if (pDecInfo->decReportUserData.enable &&
	    !pDecInfo->userDataBufMem.phy_addr) {
		pDecInfo->userDataBufMem.size = pDecInfo->decReportUserData.size;
		ret = IOGetPhyMem(&pDecInfo->userDataBufMem);
		if (ret) {
			err_msg("Unable to obtain physical mem\n");
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}
		if (IOGetVirtMem(&pDecInfo->userDataBufMem) == -1) {
			IOFreePhyMem(&pDecInfo->userDataBufMem);
			pDecInfo->userDataBufMem.phy_addr = 0;
			err_msg("Unable to obtain virtual mem\n");
			UnlockVpu(vpu_semap);
			return RETCODE_FAILURE;
		}

		VpuWriteReg(CMD_DEC_PIC_USER_DATA_BASE_ADDR, pDecInfo->userDataBufMem.phy_addr);
		VpuWriteReg(CMD_DEC_PIC_USER_DATA_BUF_SIZE, pDecInfo->decReportUserData.size);
	} else if (pDecInfo->decReportUserData.enable && pDecInfo->userDataBufMem.phy_addr) {
		VpuWriteReg(CMD_DEC_PIC_USER_DATA_BASE_ADDR, pDecInfo->userDataBufMem.phy_addr);
		VpuWriteReg(CMD_DEC_PIC_USER_DATA_BUF_SIZE, pDecInfo->decReportUserData.size);
	}

	if (!cpu_is_mx27()) {
		reg |= (1 << 10); /* hardcode to use interrupt disable mode  */
		if (!cpu_is_mx6x()) {
			reg |= (pDecInfo->decReportFrameBufStat.enable << 8);
			reg |= (pDecInfo->decReportMBInfo.enable << 7);
			reg |= (pDecInfo->decReportMVInfo.enable << 6);
		}
		/* if iframeSearch is Enable, other bit is ignored. */
		if (param->iframeSearchEnable == 1) {
			reg |= ((param->iframeSearchEnable & 0x1) << 2);
			pDecInfo->vc1BframeDisplayValid = 0;
		} else {
			if (param->skipframeMode)
				reg |= (param->skipframeMode << 3);
			else
				reg |= (pDecInfo->decReportUserData.enable << 5);
			if (!cpu_is_mx6x()) {
				reg |= (param->prescanMode << 1);
				reg |= (param->prescanEnable);
			}
		}
	} else {
		if (param->iframeSearchEnable == 1) {
			reg = (param->iframeSearchEnable << 2) & 0x4;
		} else {
			reg = (param->skipframeMode << 3) |
		    	      (param->iframeSearchEnable << 2) |
		    	      (param->prescanMode << 1) | param->prescanEnable;
		}
	}
	VpuWriteReg(CMD_DEC_PIC_OPTION, reg);

	if (!cpu_is_mx27())
		VpuWriteReg(CMD_DEC_PIC_SKIP_NUM, param->skipframeNum);

	if (cpu_is_mx27()) {
		/* clear dispReorderBuf flag firstly */
		reg = VpuReadReg(CMD_DEC_DISPLAY_REORDER) & 0xFFFFFFFD;
		reg |= (param->dispReorderBuf & 0x1) << 1;
		if (((pCodecInst->codecMode == AVC_DEC) && (pDecInfo->openParam.reorderEnable == 1)) ||
		    (pCodecInst->codecMode == VC1_DEC) ||
		    (pCodecInst->codecMode == MP2_DEC) ||
		    (pCodecInst->codecMode == MP4_DEC) ||
		    (pCodecInst->codecMode == RV_DEC)) {
			if (pDecInfo->filePlayEnable == 1)
				VpuWriteReg(CMD_DEC_DISPLAY_REORDER, reg);
		}
	}

	if (!cpu_is_mx6x() && pDecInfo->filePlayEnable == 1) {
		VpuWriteReg(CMD_DEC_PIC_CHUNK_SIZE, param->chunkSize);
		if (pDecInfo->dynamicAllocEnable == 1) {
			VpuWriteReg(CMD_DEC_PIC_BB_START,
				    param->picStreamBufferAddr);
		}

		VpuWriteReg(CMD_DEC_PIC_START_BYTE, param->picStartByteOffset);
	}

	if (cpu_is_mx6x()) {
		reg = (pDecInfo->secAxiUse.useBitEnable |
		       pDecInfo->secAxiUse.useIpEnable << 1 |
		       pDecInfo->secAxiUse.useDbkEnable << 2 |
		       pDecInfo->secAxiUse.useDbkEnable << 3 |
		       pDecInfo->secAxiUse.useOvlEnable << 4 |
		       pDecInfo->secAxiUse.useBtpEnable << 5 |
		       pDecInfo->secAxiUse.useHostBitEnable << 8 |
		       pDecInfo->secAxiUse.useHostIpEnable << 9 |
		       pDecInfo->secAxiUse.useHostDbkEnable << 10 |
		       pDecInfo->secAxiUse.useHostDbkEnable << 11 |
		       pDecInfo->secAxiUse.useHostOvlEnable << 12 |
		       pDecInfo->secAxiUse.useHostBtpEnable << 13 );
	} else {
		reg = (pDecInfo->secAxiUse.useBitEnable |
		       pDecInfo->secAxiUse.useIpEnable << 1 |
		       pDecInfo->secAxiUse.useDbkEnable << 2 |
		       pDecInfo->secAxiUse.useOvlEnable << 3 |
		       pDecInfo->secAxiUse.useHostBitEnable << 7 |
		       pDecInfo->secAxiUse.useHostIpEnable << 8 |
		       pDecInfo->secAxiUse.useHostDbkEnable << 9 |
		       pDecInfo->secAxiUse.useHostOvlEnable << 10);
	}
	VpuWriteReg(BIT_AXI_SRAM_USE, reg);

	BitIssueCommand(pCodecInst, PIC_RUN);

	*ppendingInst = pCodecInst;
	return RETCODE_SUCCESS;
}

/*!
 * @brief Get the information of output of decoding.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 * @param info [Output] Pointer to DecOutputInfo data structure.
 *
 * @return
 * @li RETCODE_SUCCESS Successful operation.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_WRONG_CALL_SEQUENCE Wrong calling sequence.
 * @li RETCODE_INVALID_PARAM Info is an invalid pointer.
 */
RetCode vpu_DecGetOutputInfo(DecHandle handle, DecOutputInfo * info)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	RetCode ret;
	Uint32 val = 0;
	Uint32 val2 = 0;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS) {
		err_msg("CheckInst, ret=%d\n", ret);
		return ret;
	}

	if (info == 0) {
		return RETCODE_INVALID_PARAM;
	}

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	if (*ppendingInst == 0) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	if (pCodecInst != *ppendingInst) {
		err_msg("pCodecInst 0x%p, pendingInst 0x%p\n", pCodecInst, *ppendingInst);
		return RETCODE_INVALID_HANDLE;
	}

	memset(info, 0, sizeof(DecOutputInfo));

	if (is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		if (pDecInfo->jpgInfo.frameOffset < 0 ||
		    pDecInfo->jpgInfo.quitCodec) {
			info->indexFrameDisplay = -1;
			info->decodingSuccess = 1;
			*ppendingInst = 0;
			pDecInfo->jpgInfo.inProcess = 0;
			UnlockVpu(vpu_semap);
			log_time(pCodecInst->instIndex, OUT_UNLOCK);
			return RETCODE_SUCCESS;
		}

		if (pDecInfo->jpgInfo.rollBack) {
                        info->decodingSuccess = 0x10 | 0x01;
			info->indexFrameDisplay = -1;
			pDecInfo->jpgInfo.rollBack = 0;
			*ppendingInst = 0;
			pDecInfo->jpgInfo.inProcess = 0;
			UnlockVpu(vpu_semap);
			log_time(pCodecInst->instIndex, OUT_UNLOCK);
			return RETCODE_SUCCESS;
		}

		info->decPicWidth = pDecInfo->jpgInfo.picWidth >> pDecInfo->jpgInfo.iHorScaleMode;
		info->decPicHeight = pDecInfo->jpgInfo.picHeight >> pDecInfo->jpgInfo.iVerScaleMode;
		info->indexFrameDecoded = 0;
		info->indexFrameDisplay = 0;
		info->consumedByte = VpuReadReg(MJPEG_GBU_TT_CNT_REG) / 8;

		if (pDecInfo->jpgInfo.lineBufferMode)
			pDecInfo->jpgInfo.frameOffset = 0;
		pDecInfo->jpgInfo.ecsPtr = 0;
		pDecInfo->jpgInfo.consumeByte = info->consumedByte;
		pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = VpuReadReg(MJPEG_BBC_RD_PTR_REG);

		val = VpuReadReg(MJPEG_PIC_STATUS_REG);
		if (val & (1 << INT_JPU_DONE))
			info->decodingSuccess = 1;
		else {
			info->numOfErrMBs = VpuReadReg(MJPEG_PIC_ERRMB_REG);
			info->decodingSuccess = 0;
		}

		if (val != 0)
			VpuWriteReg(MJPEG_PIC_STATUS_REG, val);

		/* Workaround to reset JPU after each decoder: encoder may be blocked
		 * after decoder randomly if not do reset. Fixme later */
		vpu_mx6_hwreset();

		*ppendingInst = 0;
		pDecInfo->jpgInfo.inProcess = 0;
		UnlockVpu(vpu_semap);
		log_time(pCodecInst->instIndex, OUT_UNLOCK);
		return RETCODE_SUCCESS;
	}

	if (VpuReadReg(BIT_BUSY_FLAG))
		err_msg("fatal: VPU is busy in %s\n", __func__);

	val = VpuReadReg(RET_DEC_PIC_SUCCESS);
	info->decodingSuccess = (val & 0x01);

	if (cpu_is_mx6x()) {
#ifdef MEM_PROTECT
		if (val & (1 << 31)) {
			*ppendingInst = 0;
			err_msg("access violation in vpu_DecGetOutputInfo\n");
			err_msg("PC: 0x%lx, ERR_CLR: 0x%lx, ERR_RSN: 0x%lx, ERR_ADR: 0x%lx\n",
					VpuReadReg(BIT_CUR_PC),
					VpuReadReg(GDI_WPROT_ERR_CLR),
					VpuReadReg(GDI_WPROT_ERR_RSN),
					VpuReadReg(GDI_WPROT_ERR_ADR));
			vpu_mx6_swreset(0);
			UnlockVpu(vpu_semap);
			return RETCODE_MEMORY_ACCESS_VIOLATION;
		}
#endif
		if (pDecInfo->openParam.bitstreamMode && (val & (1 << 4))) {
			info->decodingSuccess |= 0x10;
			VpuWriteReg(BIT_RUN_INDEX, pCodecInst->instIndex);
		}

		info->decodingSuccess |= val & (1 << 20);
	}

	if (pCodecInst->codecMode == AVC_DEC) {
		info->notSufficientPsBuffer = (val >> 3) & 0x1;
		info->notSufficientSliceBuffer = (val >> 2) & 0x1;
	} else if (pCodecInst->codecMode == MP4_DEC) {
		info->mp4PackedPBframe = ((val >> 16) & 0x01);
		/* Need to backup WR_PTR for mp4PackedPBframe */
		if (info->mp4PackedPBframe)
			pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = VpuReadReg(BIT_WR_PTR);
	}

	val = VpuReadReg(RET_DEC_PIC_SIZE);     /* decoding picture size */
	info->decPicHeight = val & 0xFFFF;
	info->decPicWidth = (val >> 16) & 0xFFFF;

	if (cpu_is_mx6x()) {
		if(pCodecInst->codecMode == VC1_DEC
			|| pCodecInst->codecMode == AVS_DEC
			|| pCodecInst->codecMode == MP4_DEC) {
			info->frameStartPos = VpuReadReg(BIT_BYTE_POS_FRAME_START);
			info->frameEndPos = VpuReadReg(BIT_BYTE_POS_FRAME_END);
		} else {
			info->frameStartPos = pCodecInst->ctxRegs[CTX_BIT_RD_PTR];
			info->frameEndPos = VpuReadReg(BIT_RD_PTR);
		}
		if (info->frameEndPos < info->frameStartPos) {
			info->consumedByte =
				pDecInfo->streamBufEndAddr - info->frameStartPos;
			info->consumedByte +=
				info->frameEndPos - pDecInfo->streamBufStartAddr;
		} else
			info->consumedByte = info->frameEndPos - info->frameStartPos;
	}

	if (cpu_is_mx6x() && pCodecInst->codecMode == VC1_DEC ) {
		val = VpuReadReg(RET_DEC_PIC_POST);
		info->hScaleFlag = val >> 1 & 1 ;
		info->vScaleFlag = val >> 2 & 1 ;

		if (info->hScaleFlag)
			info->decPicWidth = pDecInfo->initialInfo.picWidth/2;
		if (info->vScaleFlag)
			info->decPicHeight = pDecInfo->initialInfo.picHeight/2;
	}

	if (pCodecInst->codecMode == VPX_DEC &&
	    pCodecInst->codecModeAux == VPX_AUX_VP8) {
		/* VP8 specific header information */
		/* h_scale[31:30] v_scale[29:28] pic_width[27:14] pic_height[13:0] */
		val = VpuReadReg(RET_DEC_PIC_VP8_SCALE_INFO);
		info->vp8ScaleInfo.hScaleFactor = (val >> 30) & 0x03;
		info->vp8ScaleInfo.vScaleFactor = (val >> 28) & 0x03;
		info->vp8ScaleInfo.picWidth = (val >> 14) & 0x3FFF;
		info->vp8ScaleInfo.picHeight = (val >> 0) & 0x3FFF;
		/* ref_idx_gold[31:24], ref_idx_altr[23:16], ref_idx_last[15: 8], */
		/* version_number[3:1], show_frame[0] */
		val = VpuReadReg(RET_DEC_PIC_VP8_PIC_REPORT);
		info->vp8PicInfo.refIdxGold = (val >> 24) & 0x0FF;
		info->vp8PicInfo.refIdxAltr = (val >> 16) & 0x0FF;
		info->vp8PicInfo.refIdxLast = (val >> 8) & 0x0FF;
		info->vp8PicInfo.versionNumber = (val >> 1) & 0x07;
		info->vp8PicInfo.showFrame = (val >> 0) & 0x01;
	}

	/* frame crop information */
	if (pCodecInst->codecMode == AVC_DEC) {
		val = VpuReadReg(RET_DEC_PIC_CROP_LEFT_RIGHT);
		val2 = VpuReadReg(RET_DEC_PIC_CROP_TOP_BOTTOM);
		if (val == 0xFFFFFFFF && val2 == 0xFFFFFFFF) {
			/* Keep current crop information */
		} else if (val == 0 && val2 == 0) {
			info->decPicCrop.left = 0;
			info->decPicCrop.right = 0;
			info->decPicCrop.top = 0;
			info->decPicCrop.bottom = 0;
		} else {
			info->decPicCrop.left =
			    ((val >> 16) & 0xFFFF);
			info->decPicCrop.right =
			    info->decPicWidth - ((val & 0xFFFF));
			info->decPicCrop.top =
			    ((val2 >> 16) & 0xFFFF);
			info->decPicCrop.bottom =
			    info->decPicHeight - ((val2 & 0xFFFF));
		}
	} else {
		info->decPicCrop.left = 0;
		info->decPicCrop.right = 0;
		info->decPicCrop.top = 0;
		info->decPicCrop.bottom = 0;
	}

	val = VpuReadReg(RET_DEC_PIC_TYPE);

	if (pCodecInst->codecMode == VC1_DEC &&
	    pDecInfo->initialInfo.profile == 2) /* VC1 AP propile */
		info->picType = val & 0x3f;
	else
		info->picType = val & 0x7;
	if (cpu_is_mx6x()) {
		info->picTypeFirst = (val & 0x38) >> 3;
		info->idrFlg = (val & 0xC0) >> 6;
	}
	info->interlacedFrame = (val >> 16) & 0x1;

	if (!cpu_is_mx27()) {
		info->h264Npf = (val >> 16) & 0x3;
		info->interlacedFrame = (val >> 18) & 0x1;
		info->pictureStructure = (val >> 19) & 0x0003;	/* MbAffFlag[17], FieldPicFlag[16] */
		info->topFieldFirst = (val >> 21) & 0x0001;	/* TopFieldFirst[18] */
		info->repeatFirstField = (val >> 22) & 0x0001;
		if (pCodecInst->codecMode == VC1_DEC)
			info->vc1_repeatFrame = (val >> 23) & 0x0003;
		else
			info->progressiveFrame = (val >> 23) & 0x0003;
		info->fieldSequence = (val >> 25) & 0x0007;
	}

	if (cpu_is_mx6x() && (pCodecInst->codecMode == AVC_DEC)) {
		val = VpuReadReg(RET_DEC_PIC_VUI_INFO);
		info->avcVuiInfo.fixedFrameRateFlag    = val &1;
		info->avcVuiInfo.timingInfoPresent     = (val>>1) & 0x01;
		info->avcVuiInfo.chromaLocBotField     = (val>>2) & 0x07;
		info->avcVuiInfo.chromaLocTopField     = (val>>5) & 0x07;
		info->avcVuiInfo.chromaLocInfoPresent  = (val>>8) & 0x01;
		info->avcVuiInfo.colorPrimaries        = (val>>16) & 0xff;
		info->avcVuiInfo.colorDescPresent      = (val>>24) & 0x01;
		info->avcVuiInfo.isExtSAR              = (val>>25) & 0x01;
		info->avcVuiInfo.vidFullRange          = (val>>26) & 0x01;
		info->avcVuiInfo.vidFormat             = (val>>27) & 0x07;
		info->avcVuiInfo.vidSigTypePresent     = (val>>30) & 0x01;
		info->avcVuiInfo.vuiParamPresent       = (val>>31) & 0x01;

		val = VpuReadReg(RET_DEC_PIC_VUI_PIC_STRUCT);
		info->avcVuiInfo.vuiPicStructPresent = (val & 0x1);
		info->avcVuiInfo.vuiPicStruct = (val>>1);
	}

	if (cpu_is_mx6x()) {
		info->frameRateRes = VpuReadReg(RET_DEC_PIC_FRATE_NR);
		info->frameRateDiv = VpuReadReg(RET_DEC_PIC_FRATE_DR);
		if (pCodecInst->codecMode == AVC_DEC && info->frameRateDiv)
			info->frameRateDiv *= 2;
		if (pCodecInst->codecMode == VPX_DEC)
			info->aspectRateInfo = 0;
		else
			info->aspectRateInfo = VpuReadReg(RET_DEC_PIC_ASPECT);
	}

	/* Not support framebuffer, MB, MV report on mx6 vpu */
	if (pDecInfo->decReportFrameBufStat.enable) {
		int size = 0, paraInfo = 0;
		Uint32 tempBuf[2], virt_addr;

		virt_addr = pDecInfo->picParaBaseMem.virt_uaddr;
		memcpy((char *)tempBuf, (void *)virt_addr, 8);
		val = *(tempBuf + 1);

		paraInfo = (val >> 24) & 0xFF;
		size = (val >>  0) & 0xFFFFFF;

		info->frameBufStat.enable = 1;
		if (paraInfo == PARA_TYPE_FRM_BUF_STATUS) {
			info->frameBufStat.size = size;
			info->frameBufStat.addr = pDecInfo->decReportFrameBufStat.addr;
			size = (size + 7) / 8 * 8;
			if (info->frameBufStat.size && info->frameBufStat.addr) {
				Uint8 *dst_addr, *src_addr;
				dst_addr = (Uint8 *)info->frameBufStat.addr;
				src_addr = (Uint8 *)(virt_addr +
					 ADDR_FRAME_BUF_STAT_BASE_OFFSET);
				CopyBufferData(dst_addr, src_addr, size);
			}
		}
	}

	/* Mb Param */
	if (pDecInfo->decReportMBInfo.enable) {
		int size = 0, paraInfo = 0;
		Uint32 tempBuf[2], virt_addr;

		virt_addr = pDecInfo->picParaBaseMem.virt_uaddr;

		memcpy((char *)tempBuf, (void *)(virt_addr + 8), 8);
		val = *(tempBuf + 1);

		paraInfo = (val >> 24) & 0xFF;
		size = (val >>  0) & 0x00FFFF;

		info->mbInfo.enable = 1;
		if (paraInfo == PARA_TYPE_MB_PARA) {
			info->mbInfo.size = size;
			info->mbInfo.addr = pDecInfo->decReportMBInfo.addr;
			size = (size + 7) / 8 * 8;
			if (info->mbInfo.size && info->mbInfo.addr) {
				Uint8 *dst_addr, *src_addr;
				dst_addr = (Uint8 *)info->mbInfo.addr;
				src_addr = (Uint8 *)(virt_addr +
						ADDR_MB_BASE_OFFSET);
				CopyBufferData(dst_addr, src_addr, size);
			}
		} else {
			/* VPU does not write data */
			info->mbInfo.size = 0;
			info->mbInfo.addr = 0;
		}

	}

	/* Motion Vector */
	if (pDecInfo->decReportMVInfo.enable) {
		int size = 0, paraInfo = 0, mvNumPerMb = 0;
		Uint32 tempBuf[2], virt_addr;

		virt_addr = pDecInfo->picParaBaseMem.virt_uaddr;
		memcpy((char *)tempBuf, (void *)(virt_addr + 16), 8);
		val = *(tempBuf + 1);

		paraInfo	= (val >> 24) & 0xFF;
		mvNumPerMb	= (val >> 16) & 0xFF;
		size		= (val >>  0) & 0xFFFF;
		info->mvInfo.enable = 1;
		if (paraInfo == PARA_TYPE_MV) {

			info->mvInfo.size = size;
			info->mvInfo.mvNumPerMb = mvNumPerMb;
			info->mvInfo.addr = pDecInfo->decReportMVInfo.addr;
			if (info->mvInfo.size && info->mvInfo.addr) {
				Uint8 *dst_addr, *src_addr;
				dst_addr = (Uint8 *)info->mvInfo.addr;
				src_addr = (Uint8 *)(virt_addr +
						ADDR_MV_BASE_OFFSET);
				size = (size + 7) / 8 * 8 * mvNumPerMb * 4;
				CopyBufferData(dst_addr, src_addr, size);
			}

		} else {
			/* VPU does not write data */
			info->mvInfo.mvNumPerMb = 0;
			info->mvInfo.addr = 0;
		}
	}

	/* User Data */
	if (pDecInfo->decReportUserData.enable) {
		int userDataNum = 0, userDataSize = 0;
		Uint32 tempBuf[2], virt_addr;

		virt_addr = pDecInfo->userDataBufMem.virt_uaddr;

		memcpy((char *)tempBuf, (void *)virt_addr, 8);

		val = *(tempBuf + 1);
		userDataNum = (val >> 16) & 0xFFFF;
		userDataSize = (val >> 0) & 0xFFFF;
		if (userDataNum == 0)
			userDataSize = 0;

		info->userData.userDataNum = userDataNum;
		info->userData.size = userDataSize;

		val = *tempBuf;
		if (userDataNum == 0)
			info->userData.userDataBufFull = 0;
		else
			info->userData.userDataBufFull = (val >> 16) & 0xFFFF;

		info->userData.enable = 1;
		if (userDataSize && pDecInfo->decReportUserData.addr) {
			int size = (userDataSize + 7) / 8 * 8 + USER_DATA_INFO_OFFSET;
			Uint8 *dst_addr, *src_addr;
			dst_addr = (Uint8 *)pDecInfo->decReportUserData.addr;
			src_addr = (Uint8 *)virt_addr;
			CopyBufferData(dst_addr, src_addr, size);
		}
	}

	info->numOfErrMBs = VpuReadReg(RET_DEC_PIC_ERR_MB);
	if (!cpu_is_mx6x())
		info->prescanresult = VpuReadReg(RET_DEC_PIC_OPTION);

	info->indexFrameDisplay = VpuReadReg(RET_DEC_PIC_FRAME_IDX);
	info->indexFrameDecoded = VpuReadReg(RET_DEC_PIC_CUR_IDX);
	if (!cpu_is_mx6x())
		info->NumDecFrameBuf = VpuReadReg(RET_DEC_PIC_FRAME_NEED);

	/* save decoded picType to this array */
	if (info->indexFrameDecoded >= 0)
		pDecInfo->decoded_pictype[info->indexFrameDecoded] = info->picType;

	if (pCodecInst->codecMode == VC1_DEC && info->indexFrameDisplay != -3) {
		if (pDecInfo->vc1BframeDisplayValid == 0) {
			/* Check the pictype of displayed frame */
			if ((pDecInfo->decoded_pictype[info->indexFrameDisplay] == 3
				&& pDecInfo->initialInfo.profile != 2)
				|| ((pDecInfo->decoded_pictype[info->indexFrameDisplay] >> 3) == 3
				&& pDecInfo->initialInfo.profile == 2)) {
				/* clear buffer for not displayed B frame */
				val = ~(1 << info->indexFrameDisplay);
				val &= VpuReadReg(BIT_FRM_DIS_FLG);
				VpuWriteReg(BIT_FRM_DIS_FLG, val);
				info->indexFrameDisplay = -3;
			} else {
				pDecInfo->vc1BframeDisplayValid = 1;
			}
		}
	}

	if (pCodecInst->codecMode == AVC_DEC &&
	    pCodecInst->codecModeAux == AVC_AUX_MVC) {
		val = VpuReadReg(RET_DEC_PIC_MVC_REPORT);
		info->mvcPicInfo.viewIdxDisplay = val & 1;
		info->mvcPicInfo.viewIdxDecoded = (val >> 1) & 1;
	}

	if (cpu_is_mx6x() && (pCodecInst->codecMode == AVC_DEC)) {
		val = VpuReadReg(RET_DEC_PIC_AVC_FPA_SEI0);

		if ((int)val < 0)
			info->avcFpaSei.exist = 0;
		else {
			info->avcFpaSei.exist = 1;
			info->avcFpaSei.frame_packing_arrangement_id = val & 0x7FFFFFFF;

			val = VpuReadReg(RET_DEC_PIC_AVC_FPA_SEI1);
			info->avcFpaSei.content_interpretation_type = val & 0x3F;
			info->avcFpaSei.frame_packing_arrangement_type = (val >> 6) & 0x7F;
			info->avcFpaSei.frame_packing_arrangement_ext_flag = (val >> 13) & 0x01;
			info->avcFpaSei.frame1_self_contained_flag = (val >> 14) & 0x01;
			info->avcFpaSei.frame0_self_contained_flag = (val >> 15) & 0x01;
			info->avcFpaSei.current_frame_is_frame0_flag = (val >> 16) & 0x01;
			info->avcFpaSei.field_views_flag = (val >> 17) & 0x01;
			info->avcFpaSei.frame0_flipped_flag = (val >> 18) & 0x01;
			info->avcFpaSei.spatial_flipping_flag = (val >> 19) & 0x01;
			info->avcFpaSei.quincunx_sampling_flag = (val >> 20)&0x01;
			info->avcFpaSei.frame_packing_arrangement_cancel_flag = (val >> 21) & 0x01;

			val = VpuReadReg(RET_DEC_PIC_AVC_FPA_SEI2);
			info->avcFpaSei.frame_packing_arrangement_repetition_period = val & 0x7FFF;
			info->avcFpaSei.frame1_grid_position_y = (val >> 16) & 0x0F;
			info->avcFpaSei.frame1_grid_position_x = (val >> 20) & 0x0F;
			info->avcFpaSei.frame0_grid_position_y = (val >> 24) & 0x0F;
			info->avcFpaSei.frame0_grid_position_x = (val >> 28) &0x0F;
		}
	}

	/* Backup context regs, no need to save BIT_WR_PTR
	   and BIT_FRAME_MEM_CTRL since f/w doesn't update the registers */
	pCodecInst->ctxRegs[CTX_BIT_FRM_DIS_FLG] = VpuReadReg(BIT_FRM_DIS_FLG);
	pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = VpuReadReg(BIT_RD_PTR);
	pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM] = VpuReadReg(BIT_BIT_STREAM_PARAM);

	if (cpu_is_mx27()) {
		if (pCodecInst->codecMode == MP4_DEC &&
		    pDecInfo->openParam.qpReport == 1) {
			int widthInMB;
			int heightInMB;
			int readPnt;
			int writePnt;
			int i;
			int j;
			Uint32 val, val1, val2;

			widthInMB = pDecInfo->initialInfo.picWidth / 16;
			heightInMB = pDecInfo->initialInfo.picHeight / 16;
			writePnt = 0;
			for (i = 0; i < heightInMB; ++i) {
				readPnt = i * 32;
				for (j = 0; j < widthInMB; j += 4) {
					val1 = virt_paraBuf[readPnt];
					readPnt++;
					val2 = virt_paraBuf[readPnt];
					readPnt++;
					val = (val1 << 8 & 0xff000000) |
					    (val1 << 16) | (val2 >> 8) |
					    (val2 & 0x000000ff);
					virt_paraBuf2[writePnt] = val;
					writePnt++;
				}
			}

			info->qpInfo = virt_paraBuf2;
		}
	}

	if (pCodecInst->codecMode == VC1_DEC) {
		val = VpuReadReg(RET_DEC_PIC_POST);
		info->hScaleFlag = (val >> 1) & 1;
		info->vScaleFlag = (val >> 2) & 1;
		info->indexFrameRangemap = -1;
		if (val & 1)
			info->indexFrameRangemap = (val >> 3) & 31;
	}

	*ppendingInst = 0;
	UnlockVpu(vpu_semap);
	log_time(pCodecInst->instIndex, OUT_UNLOCK);

	return RETCODE_SUCCESS;
}

RetCode vpu_DecBitBufferFlush(DecHandle handle)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	/* This means frame buffers have not been registered. */
	if (pDecInfo->frameBufPool == 0) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	if (!LockVpu(vpu_semap))
		return RETCODE_FAILURE_TIMEOUT;

	if (cpu_is_mx6x())
		pCodecInst->ctxRegs[CTX_BIT_RD_PTR] = pDecInfo->streamBufStartAddr;

	if (!is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
		BitIssueCommand(pCodecInst, DEC_BUF_FLUSH);
		while (VpuReadReg(BIT_BUSY_FLAG)) ;
	} else
		pDecInfo->jpgInfo.frameOffset = 0;

	pDecInfo->streamWrPtr = pDecInfo->streamBufStartAddr;

	VpuWriteReg(BIT_WR_PTR, pDecInfo->streamBufStartAddr);
	/* Backup context reg */
	pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = pDecInfo->streamBufStartAddr;
	UnlockVpu(vpu_semap);

	return RETCODE_SUCCESS;
}

RetCode vpu_DecClrDispFlag(DecHandle handle, int index)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	RetCode ret;
	int val;

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	/* This means frame buffers have not been registered. */
	if (pDecInfo->frameBufPool == 0) {
		return RETCODE_WRONG_CALL_SEQUENCE;
	}

	if ((index < 0) || (index > (pDecInfo->numFrameBuffers - 1)))
		return RETCODE_INVALID_PARAM;

	val = (~(1 << index) & pCodecInst->ctxRegs[CTX_BIT_FRM_DIS_FLG]);
	pCodecInst->ctxRegs[CTX_BIT_FRM_DIS_FLG] = val;

	return RETCODE_SUCCESS;
}

/*!
 * @brief Give command to the decoder.
 *
 * @param handle [Input] The handle obtained from vpu_DecOpen().
 * @param cmd [Intput] Command.
 * @param param [Intput/Output] param  for cmd.
 *
 * @return
 * @li RETCODE_INVALID_COMMANDcmd is not valid.
 * @li RETCODE_INVALID_HANDLE decHandle is invalid.
 * @li RETCODE_FRAME_NOT_COMPLETE A frame has not been finished.
 */
RetCode vpu_DecGiveCommand(DecHandle handle, CodecCommand cmd, void *param)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	RetCode ret;

	ENTER_FUNC();

	ret = CheckDecInstanceValidity(handle);
	if (ret != RETCODE_SUCCESS)
		return ret;

	if (cpu_is_mx27() && (cmd == DEC_SET_DEBLOCK_OUTPUT)) {
		return RETCODE_NOT_SUPPORTED;
	}

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	switch (cmd) {
	case ENABLE_ROTATION:
		{
			if (!pDecInfo->rotatorOutputValid) {
				return RETCODE_ROTATOR_OUTPUT_NOT_SET;
			}
			if (pDecInfo->rotatorStride == 0) {
				return RETCODE_ROTATOR_STRIDE_NOT_SET;
			}
			pDecInfo->rotationEnable = 1;
			break;
		}

	case DISABLE_ROTATION:
		{
			pDecInfo->rotationEnable = 0;
			break;
		}

	case ENABLE_MIRRORING:
		{
			if (!pDecInfo->rotatorOutputValid) {
				return RETCODE_ROTATOR_OUTPUT_NOT_SET;
			}
			if (pDecInfo->rotatorStride == 0) {
				return RETCODE_ROTATOR_STRIDE_NOT_SET;
			}
			pDecInfo->mirrorEnable = 1;
			break;
		}

	case DISABLE_MIRRORING:
		{
			pDecInfo->mirrorEnable = 0;
			break;
		}

	case SET_MIRROR_DIRECTION:
		{
			int mirDir;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}
			mirDir = *(int*) param;
			if (mirDir < MIRDIR_NONE || mirDir > MIRDIR_HOR_VER) {
				return RETCODE_INVALID_PARAM;
			}
			pDecInfo->mirrorDirection = (MirrorDirection)mirDir;
			break;
		}

	case SET_ROTATION_ANGLE:
		{
			int angle;
			int height, width;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}
			angle = *(int *)param;
			if (angle != 0 && angle != 90 &&
			    angle != 180 && angle != 270) {
				return RETCODE_INVALID_PARAM;
			}
			if (pDecInfo->rotatorStride != 0) {
				height = pDecInfo->initialInfo.picHeight;
				width = pDecInfo->initialInfo.picWidth;

				if (angle == 90 || angle == 270) {
					if (height > pDecInfo->rotatorStride) {
						return RETCODE_INVALID_PARAM;
					}
				} else {
					if (width > pDecInfo->rotatorStride) {
						return RETCODE_INVALID_PARAM;
					}
				}
			}

			pDecInfo->rotationAngle = angle;
			break;
		}

	case SET_ROTATOR_OUTPUT:
		{
			FrameBuffer *frame;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}
			frame = (FrameBuffer *) param;
			pDecInfo->rotatorOutput = *frame;
			pDecInfo->rotatorOutputValid = 1;
			break;
		}

	case SET_ROTATOR_STRIDE:
		{
			int stride;

			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}
			stride = *(int *)param;
			if (stride % 8 != 0 || stride == 0) {
				return RETCODE_INVALID_STRIDE;
			}
			if (pDecInfo->rotationAngle == 90 ||
			    pDecInfo->rotationAngle == 270) {
				if (pDecInfo->initialInfo.picHeight > stride) {
					return RETCODE_INVALID_STRIDE;
				}
			} else {
				if (!is_mx6x_mjpg_codec(pCodecInst->codecMode)) {
					if (pDecInfo->initialInfo.picWidth > stride)
						return RETCODE_INVALID_STRIDE;
				}
			}

			pDecInfo->rotatorStride = stride;
			break;
		}

	case DEC_SET_SPS_RBSP:
		{
			if (pCodecInst->codecMode != AVC_DEC) {
				return RETCODE_INVALID_COMMAND;
			}
			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}

			if (!LockVpu(vpu_semap))
				return RETCODE_FAILURE_TIMEOUT;

			SetParaSet(handle, 0, param);
			UnlockVpu(vpu_semap);
			break;
		}

	case DEC_SET_PPS_RBSP:
		{
			if (pCodecInst->codecMode != AVC_DEC) {
				return RETCODE_INVALID_COMMAND;
			}
			if (param == 0) {
				return RETCODE_INVALID_PARAM;
			}
			SetParaSet(handle, 1, param);
			break;
		}

	case DEC_SET_DEBLOCK_OUTPUT:
		{
			if (cpu_is_mx27()) {
				FrameBuffer *frame;
				if (param == 0) {
					return RETCODE_INVALID_PARAM;
				}
				frame = (FrameBuffer *) param;
				pDecInfo->deBlockingFilterOutput = *frame;
				pDecInfo->deBlockingFilterOutputValid = 1;
			}
			break;
		}
	case ENABLE_DERING:
		{
			if (!pDecInfo->rotatorOutputValid) {
				return RETCODE_ROTATOR_OUTPUT_NOT_SET;
			}
			if (pDecInfo->rotatorStride == 0) {
				return RETCODE_ROTATOR_STRIDE_NOT_SET;
			}
			pDecInfo->deringEnable = 1;
			break;
		}

	case DISABLE_DERING:
		{
			pDecInfo->deringEnable = 0;
			break;
		}

	case SET_DBK_OFFSET :
		{
			DbkOffset dbkOffset;
			dbkOffset = *(DbkOffset *)param;

			pDecInfo->dbkOffset.DbkOffsetA = dbkOffset.DbkOffsetA;
			pDecInfo->dbkOffset.DbkOffsetB = dbkOffset.DbkOffsetB;

			pDecInfo->dbkOffset.DbkOffsetEnable =
					((pDecInfo->dbkOffset.DbkOffsetA !=0 ) &&
						(pDecInfo->dbkOffset.DbkOffsetB != 0));
			break;
		}

	case DEC_SET_REPORT_BUFSTAT:
		{
			if (param == 0)
				return  RETCODE_INVALID_PARAM;
			pDecInfo->decReportFrameBufStat = *(DecReportInfo *)param;

			if (pDecInfo->decReportFrameBufStat.enable &&
			    !pDecInfo->decReportFrameBufStat.addr)
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case DEC_SET_REPORT_MBINFO:
		{
			if (param == 0)
				return  RETCODE_INVALID_PARAM;
			pDecInfo->decReportMBInfo = *(DecReportInfo *)param;

			if (pDecInfo->decReportMBInfo.enable && !pDecInfo->decReportMBInfo.addr)
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case DEC_SET_REPORT_MVINFO:
		{
			if (param == 0)
				return RETCODE_INVALID_PARAM;
			pDecInfo->decReportMVInfo = *(DecReportInfo *)param;
			if (pDecInfo->decReportMVInfo.enable && !pDecInfo->decReportMVInfo.addr)
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case DEC_SET_REPORT_USERDATA:
		{
			if (param == 0)
				return RETCODE_INVALID_PARAM;
			pDecInfo->decReportUserData = *(DecReportInfo *)param;
			if ((pDecInfo->decReportUserData.enable) && (!pDecInfo->decReportUserData.addr))
				return RETCODE_REPORT_BUF_NOT_SET;
			break;
		}

	case DEC_SET_FRAME_DELAY:
		{
			pDecInfo->frame_delay = *(int *)param;
			break;
		}

	default:
		return RETCODE_INVALID_COMMAND;
	}

	return RETCODE_SUCCESS;
}

void SaveGetEncodeHeader(EncHandle handle, int encHeaderType, char *filename)
{
	FILE *fp = NULL;
	Uint8 *pHeader = NULL;
	EncParamSet encHeaderParam = { 0, 0, 0 };
	int i;
	Uint32 dword1, dword2;
	Uint32 *pBuf;
	Uint32 byteSize;

	ENTER_FUNC();

	if (filename == NULL)
		return;

	vpu_EncGiveCommand(handle, encHeaderType, &encHeaderParam);
	byteSize = ((encHeaderParam.size + 3) & ~3);
	pHeader = (Uint8 *) malloc(sizeof(Uint8) * byteSize);
	if (pHeader) {
		memcpy(pHeader, encHeaderParam.paraSet, byteSize);

		/* ParaBuffer is big endian */
		pBuf = (Uint32 *) pHeader;
		for (i = 0; i < (int)byteSize / 4; i++) {
			dword1 = pBuf[i];
			dword2 = (dword1 >> 24) & 0xFF;
			dword2 |= ((dword1 >> 16) & 0xFF) << 8;
			dword2 |= ((dword1 >> 8) & 0xFF) << 16;
			dword2 |= ((dword1 >> 0) & 0xFF) << 24;
			pBuf[i] = dword2;
		}

		if (encHeaderParam.size > 0) {
			fp = fopen(filename, "wb");
			if (fp) {
				fwrite(pHeader, sizeof(Uint8),
				       encHeaderParam.size, fp);
				fclose(fp);
			}
		}

		free(pHeader);
	}
}
