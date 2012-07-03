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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "vpu_util.h"
#include "vpu_io.h"

CodecInst codecInstPool[MAX_NUM_INSTANCE];

extern PhysicalAddress workBuffer;
extern PhysicalAddress codeBuffer;
extern PhysicalAddress paraBuffer;
extern unsigned long *virt_paraBuf;
extern unsigned long *virt_paraBuf2;

/*
 * GetCodecInstance() obtains an instance.
 * It stores a pointer to the allocated instance in *ppInst
 * and returns RETCODE_SUCCESS on success.
 * Failure results in 0(null pointer) in *ppInst and RETCODE_FAILURE.
 */
RetCode GetCodecInstance(CodecInst ** ppInst)
{
	int i;
	CodecInst *pCodecInst;

	pCodecInst = &codecInstPool[0];
	for (i = 0; i < MAX_NUM_INSTANCE; ++i, ++pCodecInst) {
		if (!pCodecInst->inUse)
			break;
	}

	if (i == MAX_NUM_INSTANCE) {
		*ppInst = 0;
		return RETCODE_FAILURE;
	}

	i = pCodecInst->instIndex;
	memset(pCodecInst, 0, sizeof(CodecInst));
	pCodecInst->instIndex = i;
	pCodecInst->inUse = 1;
	*ppInst = pCodecInst;
	return RETCODE_SUCCESS;
}

RetCode CheckInstanceValidity(CodecInst * pci)
{
	CodecInst *pCodecInst;
	int i;

	pCodecInst = &codecInstPool[0];
	for (i = 0; i < MAX_NUM_INSTANCE; ++i, ++pCodecInst) {
		if (pCodecInst == pci)
			return RETCODE_SUCCESS;
	}
	return RETCODE_INVALID_HANDLE;
}

RetCode CheckEncInstanceValidity(EncHandle handle)
{
	CodecInst *pCodecInst;
	RetCode ret;

	if (cpu_is_mx32()) {
		return RETCODE_NOT_SUPPORTED;
	}

	pCodecInst = handle;
	ret = CheckInstanceValidity(pCodecInst);
	if (ret != RETCODE_SUCCESS) {
		return RETCODE_INVALID_HANDLE;
	}
	if (!pCodecInst->inUse) {
		return RETCODE_INVALID_HANDLE;
	}
	if (pCodecInst->codecMode != MP4_ENC &&
	    pCodecInst->codecMode != AVC_ENC) {
		return RETCODE_INVALID_HANDLE;
	}
	return RETCODE_SUCCESS;
}

RetCode CheckDecInstanceValidity(DecHandle handle)
{
	CodecInst *pCodecInst;
	RetCode ret;

	pCodecInst = handle;
	ret = CheckInstanceValidity(pCodecInst);
	if (ret != RETCODE_SUCCESS) {
		return RETCODE_INVALID_HANDLE;
	}
	if (!pCodecInst->inUse) {
		return RETCODE_INVALID_HANDLE;
	}

	if (cpu_is_mx27()) {
		if (pCodecInst->codecMode != MP4_DEC &&
		    pCodecInst->codecMode != AVC_DEC)
			return RETCODE_INVALID_HANDLE;
	} else if (cpu_is_mx32()) {
		if (pCodecInst->codecMode != MP4_DEC &&
		    pCodecInst->codecMode != AVC_DEC &&
		    pCodecInst->codecMode != VC1_DEC)
			return RETCODE_INVALID_HANDLE;
	} else if (cpu_is_mx37()) {
		if (pCodecInst->codecMode != MP4_DEC &&
		    pCodecInst->codecMode != AVC_DEC &&
		    pCodecInst->codecMode != VC1_DEC &&
		    pCodecInst->codecMode != MP2_DEC &&
		    pCodecInst->codecMode != DV3_DEC)
			return RETCODE_INVALID_HANDLE;
	} else if (cpu_is_mx51()) {
		if (pCodecInst->codecMode != MP4_DEC &&
		    pCodecInst->codecMode != AVC_DEC &&
		    pCodecInst->codecMode != VC1_DEC &&
		    pCodecInst->codecMode != MP2_DEC &&
		    pCodecInst->codecMode != DV3_DEC &&
		    pCodecInst->codecMode != RV_DEC &&
		    pCodecInst->codecMode != MJPG_DEC)
			return RETCODE_INVALID_PARAM;
	}

	return RETCODE_SUCCESS;
}

void FreeCodecInstance(CodecInst * pCodecInst)
{
	pCodecInst->inUse = 0;
}

void BitIssueCommand(int instIdx, int cdcMode, int cmd)
{
	IOClkGateSet(true);

	VpuWriteReg(BIT_BUSY_FLAG, 0x1);
	VpuWriteReg(BIT_RUN_INDEX, instIdx);
	VpuWriteReg(BIT_RUN_COD_STD, cdcMode);
	VpuWriteReg(BIT_RUN_COMMAND, cmd);

	IOClkGateSet(false);
}

RetCode CheckEncOpenParam(EncOpenParam * pop)
{
	int picWidth;
	int picHeight;

	if (cpu_is_mx32() || cpu_is_mx37()) {
		return RETCODE_NOT_SUPPORTED;
	}

	if (pop == 0) {
		return RETCODE_INVALID_PARAM;
	}
	picWidth = pop->picWidth;
	picHeight = pop->picHeight;
	if (pop->bitstreamBuffer % 4) {	/* not 4-bit aligned */
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitstreamBufferSize % 1024 ||
	    pop->bitstreamBufferSize < 1024 ||
	    pop->bitstreamBufferSize > 16383 * 1024) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitstreamFormat != STD_MPEG4 &&
	    pop->bitstreamFormat != STD_H263 &&
	    pop->bitstreamFormat != STD_AVC) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitRate > 32767 || pop->bitRate < 0) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitRate != 0 && pop->initialDelay > 32767) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitRate != 0 && pop->initialDelay != 0 &&
	    pop->vbvBufferSize < 0) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->enableAutoSkip != 0 && pop->enableAutoSkip != 1) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->gopSize > 60) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->slicemode.sliceMode != 0 && pop->slicemode.sliceMode != 1) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->slicemode.sliceMode == 1) {
		if (pop->slicemode.sliceSizeMode != 0 &&
		    pop->slicemode.sliceSizeMode != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (pop->slicemode.sliceSize == 0) {
			return RETCODE_INVALID_PARAM;
		}
	}
	if (pop->sliceReport != 0 && pop->sliceReport != 1) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->mbReport != 0 && pop->mbReport != 1) {
		return RETCODE_INVALID_PARAM;
	}

	if (pop->intraRefresh < 0 || pop->intraRefresh >=
	    (picWidth * picHeight / 256)) {
		return RETCODE_INVALID_PARAM;
	}

	if (pop->bitstreamFormat == STD_MPEG4) {
		EncMp4Param *param = &pop->EncStdParam.mp4Param;
		if (param->mp4_dataPartitionEnable != 0 &&
		    param->mp4_dataPartitionEnable != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->mp4_dataPartitionEnable == 1) {
			if (param->mp4_reversibleVlcEnable != 0 &&
			    param->mp4_reversibleVlcEnable != 1) {
				return RETCODE_INVALID_PARAM;
			}
		}
		if (param->mp4_intraDcVlcThr < 0 ||
		    param->mp4_intraDcVlcThr > 7) {
			return RETCODE_INVALID_PARAM;
		}
	} else if (pop->bitstreamFormat == STD_H263) {
		EncH263Param *param = &pop->EncStdParam.h263Param;
		if (param->h263_annexJEnable != 0 &&
		    param->h263_annexJEnable != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->h263_annexKEnable != 0 &&
		    param->h263_annexKEnable != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->h263_annexTEnable != 0 &&
		    param->h263_annexTEnable != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->h263_annexJEnable == 0 &&
		    param->h263_annexKEnable == 0 &&
		    param->h263_annexTEnable == 0) {
			if (!(picWidth == 128 && picHeight == 96) &&
			    !(picWidth == 176 && picHeight == 144) &&
			    !(picWidth == 352 && picHeight == 288) &&
			    !(picWidth == 704 && picHeight == 576)) {
				return RETCODE_INVALID_PARAM;
			}
		}
	} else if (pop->bitstreamFormat == STD_AVC) {
		EncAvcParam *param = &pop->EncStdParam.avcParam;
		if (param->avc_constrainedIntraPredFlag != 0 &&
		    param->avc_constrainedIntraPredFlag != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_disableDeblk != 0 &&
		    param->avc_disableDeblk != 1 &&
		    param->avc_disableDeblk != 2) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_deblkFilterOffsetAlpha < -6 ||
		    param->avc_deblkFilterOffsetAlpha > 6) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_deblkFilterOffsetBeta < -6 ||
		    param->avc_deblkFilterOffsetBeta > 6) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_chromaQpOffset < -12 ||
		    param->avc_chromaQpOffset > 12) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_audEnable != 0 && param->avc_audEnable != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_fmoEnable != 0 && param->avc_fmoEnable != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (param->avc_fmoEnable == 1) {
			if (param->avc_fmoType != 0 && param->avc_fmoType != 1) {
				return RETCODE_INVALID_PARAM;
			}
			if (param->avc_fmoSliceNum < 2 ||
			    8 < param->avc_fmoSliceNum) {
				return RETCODE_INVALID_PARAM;
			}
		}
	}

	if (picWidth < 32 || picWidth > MAX_ENC_PIC_WIDTH) {
		return RETCODE_INVALID_PARAM;
	}
	if (picHeight < 16 || picHeight > MAX_ENC_PIC_HEIGHT) {
		return RETCODE_INVALID_PARAM;
	}

	return RETCODE_SUCCESS;
}

RetCode CheckEncParam(CodecInst * pCodecInst, EncParam * param)
{
	if (param == 0) {
		return RETCODE_INVALID_PARAM;
	}
	if (param->skipPicture != 0 && param->skipPicture != 1) {
		return RETCODE_INVALID_PARAM;
	}
	if (param->skipPicture == 0) {
		if (param->sourceFrame == 0) {
			return RETCODE_INVALID_FRAME_BUFFER;
		}
		if (param->forceIPicture != 0 && param->forceIPicture != 1) {
			return RETCODE_INVALID_PARAM;
		}
	}

	/* no rate control */
	if (pCodecInst->CodecInfo.encInfo.openParam.bitRate == 0) {
		if (pCodecInst->codecMode == MP4_ENC) {
			if (param->quantParam < 1 || param->quantParam > 31) {
				return RETCODE_INVALID_PARAM;
			}
		} else {	/* AVC_ENC */
			if (param->quantParam < 0 || param->quantParam > 51) {
				return RETCODE_INVALID_PARAM;
			}
		}
	}
	return RETCODE_SUCCESS;
}

void EncodeHeader(EncHandle handle, EncHeaderParam * encHeaderParam)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	PhysicalAddress rdPtr;
	PhysicalAddress wrPtr;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	IOClkGateSet(true);
	if (pEncInfo->dynamicAllocEnable == 1) {
		VpuWriteReg(CMD_ENC_HEADER_BB_START, encHeaderParam->buf);
		VpuWriteReg(CMD_ENC_HEADER_BB_SIZE, encHeaderParam->size);
	}
	// 0: SPS, 1: PPS
	VpuWriteReg(CMD_ENC_HEADER_CODE, encHeaderParam->headerType);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			ENCODE_HEADER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	if (pEncInfo->dynamicAllocEnable == 1) {
		rdPtr = VpuReadReg(CMD_ENC_HEADER_BB_START);
		wrPtr = VpuReadReg(pEncInfo->streamWrPtrRegAddr);
	} else {
		rdPtr = VpuReadReg(pEncInfo->streamRdPtrRegAddr);
		wrPtr = VpuReadReg(pEncInfo->streamWrPtrRegAddr);
	}
	IOClkGateSet(false);

	encHeaderParam->buf = rdPtr;
	encHeaderParam->size = wrPtr - rdPtr;
}

RetCode CheckDecOpenParam(DecOpenParam * pop)
{
	if (pop == 0) {
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitstreamBuffer % 4) {	/* not 4-bit aligned */
		return RETCODE_INVALID_PARAM;
	}
	if (pop->bitstreamBufferSize % 1024 ||
	    pop->bitstreamBufferSize < 1024 ||
	    pop->bitstreamBufferSize > 16383 * 1024) {
		return RETCODE_INVALID_PARAM;
	}
	if (cpu_is_mx27()) {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_H263 &&
		    pop->bitstreamFormat != STD_AVC)
			return RETCODE_INVALID_PARAM;
	} else if (cpu_is_mx32()) {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_H263 &&
		    pop->bitstreamFormat != STD_AVC &&
		    pop->bitstreamFormat != STD_VC1)
			return RETCODE_INVALID_PARAM;
	} else if (cpu_is_mx37()) {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_H263 &&
		    pop->bitstreamFormat != STD_AVC &&
		    pop->bitstreamFormat != STD_VC1 &&
		    pop->bitstreamFormat != STD_MPEG2 &&
		    pop->bitstreamFormat != STD_DIV3)
			return RETCODE_INVALID_PARAM;
	} else if (cpu_is_mx51()) {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_H263 &&
		    pop->bitstreamFormat != STD_AVC &&
		    pop->bitstreamFormat != STD_VC1 &&
		    pop->bitstreamFormat != STD_MPEG2 &&
		    pop->bitstreamFormat != STD_DIV3 &&
		    pop->bitstreamFormat != STD_RV &&
		    pop->bitstreamFormat != STD_MJPG)
			return RETCODE_INVALID_PARAM;
	}
	if (cpu_is_mx27()) {
		if (pop->bitstreamFormat == STD_MPEG4 ||
		    pop->bitstreamFormat == STD_H263) {
			if (pop->qpReport != 0 && pop->qpReport != 1) {
				return RETCODE_INVALID_PARAM;
			}
		}
	} else {
		if (pop->mp4DeblkEnable == 1 && !(pop->bitstreamFormat ==
						  STD_MPEG4
						  || pop->bitstreamFormat ==
						  STD_H263
						  || pop->bitstreamFormat ==
						  STD_MPEG2
						  || pop->bitstreamFormat ==
						  STD_DIV3)) {
			return RETCODE_INVALID_PARAM;
		}
	}
	return RETCODE_SUCCESS;
}

int DecBitstreamBufEmpty(DecInfo * pDecInfo)
{
	PhysicalAddress rdPtr;
	PhysicalAddress wrPtr;

	IOClkGateSet(true);

	rdPtr = VpuReadReg(pDecInfo->streamRdPtrRegAddr);
	wrPtr = VpuReadReg(pDecInfo->streamWrPtrRegAddr);

	IOClkGateSet(false);

	return rdPtr == wrPtr;
}

void GetParaSet(EncHandle handle, int paraSetType, EncParamSet * para)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	IOClkGateSet(true);

	/* SPS: 0, PPS: 1, VOS: 1, VO: 2, VOL: 0 */
	VpuWriteReg(CMD_ENC_PARA_SET_TYPE, paraSetType);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			ENC_PARA_SET);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	para->paraSet = virt_paraBuf;
	para->size = VpuReadReg(RET_ENC_PARA_SET_SIZE);

	IOClkGateSet(false);
}

void SetParaSet(DecHandle handle, int paraSetType, DecParamSet * para)
{
	CodecInst *pCodecInst;
	DecInfo *pDecInfo;
	int i;
	Uint32 *src;
	int byteSize;

	pCodecInst = handle;
	pDecInfo = &pCodecInst->CodecInfo.decInfo;

	src = para->paraSet;
	byteSize = para->size / 4;

	for (i = 0; i < byteSize; i += 1) {
		virt_paraBuf[i] = *src++;
	}

	IOClkGateSet(true);

	VpuWriteReg(CMD_DEC_PARA_SET_TYPE, paraSetType);
	VpuWriteReg(CMD_DEC_PARA_SET_SIZE, para->size);

	if (cpu_is_mx51()) {
		if (pDecInfo->openParam.bitstreamFormat == STD_DIV3)
			VpuWriteReg(BIT_RUN_AUX_STD, 1);
		else
			VpuWriteReg(BIT_RUN_AUX_STD, 0);
	}

	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			DEC_PARA_SET);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	IOClkGateSet(false);
}

// Following are not for MX32 and MX27 TO1
RetCode SetGopNumber(EncHandle handle, Uint32 * pGopNumber)
{
	CodecInst *pCodecInst;
	int data = 0;
	Uint32 gopNumber = *pGopNumber;

	pCodecInst = handle;
	data = 1;
	IOClkGateSet(true);
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	VpuWriteReg(CMD_ENC_SEQ_PARA_RC_GOP, gopNumber);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetIntraQp(EncHandle handle, Uint32 * pIntraQp)
{
	CodecInst *pCodecInst;
	int data = 0;
	Uint32 intraQp = *pIntraQp;

	IOClkGateSet(true);

	pCodecInst = handle;
	data = 1 << 1;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	VpuWriteReg(CMD_ENC_SEQ_PARA_RC_INTRA_QP, intraQp);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetBitrate(EncHandle handle, Uint32 * pBitrate)
{
	CodecInst *pCodecInst;
	int data = 0;
	Uint32 bitrate = *pBitrate;

	IOClkGateSet(true);

	pCodecInst = handle;
	data = 1 << 2;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	VpuWriteReg(CMD_ENC_SEQ_PARA_RC_BITRATE, bitrate);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetFramerate(EncHandle handle, Uint32 * pFramerate)
{
	CodecInst *pCodecInst;
	int data = 0;
	Uint32 framerate = *pFramerate;

	IOClkGateSet(true);

	pCodecInst = handle;
	data = 1 << 3;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	VpuWriteReg(CMD_ENC_SEQ_PARA_RC_FRAME_RATE, framerate);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetIntraRefreshNum(EncHandle handle, Uint32 * pIntraRefreshNum)
{
	CodecInst *pCodecInst;
	Uint32 intraRefreshNum = *pIntraRefreshNum;
	int data = 0;

	IOClkGateSet(true);

	pCodecInst = handle;
	data = 1 << 4;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	VpuWriteReg(CMD_ENC_SEQ_PARA_INTRA_MB_NUM, intraRefreshNum);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetSliceMode(EncHandle handle, EncSliceMode * pSliceMode)
{
	CodecInst *pCodecInst;
	Uint32 data = 0;
	int data2 = 0;

	data = pSliceMode->sliceSize << 2 | pSliceMode->sliceSizeMode << 1 |
	    pSliceMode->sliceMode;
	pCodecInst = handle;

	IOClkGateSet(true);

	data2 = 1 << 5;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data2);
	VpuWriteReg(CMD_ENC_SEQ_PARA_SLICE_MODE, data);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetHecMode(EncHandle handle, int mode)
{
	CodecInst *pCodecInst;
	Uint32 HecMode = mode;
	int data = 0;
	pCodecInst = handle;

	IOClkGateSet(true);

	data = 1 << 6;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	VpuWriteReg(CMD_ENC_SEQ_PARA_HEC_MODE, HecMode);
	BitIssueCommand(pCodecInst->instIndex, pCodecInst->codecMode,
			RC_CHANGE_PARAMETER);

	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}
