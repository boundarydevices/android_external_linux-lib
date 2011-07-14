/*
 * Copyright 2004-2011 Freescale Semiconductor, Inc.
 *
 * Copyright (c) 2006, Chips & Media. All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>

#include "vpu_util.h"
#include "vpu_io.h"
#include "vpu_debug.h"

#define MAX_VSIZE       8192
#define MAX_HSIZE       8192

enum {
	SAMPLE_420 = 0xA,
	SAMPLE_H422 = 0x9,
	SAMPLE_V422 = 0x6,
	SAMPLE_444 = 0x5,
	SAMPLE_400 = 0x1
};

/*
 * VPU binary file header format:
 * 12-byte: platform version, eg, MX27, MX51, and so on.
 * 4-byte:  element numbers, each element is 16bit(unsigned short)
 */
typedef struct {
	Uint8 platform[12];
	Uint32 size;
} headerInfo;

extern unsigned long *virt_paraBuf;
extern semaphore_t *vpu_semap;
static int mutex_timeout;
static vpu_mem_desc share_mem;

static semaphore_t  g_sema_buffer;

RetCode LoadBitCodeTable(Uint16 * pBitCode, int *size)
{
	FILE *fp;
	headerInfo info;
	char *fw_path, temp_str[64], fw_name[256];
	int ret;

	fw_path = getenv("VPU_FW_PATH");

	if (fw_path == NULL)
#ifdef BUILD_FOR_ANDROID
		strcpy(fw_name, "/system/lib/firmware/vpu");    /* default path */
#else
		strcpy(fw_name, "/lib/firmware/vpu");	/* default path */
#endif
	else
		strcpy(fw_name, fw_path);

	strcat(fw_name, "/");
	if (cpu_is_mx27_rev(CHIP_REV_2_0) > 0)
		strcat(fw_name, "vpu_fw_imx27_TO2.bin");
	else if (cpu_is_mx27_rev(CHIP_REV_1_0) > 0)
		strcat(fw_name, "vpu_fw_imx27_TO1.bin");
	else if cpu_is_mx6q()
		strcat(fw_name, "vpu_fw_imx6q.bin");
	else {
		memset(temp_str, 0, 64);
		sprintf(temp_str, "vpu_fw_imx%2x.bin", mxc_cpu());
		strcat(fw_name, temp_str);
	}

	fp = fopen(fw_name, "rb");
	if (fp == NULL) {
		err_msg("Error in opening firmware binary file\n");
		err_msg("Please put bin file to /lib/firmware/vpu folder or export VPU_FW_PATH env\n");
		return RETCODE_FAILURE;
	}

	fread(&info, sizeof(headerInfo), 1, fp);

	if (info.size > MAX_FW_BINARY_LEN) {
		err_msg("Size in VPU header is too large.Size: %d\n",
			(Uint16) info.size);
		goto err;
	}

	ret = fread(pBitCode, sizeof(Uint16), info.size, fp);
	if (ret < info.size) {
		err_msg("VPU firmware binary file is wrong or corrupted.\n");
		goto err;
	}
	fclose(fp);

	memset(temp_str, 0, 64);
	sprintf(temp_str, "%2x", mxc_cpu());
	if (strcmp(temp_str, "63") == 0) {
		strcpy(temp_str, "6Q");
	}

	if (strstr((char *)info.platform, temp_str) == NULL) {
		err_msg("VPU firmware platform version isn't matched\n");
		goto err;
	}

	*size = (int)info.size;
	return RETCODE_SUCCESS;

      err:
	fclose(fp);
	return RETCODE_FAILURE;
}

RetCode DownloadBitCodeTable(unsigned long *virtCodeBuf, Uint16 *bit_code)
{
	int i, size;
	volatile Uint32 data;
	unsigned long *virt_codeBuf = NULL;

	if (virtCodeBuf == NULL || bit_code == NULL) {
		err_msg("Failed to allocate bit_code\n");
		return RETCODE_FAILURE;
	}

	memset(bit_code, 0, MAX_FW_BINARY_LEN * sizeof(Uint16));
	if (LoadBitCodeTable(bit_code, &size) != RETCODE_SUCCESS) {
		return RETCODE_FAILURE;
	}

	virt_codeBuf = virtCodeBuf;
	/* Copy full Microcode to Code Buffer allocated on SDRAM */
	if (!cpu_is_mx27()) {
		for (i = 0; i < size; i += 4) {
			data =
			    (bit_code[i + 0] << 16) | bit_code[i + 1];
			((unsigned int *)virt_codeBuf)[i / 2 + 1] =
			    data;
			data =
			    (bit_code[i + 2] << 16) | bit_code[i + 3];
			((unsigned int *)virt_codeBuf)[i / 2] = data;
		}
	} else {
		for (i = 0; i < size; i += 2) {
			data = (unsigned int)((bit_code[i] << 16) |
					      bit_code[i + 1]);
			((unsigned int *)virt_codeBuf)[i / 2] = data;
		}
	}

	return RETCODE_SUCCESS;
}

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

	for (i = 0; i < MAX_NUM_INSTANCE; ++i) {
		pCodecInst = (CodecInst *) (&vpu_semap->codecInstPool[i]);
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

	for (i = 0; i < MAX_NUM_INSTANCE; ++i) {
		pCodecInst = (CodecInst *) (&vpu_semap->codecInstPool[i]);
		if (pCodecInst == pci)
			return RETCODE_SUCCESS;
	}
	return RETCODE_INVALID_HANDLE;
}

RetCode CheckEncInstanceValidity(EncHandle handle)
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
		if (pCodecInst->codecMode != MP4_ENC &&
		    pCodecInst->codecMode != AVC_ENC)
			return RETCODE_INVALID_HANDLE;
	} else {
		if (pCodecInst->codecMode != MP4_ENC &&
		    pCodecInst->codecMode != AVC_ENC &&
		    pCodecInst->codecMode != MJPG_ENC)
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
	} else if (cpu_is_mx6q()) {
		if (pCodecInst->codecMode != MP4_DEC &&
		    pCodecInst->codecMode != AVC_DEC &&
		    pCodecInst->codecMode != VC1_DEC &&
		    pCodecInst->codecMode != MP2_DEC &&
		    pCodecInst->codecMode != DV3_DEC &&
		    pCodecInst->codecMode != AVS_DEC &&
		    pCodecInst->codecMode != RV_DEC &&
		    pCodecInst->codecMode != VPX_DEC &&
		    pCodecInst->codecMode != MJPG_DEC)
			return RETCODE_INVALID_PARAM;
	} else {
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

void BitIssueCommand(int instIdx, int cdcMode, int cdcModeAux, int cmd)
{
	LockVpuReg(vpu_semap);

	VpuWriteReg(BIT_BUSY_FLAG, 0x1);
	VpuWriteReg(BIT_RUN_INDEX, instIdx);
	VpuWriteReg(BIT_RUN_COD_STD, cdcMode);
	VpuWriteReg(BIT_RUN_AUX_STD, cdcModeAux);
	VpuWriteReg(BIT_RUN_COMMAND, cmd);

	UnlockVpuReg(vpu_semap);
}
void BitIssueCommandEx(CodecInst *pCodecInst, int cmd)
{
	LockVpuReg(vpu_semap);

	/* Save context related registers to vpu */
	VpuWriteReg(BIT_BIT_STREAM_PARAM,
			pCodecInst->ctxRegs[CTX_BIT_STREAM_PARAM]);
	VpuWriteReg(BIT_FRM_DIS_FLG,
			pCodecInst->ctxRegs[CTX_BIT_FRM_DIS_FLG]);
	VpuWriteReg(BIT_WR_PTR,
			pCodecInst->ctxRegs[CTX_BIT_WR_PTR]);
	VpuWriteReg(BIT_RD_PTR,
			pCodecInst->ctxRegs[CTX_BIT_RD_PTR]);
	VpuWriteReg(BIT_FRAME_MEM_CTRL,
			pCodecInst->ctxRegs[CTX_BIT_FRAME_MEM_CTRL]);

	if (!cpu_is_mx6q())
		VpuWriteReg(BIT_WORK_BUF_ADDR, pCodecInst->contextBufMem.phy_addr);

	VpuWriteReg(BIT_BUSY_FLAG, 0x1);
	VpuWriteReg(BIT_RUN_INDEX, pCodecInst->instIndex);
	VpuWriteReg(BIT_RUN_COD_STD, pCodecInst->codecMode);
	VpuWriteReg(BIT_RUN_AUX_STD, pCodecInst->codecModeAux);
	VpuWriteReg(BIT_RUN_COMMAND, cmd);
	UnlockVpuReg(vpu_semap);
}

RetCode CheckEncOpenParam(EncOpenParam * pop)
{
	int picWidth;
	int picHeight;

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
	    pop->bitstreamFormat != STD_AVC &&
	    pop->bitstreamFormat != STD_MJPG) {
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
	if (pop->gopSize > 32767) {
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
	if (cpu_is_mx27()) {
		if (pop->sliceReport != 0 && pop->sliceReport != 1) {
			return RETCODE_INVALID_PARAM;
		}
		if (pop->mbReport != 0 && pop->mbReport != 1) {
			return RETCODE_INVALID_PARAM;
		}
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

	if (picWidth < 32 || picHeight < 16) {
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
	int data = 0;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	IOClkGateSet(true);
	if (pEncInfo->dynamicAllocEnable == 1) {
		VpuWriteReg(CMD_ENC_HEADER_BB_START, encHeaderParam->buf);
		VpuWriteReg(CMD_ENC_HEADER_BB_SIZE, encHeaderParam->size);
	}

	if (encHeaderParam->headerType == VOS_HEADER ||
	    encHeaderParam->headerType == SPS_RBSP) {
		data = (((encHeaderParam->userProfileLevelIndication & 0xFF) << 8) |
			((encHeaderParam->userProfileLevelEnable & 0x01) << 4) |
			(encHeaderParam->headerType & 0x0F));
		VpuWriteReg(CMD_ENC_HEADER_CODE, data);
	} else {
		VpuWriteReg(CMD_ENC_HEADER_CODE, encHeaderParam->headerType); /* 0: SPS, 1: PPS */
	}

	BitIssueCommandEx(pCodecInst, ENCODE_HEADER);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	IOClkGateSet(false);

	LockVpuReg(vpu_semap);
	if (pEncInfo->dynamicAllocEnable == 1) {
		rdPtr = VpuReadReg(CMD_ENC_HEADER_BB_START);
		wrPtr = VpuReadReg(BIT_WR_PTR);
		pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = wrPtr;
	} else {
		rdPtr = VpuReadReg(BIT_RD_PTR);
		wrPtr = VpuReadReg(BIT_WR_PTR);
		pCodecInst->ctxRegs[CTX_BIT_WR_PTR] = wrPtr;
	}
	UnlockVpuReg(vpu_semap);

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

	/* Workaround for STD_H263 support: Force to convert STD_H263
           to STD_MPEG4 since VPU treats all H263 as MPEG4 in decoder*/
	if (pop->bitstreamFormat == STD_H263)
		pop->bitstreamFormat = STD_MPEG4;

	if (cpu_is_mx27()) {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_AVC)
			return RETCODE_INVALID_PARAM;
	} else if (cpu_is_mx6q()) {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_AVC &&
		    pop->bitstreamFormat != STD_VC1 &&
		    pop->bitstreamFormat != STD_MPEG2 &&
		    pop->bitstreamFormat != STD_DIV3 &&
		    pop->bitstreamFormat != STD_RV &&
		    pop->bitstreamFormat != STD_AVS &&
		    pop->bitstreamFormat != STD_VP8 &&
		    pop->bitstreamFormat != STD_MJPG)
			return RETCODE_INVALID_PARAM;
	} else {
		if (pop->bitstreamFormat != STD_MPEG4 &&
		    pop->bitstreamFormat != STD_AVC &&
		    pop->bitstreamFormat != STD_VC1 &&
		    pop->bitstreamFormat != STD_MPEG2 &&
		    pop->bitstreamFormat != STD_DIV3 &&
		    pop->bitstreamFormat != STD_RV &&
		    pop->bitstreamFormat != STD_MJPG)
			return RETCODE_INVALID_PARAM;
	}

	if (cpu_is_mx27()) {
		if (pop->bitstreamFormat == STD_MPEG4) {
			if (pop->qpReport != 0 && pop->qpReport != 1) {
				return RETCODE_INVALID_PARAM;
			}
		}
	} else {
		if (pop->mp4DeblkEnable == 1 && !(pop->bitstreamFormat ==
						  STD_MPEG4
						  || pop->bitstreamFormat ==
						  STD_MPEG2
						  || pop->bitstreamFormat ==
						  STD_DIV3)) {
			return RETCODE_INVALID_PARAM;
		}
	}
	return RETCODE_SUCCESS;
}

int DecBitstreamBufEmpty(DecHandle handle)
{
	CodecInst *pCodecInst;
	PhysicalAddress rdPtr;
	PhysicalAddress wrPtr;
	int instIndex;

	pCodecInst = handle;

	LockVpuReg(vpu_semap);
	instIndex = VpuReadReg(BIT_RUN_INDEX);

	rdPtr = (pCodecInst->instIndex == instIndex) ?
		    VpuReadReg(BIT_RD_PTR) :
		    pCodecInst->ctxRegs[CTX_BIT_RD_PTR];
	wrPtr = (pCodecInst->instIndex == instIndex) ?
		    VpuReadReg(BIT_WR_PTR) :
		    pCodecInst->ctxRegs[CTX_BIT_WR_PTR];

	UnlockVpuReg(vpu_semap);

	return rdPtr == wrPtr;
}

RetCode CopyBufferData(Uint8 *dst, Uint8 *src, int size)
{
	Uint32 temp;

	if (!dst || !src || !size)
		return RETCODE_FAILURE;

	if (!cpu_is_mx27()) {
		int i;
		for (i = 0; i < size / 8; i++) {
			/* swab odd and even words and swab32 */
			temp = *((Uint32 *)src + i * 2 + 1);
			*((Uint32 *)dst + i * 2) = swab32(temp);
			temp = *((Uint32 *)src + i * 2);
			*((Uint32 *)dst + i * 2 + 1) = swab32(temp);
		}
	}
	return RETCODE_SUCCESS;
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
	BitIssueCommandEx(pCodecInst, ENC_PARA_SET);
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

	BitIssueCommandEx(pCodecInst, DEC_PARA_SET);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	IOClkGateSet(false);
}

/* Following are not for MX27 TO1 */
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommandEx(pCodecInst, RC_CHANGE_PARAMETER);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

void SetDecSecondAXIIRAM(SecAxiUse *psecAxiIramInfo, SetIramParam *parm)
{
	iram_t iram;
	int size, dbk_size, bitram_size, ipacdc_size, ovl_size, btp_size;

	if (!parm->width) {
		err_msg("Width is zero when calling SetDecSecondAXIIRAM function\n");
		return;
	}

	memset(psecAxiIramInfo, 0, sizeof(SecAxiUse));

	IOGetIramBase(&iram);
	size = iram.end - iram.start + 1;

	/* Setting internal iram usage per priority when iram isn't enough */
	if ((parm->codecMode == VC1_DEC) && (parm->profile == 2))
		dbk_size = (512 * parm->width / 16 + 1023) & ~1023;
	else
		dbk_size = (256 * parm->width / 16 + 1023) & ~1023;

	if (size >= dbk_size) {
		psecAxiIramInfo->useHostDbkEnable = 1;
		psecAxiIramInfo->bufDbkYUse = iram.start;
		psecAxiIramInfo->bufDbkCUse = iram.start + dbk_size / 2;
		size -= dbk_size;
	} else
		goto out;

	bitram_size = (128 * parm->width / 16 + 1023) & ~1023;
	if (size >= bitram_size) {
		psecAxiIramInfo->useHostBitEnable = 1;
		psecAxiIramInfo->bufBitUse = psecAxiIramInfo->bufDbkCUse + dbk_size / 2;
		size -= bitram_size;
	} else
		goto out;

	ipacdc_size = (128 * parm->width / 16 + 1023) & ~1023;
	if (size >= ipacdc_size) {
		psecAxiIramInfo->useHostIpEnable = 1;
		psecAxiIramInfo->bufIpAcDcUse = psecAxiIramInfo->bufBitUse + bitram_size;
		size -= ipacdc_size;
	} else
		goto out;

	ovl_size = (160 * parm->width / 16 + 1023) & ~1023;
	if (parm->codecMode == VC1_DEC) {
		if (size >= ovl_size) {
			psecAxiIramInfo->useHostOvlEnable = 1;
			psecAxiIramInfo->bufOvlUse = psecAxiIramInfo->bufIpAcDcUse + ipacdc_size;
			size -= ovl_size;
		}
		if (cpu_is_mx6q()) {
			btp_size = (160 * parm->width / 16 + 1023) & ~1023;
			if (size >= btp_size) {
				psecAxiIramInfo->useHostBtpEnable = 1;
				psecAxiIramInfo->bufBtpUse = psecAxiIramInfo->bufOvlUse + ovl_size;
				size -= btp_size;
			}
		}
	}
out:
	/* i.MX51 has no secondary AXI memory, but use on chip RAM
	   Set the useHoseXXX as 1 to enable corresponding IRAM
	   Set the useXXXX as 0 at the same time to use IRAM,
	   i.MX53 uses secondary AXI for IRAM access, also needs to
	   set the useXXXX. */
	if (cpu_is_mx53() || cpu_is_mx6q()) {
		/* i.MX53/i.MX6Q uses secondary AXI for IRAM access */
		psecAxiIramInfo->useBitEnable = psecAxiIramInfo->useHostBitEnable;
		psecAxiIramInfo->useIpEnable = psecAxiIramInfo->useHostIpEnable;
		psecAxiIramInfo->useDbkEnable = psecAxiIramInfo->useHostDbkEnable;
		psecAxiIramInfo->useOvlEnable = psecAxiIramInfo->useHostOvlEnable;
		psecAxiIramInfo->useBtpEnable = psecAxiIramInfo->useHostBtpEnable;
	}

	if (((parm->codecMode == VC1_DEC) && !psecAxiIramInfo->useHostOvlEnable) ||
	    !psecAxiIramInfo->useHostIpEnable)
		warn_msg("VPU iram is less than needed, some parts don't use iram\n");
}

void SetEncSecondAXIIRAM(SecAxiUse *psecAxiIramInfo, SetIramParam *parm)
{
	iram_t iram;
	int size, dbk_size, bitram_size, ipacdc_size;

	if (!parm->width) {
		err_msg("Width is zero when calling SetEncSecondAXIIRAM function\n");
		return;
	}

	memset(psecAxiIramInfo, 0, sizeof(SecAxiUse));

	IOGetIramBase(&iram);
	size = iram.end - iram.start + 1;

	if (cpu_is_mx6q()) {
		psecAxiIramInfo->searchRamSize = 0;
		psecAxiIramInfo->searchRamAddr = 0;
		goto set_dbk;
	}

	/* Setting internal iram usage per priority when iram isn't enough */
	psecAxiIramInfo->searchRamSize = (parm->width * 36 + 2048 + 1023) & ~1023;
	if (size >= psecAxiIramInfo->searchRamSize) {
		psecAxiIramInfo->useHostMeEnable = 1;
		psecAxiIramInfo->searchRamAddr = iram.start;
		size -= psecAxiIramInfo->searchRamSize;
	} else {
		err_msg("VPU iram is less than search ram size\n");
		goto out;
	}

set_dbk:
	/* Only H.264BP and H.263P3 are considered */
	dbk_size = (128 * parm->width / 16 + 1023) & ~1023;
	if (size >= dbk_size) {
		psecAxiIramInfo->useHostDbkEnable = 1;
		psecAxiIramInfo->bufDbkYUse = iram.start + psecAxiIramInfo->searchRamSize;
		psecAxiIramInfo->bufDbkCUse = psecAxiIramInfo->bufDbkYUse + dbk_size / 2;
		size -= dbk_size;
	} else
		goto out;

	bitram_size = (128 * parm->width / 16 + 1023) & ~1023;
	if (size >= bitram_size) {
		psecAxiIramInfo->useHostBitEnable = 1;
		psecAxiIramInfo->bufBitUse = psecAxiIramInfo->bufDbkCUse + dbk_size / 2;
		size -= bitram_size;
	} else
		goto out;

	ipacdc_size = (128 * parm->width / 16 + 1023) & ~1023;
	if (size >= ipacdc_size) {
		psecAxiIramInfo->useHostIpEnable = 1;
		psecAxiIramInfo->bufIpAcDcUse = psecAxiIramInfo->bufBitUse + bitram_size;
		size -= ipacdc_size;
	}

	psecAxiIramInfo->useHostOvlEnable = 0; /* no need to enable ovl in encoder */
	psecAxiIramInfo->useBtpEnable = 0;

out:
	/* i.MX51 has no secondary AXI memory, but use on chip RAM
	   Set the useHoseXXX as 1 to enable corresponding IRAM
	   Set the useXXXX as 0 at the same time to use IRAM,
	   i.MX53/i.MX6Q uses secondary AXI for IRAM access, also needs to set
	   useXXXX. */
	if (cpu_is_mx53() || cpu_is_mx6q()) {
		/* i.MX53 uses secondary AXI for IRAM access */
		psecAxiIramInfo->useBitEnable = psecAxiIramInfo->useHostBitEnable;
		psecAxiIramInfo->useIpEnable = psecAxiIramInfo->useHostIpEnable;
		psecAxiIramInfo->useDbkEnable = psecAxiIramInfo->useHostDbkEnable;
		psecAxiIramInfo->useMeEnable = psecAxiIramInfo->useHostMeEnable;
	}

	if (!psecAxiIramInfo->useHostIpEnable)
		warn_msg("VPU iram is less than needed, some parts don't use iram\n");
}

void SetMaverickCache(MaverickCacheConfig *pCacheConf, int mapType, int chromInterleave)
{
	if (mapType == LINEAR_FRAME_MAP) {
		/* Set luma */
		pCacheConf->luma.cfg.PageSizeX = 2;
		pCacheConf->luma.cfg.PageSizeY = 0;
		pCacheConf->luma.cfg.CacheSizeX = 2;
		pCacheConf->luma.cfg.CacheSizeY = 6;
		/* Set chroma */
		pCacheConf->chroma.cfg.PageSizeX = 2;
		pCacheConf->chroma.cfg.PageSizeY = 0;
		pCacheConf->chroma.cfg.CacheSizeX = 2;
		pCacheConf->chroma.cfg.CacheSizeY = 4;
		pCacheConf->PageMerge = 2;
	} else {
		/* Set luma */
		pCacheConf->luma.cfg.PageSizeX = 0;
		pCacheConf->luma.cfg.PageSizeY = 2;
		pCacheConf->luma.cfg.CacheSizeX = 4;
		pCacheConf->luma.cfg.CacheSizeY = 4;
		/* Set chroma */
		pCacheConf->chroma.cfg.PageSizeX = 0;
		pCacheConf->chroma.cfg.PageSizeY = 2;
		pCacheConf->chroma.cfg.CacheSizeX = 4;
		pCacheConf->chroma.cfg.CacheSizeY = 3;
		pCacheConf->PageMerge = 1;
	}

	pCacheConf->Bypass = 0; /* cache enable */
	pCacheConf->DualConf = 0;
	pCacheConf->LumaBufferSize = 32;
	if (chromInterleave) {
		pCacheConf->CbBufferSize = 0;
		pCacheConf->CrBufferSize = 0x10;
	} else {
		pCacheConf->CbBufferSize = 8;
		pCacheConf->CrBufferSize = 8;
	}
}

semaphore_t *vpu_semaphore_open(void)
{
	semaphore_t *semap;
	pthread_mutexattr_t psharedm;
	CodecInst *pCodecInst;
	char *timeout_env;
	int i;


	if (cpu_is_mx6q()) {
		/*
		 * Temporarily to use global variable for shared memory for mx6q now,
		 * Will fix this later since getting shared memory from kernel will
		 * make vpu hang now.
		 * And mx6q cannot support multi-instances currently.
		 * Fixme later......
		 */
		semap = &g_sema_buffer;
		goto semap_init;
	}

	share_mem.size = sizeof(semaphore_t);

	if (IOGetPhyShareMem(&share_mem)) {
		err_msg("Unable to obtain physical of share memory\n");
		return NULL;
	}

	semap = (semaphore_t *)IOGetVirtMem(&share_mem);
	if (semap == NULL) {
		err_msg("Unable to map physical of share memory\n");
		return NULL;
	}

semap_init:
	if (!semap->is_initialized) {
		pthread_mutexattr_init(&psharedm);
		pthread_mutexattr_setpshared(&psharedm, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(&semap->api_lock, &psharedm);
		pthread_mutex_init(&semap->reg_lock, &psharedm);
		for (i = 0; i < MAX_NUM_INSTANCE; ++i) {
			pCodecInst = (CodecInst *) (&semap->codecInstPool[i]);
			pCodecInst->instIndex = i;
			pCodecInst->inUse = 0;
		}
		semap->is_initialized = 1;
	}

	timeout_env = getenv("VPU_MUTEX_TIMEOUT");
	if (timeout_env == NULL)
		mutex_timeout = 10;
	else
		mutex_timeout = atoi(timeout_env);

	return semap;
}

void semaphore_post(semaphore_t *semap, int mutex)
{
	if (mutex == API_MUTEX)
		pthread_mutex_unlock(&semap->api_lock);
	else if (mutex == REG_MUTEX)
		pthread_mutex_unlock(&semap->reg_lock);
}

unsigned char semaphore_wait(semaphore_t *semap, int mutex)
{
#ifdef ANDROID
	if (mutex == API_MUTEX)
		pthread_mutex_lock(&semap->api_lock);
	else if (mutex == REG_MUTEX)
		pthread_mutex_lock(&semap->reg_lock);
	return true;
#else
	struct timespec ts;
	int ret = 0;

	ts.tv_sec = time(NULL) + mutex_timeout;
	ts.tv_nsec = 0;
	if (mutex == API_MUTEX)
		ret = pthread_mutex_timedlock(&semap->api_lock, &ts);
	else if (mutex == REG_MUTEX)
		ret = pthread_mutex_timedlock(&semap->reg_lock, &ts);
	else
		warn_msg("Not supported mutex\n");
	if (ret == ETIMEDOUT) {
		warn_msg("VPU mutex couldn't be locked before timeout expired\n");
		return false;
	}
	return true;
#endif
}

void vpu_semaphore_close(semaphore_t * semap)
{
	/* Fixme later for mx6q */
	if (cpu_is_mx6q())
	    goto ret;

	if (munmap((void *)semap, sizeof(semaphore_t)) != 0)
		err_msg("munmap share mem failed\n");
ret:
	return;
}

/* Following is MX6Q Jpg related */
#define PUT_BYTE(_p, _b) \
	    if (tot++ > len) return 0; \
		    *_p++ = (unsigned char)(_b);

int JpgEncGenHuffTab(EncInfo * pEncInfo, int tabNum)
{
	int p, i, l, lastp, si, maxsymbol;
	int huffsize[256];
	int huffcode[256];
	int code;

	Uint8 *bitleng, *huffval;
	int *ehufco, *ehufsi;

	bitleng = pEncInfo->jpgInfo.pHuffBits[tabNum];
	huffval = pEncInfo->jpgInfo.pHuffVal[tabNum];
	ehufco  = (int *)(pEncInfo->jpgInfo.huffCode[tabNum]);
	ehufsi  = (int *)(pEncInfo->jpgInfo.huffSize[tabNum]);

	maxsymbol = tabNum & 1 ? 256 : 16;

	/* Figure C.1: make table of Huffman code length for each symbol */
	p = 0;
	for (l=1; l<=16; l++) {
		i = bitleng[l-1];
		if (i < 0 || p + i > maxsymbol)
			return 0;
		while (i--)
			huffsize[p++] = l;
	}
	lastp = p;

	/* Figure C.2: generate the codes themselves */
	/* We also validate that the counts represent a legal Huffman code tree. */
	code = 0;
	si = huffsize[0];
	p = 0;
	while (p < lastp) {
		while (huffsize[p] == si) {
		huffcode[p++] = code;
		code++;
		}
		if (code >= (1 << si))
			return 0;
		code <<= 1;
		si++;
	}

	/* Figure C.3: generate encoding tables */
	/* These are code and size indexed by symbol value */
	memset(ehufsi, 0, sizeof(int) * 256);
	memset(ehufco, 0, sizeof(int) * 256);

	for (p=0; p<lastp; p++) {
		i = huffval[p];
		if (i < 0 || i >= maxsymbol || ehufsi[i])
			return 0;
		ehufco[i] = huffcode[p];
		ehufsi[i] = huffsize[p];
	}

	return 1;
}

int JpgEncLoadHuffTab(EncInfo * pEncInfo)
{
	int i, j, t;
	int huffData;

	for (i = 0; i < 4; i++)
		JpgEncGenHuffTab(pEncInfo, i);

	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0x3);

	for (j = 0; j < 4; j++) {
		t = (j == 0) ? AC_TABLE_INDEX0 : (j == 1) ?
		     AC_TABLE_INDEX1 : (j == 2) ? DC_TABLE_INDEX0 : DC_TABLE_INDEX1;

		for (i = 0; i < 256; i++) {
			if ((t == DC_TABLE_INDEX0 || t == DC_TABLE_INDEX1) && (i > 15))
				break;

			if ((pEncInfo->jpgInfo.huffSize[t][i] == 0) &&
			    (pEncInfo->jpgInfo.huffCode[t][i] == 0))
				huffData = 0;
			else {
				huffData = (pEncInfo->jpgInfo.huffSize[t][i] - 1);
				huffData = (huffData << 16) | (pEncInfo->jpgInfo.huffCode[t][i]);
			}
			VpuWriteReg(MJPEG_HUFF_DATA_REG, huffData);
		}
	}
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0x0);

	return 1;
}

int JpgEncLoadQMatTab(EncInfo * pEncInfo)
{
	long long int dividend = 0x80000;
	long long int quotient;
	int quantID, divisor, comp, i, t;

	for (comp = 0; comp < 3; comp++) {
		quantID = pEncInfo->jpgInfo.pCInfoTab[comp][3];
		if (quantID >= 4)
			return 0;
		t = (comp==0)? Q_COMPONENT0 :
		    (comp==1)? Q_COMPONENT1 : Q_COMPONENT2;
		VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x3 + t);
		for (i=0; i<64; i++) {
			divisor = pEncInfo->jpgInfo.pQMatTab[quantID][i];
			quotient= dividend / divisor;
			VpuWriteReg(MJPEG_QMAT_DATA_REG, (int) quotient);
		}
		VpuWriteReg(MJPEG_QMAT_CTRL_REG, t);
	}

	return 1;
}

int JpgEncEncodeHeader(EncHandle handle, EncParamSet * para)
{
	CodecInst *pCodecInst;
	EncInfo *pEncInfo;
	Uint8 *p;
	int i, tot, len, pad;

	tot = 0;
	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	p = para->pParaSet;
	len = para->size;

	// SOI Header
	PUT_BYTE(p, 0xff);
	PUT_BYTE(p, 0xD8);
	// APP9 Header
	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xE9);
	PUT_BYTE(p, 0x00);
	PUT_BYTE(p, 0x04);
	PUT_BYTE(p, (pEncInfo->jpgInfo.frameIdx >> 8));
	PUT_BYTE(p, (pEncInfo->jpgInfo.frameIdx & 0xFF));

	// DRI header
	if (pEncInfo->jpgInfo.rstIntval) {
		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xDD);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0x04);

		PUT_BYTE(p, (pEncInfo->jpgInfo.rstIntval >> 8));
		PUT_BYTE(p, (pEncInfo->jpgInfo.rstIntval & 0xff));
	}

	// DQT Header
	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xDB);

	PUT_BYTE(p, 0x00);
	PUT_BYTE(p, 0x43);

	PUT_BYTE(p, 0x00);

	for (i = 0; i < 64; i++)
		PUT_BYTE(p, pEncInfo->jpgInfo.pQMatTab[0][i]);

	if (pEncInfo->jpgInfo.format != CHROMA_FORMAT_400) {
		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xDB);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0x43);
		PUT_BYTE(p, 0x01);

		for (i = 0; i < 64; i++)
			PUT_BYTE(p, pEncInfo->jpgInfo.pQMatTab[1][i]);
	}

	// DHT Header
	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xC4);
	PUT_BYTE(p, 0x00);
	PUT_BYTE(p, 0x1F);
	PUT_BYTE(p, 0x00);

	for (i = 0; i < 16; i++)
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[0][i]);

	for (i = 0; i < 12; i++)
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[0][i]);

	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xC4);
	PUT_BYTE(p, 0x00);
	PUT_BYTE(p, 0xB5);
	PUT_BYTE(p, 0x10);

	for (i = 0; i < 16; i++)
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[1][i]);

	for (i = 0; i < 162; i++)
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[1][i]);

	if (pEncInfo->jpgInfo.format != CHROMA_FORMAT_400) {
		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xC4);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0x1F);
		PUT_BYTE(p, 0x01);

		for (i=0; i<16; i++)
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[2][i]);

		for (i=0; i<12; i++)
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[2][i]);

		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xC4);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0xB5);
		PUT_BYTE(p, 0x11);

		for (i = 0; i < 16; i++)
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[3][i]);

		for (i = 0; i < 162; i++)
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[3][i]);
	}

	/* SOF header */
	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xC0);
	PUT_BYTE(p, (((8+(pEncInfo->jpgInfo.compNum*3)) >> 8) & 0xFF));
	PUT_BYTE(p, ((8+(pEncInfo->jpgInfo.compNum*3)) & 0xFF));
	PUT_BYTE(p, 0x08);
	PUT_BYTE(p, (pEncInfo->jpgInfo.picHeight >> 8));
	PUT_BYTE(p, (pEncInfo->jpgInfo.picHeight & 0xFF));
	PUT_BYTE(p, (pEncInfo->jpgInfo.picWidth >> 8));
	PUT_BYTE(p, (pEncInfo->jpgInfo.picWidth & 0xFF));
	PUT_BYTE(p, pEncInfo->jpgInfo.compNum);

	for (i=0; i<pEncInfo->jpgInfo.compNum; i++) {
		PUT_BYTE(p, (i+1));
		PUT_BYTE(p, ((pEncInfo->jpgInfo.pCInfoTab[i][1]<<4) & 0xF0) +
				 (pEncInfo->jpgInfo.pCInfoTab[i][2] & 0x0F));
		PUT_BYTE(p, pEncInfo->jpgInfo.pCInfoTab[i][3]);
	}

	pad = 0;
	if (tot % 8) {
		pad = tot % 8;
		pad = 8-pad;
		for (i=0; i<pad; i++)
			PUT_BYTE(p, 0x00);
	}

	pEncInfo->jpgInfo.frameIdx++;
	para->size = tot;
	return tot;
}

RetCode JpgDecHuffTabSetUp(DecInfo *pDecInfo)
{
	int i, j, HuffData, HuffLength, temp;
	JpgDecInfo *jpg = &pDecInfo->jpgInfo;

	/* MIN Tables */
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0x003);

	/* DC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMin[0][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) |
		       (temp<<3) | (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* DC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMin[2][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp << 5) | (temp << 4) |
		       (temp << 3) | (temp << 2) | (temp << 1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* AC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMin[1][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) | (temp<<3) |
		       (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* AC Chroma */
	for(j=0; j<16; j++) {
		HuffData = jpg->huffMin[3][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) |
		       (temp<<3) | (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* MAX Tables */
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0x403);
	VpuWriteReg(MJPEG_HUFF_ADDR_REG, 0x440);

	/* DC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMax[0][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) |
		       (temp<<3) | (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* DC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMax[2][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) |
		       (temp<<3) | (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* AC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMax[1][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) | (temp<<3) |
		       (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* AC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMax[3][j];
		temp = (HuffData & 0x8000) >> 15;
		temp = (temp << 15) | (temp << 14) | (temp << 13) |
		       (temp << 12) | (temp << 11) | (temp << 10) |
		       (temp << 9) | (temp << 8) | (temp << 7 ) |
		       (temp << 6) | (temp <<5) | (temp<<4) | (temp<<3) |
		      (temp<<2) | (temp<<1)| (temp) ;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFF) << 16) | HuffData));
	}

	/* PTR Tables */
	VpuWriteReg (MJPEG_HUFF_CTRL_REG, 0x803);
	VpuWriteReg (MJPEG_HUFF_ADDR_REG, 0x880);

	/* DC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffPtr[0][j];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}

	/* DC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffPtr[2][j];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}

	/* AC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffPtr[1][j];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}

	/* AC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffPtr[3][j];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}

	/* VAL Tables */
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0xC03);

	/* VAL DC Luma */
	HuffLength = 0;
	for(i=0; i<12; i++)
		HuffLength += jpg->huffBits[0][i];

	for (i=0; i<HuffLength; i++) {
		HuffData = jpg->huffVal[0][i];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}

	for (i=0; i<12-HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* VAL DC Chroma */
	HuffLength = 0;
	for(i=0; i<12; i++)
		HuffLength += jpg->huffBits[2][i];
	for (i=0; i<HuffLength; i++) {
		HuffData = jpg->huffVal[2][i];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}
	for (i=0; i<12-HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* VAL AC Luma */
	HuffLength = 0;
	for(i=0; i<162; i++)
		HuffLength += jpg->huffBits[1][i];
	for (i=0; i<HuffLength; i++) {
		HuffData = jpg->huffVal[1][i];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}
	for (i=0; i<162-HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* VAL AC Chroma */
	HuffLength = 0;
	for (i=0; i<162; i++)
		HuffLength += jpg->huffBits[3][i];
	for (i=0; i<HuffLength; i++) {
		HuffData = jpg->huffVal[3][i];
		temp = (HuffData & 0x80) >> 7;
		temp = (temp<<23)|(temp<<22)|(temp<<21)|(temp<<20)|
		       (temp<<19)|(temp<<18)|(temp<<17)|(temp<<16)|
		       (temp<<15)|(temp<<14)|(temp<<13)|(temp<<12)|
		       (temp<<11)|(temp<<10)|(temp<<9)|(temp<<8)|
		       (temp<<7)|(temp<<6)|(temp<<5)|(temp<<4)|
		       (temp<<3)|(temp<<2)|(temp<<1)|(temp);
		VpuWriteReg (MJPEG_HUFF_DATA_REG, (((temp & 0xFFFFFF) << 8) | HuffData));
	}

	for (i=0; i<162-HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* end SerPeriHuffTab */
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0x000);

	return 1;
}

RetCode JpgDecQMatTabSetUp(DecInfo *pDecInfo)
{
	int i, table, val;
	JpgDecInfo *jpg = &pDecInfo->jpgInfo;

	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x03);
	table = jpg->cInfoTab[0][3];
	for (i=0; i<64; i++) {
		val = jpg->qMatTab[table][i];
		VpuWriteReg(MJPEG_QMAT_DATA_REG, val);
	}
	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x00);

	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x43);
	table = jpg->cInfoTab[1][3];
	for (i=0; i<64; i++) {
		val = jpg->qMatTab[table][i];
		VpuWriteReg(MJPEG_QMAT_DATA_REG, val);
	}
	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x00);

	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x83);
	table = jpg->cInfoTab[2][3];
	for (i=0; i<64; i++) {
		val = jpg->qMatTab[table][i];
		VpuWriteReg(MJPEG_QMAT_DATA_REG, val);
	}
	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x00);
	return 1;
}

void JpgDecGramSetup(DecInfo * pDecInfo)
{
	int dExtBitBufCurPos;
	int dExtBitBufBaseAddr;
	int dMibStatus;

	if (pDecInfo->jpgInfo.seqInited==1)
		return;

	dMibStatus = 1;
	dExtBitBufCurPos = 0;
	dExtBitBufBaseAddr = pDecInfo->streamBufStartAddr;

	VpuWriteReg(MJPEG_BBC_CUR_POS_REG, dExtBitBufCurPos);
	VpuWriteReg(MJPEG_BBC_EXT_ADDR_REG, dExtBitBufBaseAddr + (dExtBitBufCurPos << 8));
	VpuWriteReg(MJPEG_BBC_INT_ADDR_REG, (dExtBitBufCurPos & 1) << 6);
	VpuWriteReg(MJPEG_BBC_DATA_CNT_REG, 256 / 4);
	VpuWriteReg(MJPEG_BBC_COMMAND_REG, 0);

	while (dMibStatus == 1)
		dMibStatus = VpuReadReg(MJPEG_BBC_BUSY_REG);

	dMibStatus = 1;
	dExtBitBufCurPos = dExtBitBufCurPos + 1;

	VpuWriteReg(MJPEG_BBC_CUR_POS_REG, dExtBitBufCurPos);
	VpuWriteReg(MJPEG_BBC_EXT_ADDR_REG, dExtBitBufBaseAddr + (dExtBitBufCurPos << 8));
	VpuWriteReg(MJPEG_BBC_INT_ADDR_REG, (dExtBitBufCurPos & 1) << 6);
	VpuWriteReg(MJPEG_BBC_DATA_CNT_REG, 256 / 4);
	VpuWriteReg(MJPEG_BBC_COMMAND_REG, 0);

	while (dMibStatus == 1)
		dMibStatus = VpuReadReg(MJPEG_BBC_BUSY_REG);

	dMibStatus = 1;
	dExtBitBufCurPos = dExtBitBufCurPos + 1;

	VpuWriteReg(MJPEG_BBC_CUR_POS_REG, dExtBitBufCurPos);
	VpuWriteReg(MJPEG_BBC_CTRL_REG, 1);
	VpuWriteReg(MJPEG_GBU_WD_PTR_REG, 0);
	VpuWriteReg(MJPEG_GBU_BBSR_REG, 0);
	VpuWriteReg(MJPEG_GBU_BBER_REG, ((256 / 4) * 2) - 1);
	VpuWriteReg(MJPEG_GBU_BBIR_REG, 256 / 4);
	VpuWriteReg(MJPEG_GBU_BBHR_REG, 256 / 4);
	VpuWriteReg(MJPEG_GBU_CTRL_REG, 4);
	VpuWriteReg(MJPEG_GBU_FF_RPTR_REG, 0);

	pDecInfo->jpgInfo.seqInited=1;
}

const Uint8 cDefHuffBits[4][16] =
{
	{	/* DC index 0 (Luminance DC) */
		0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	{	/* AC index 0 (Luminance AC) */
		0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03,
		0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D
	},
	{	/* DC index 1 (Chrominance DC) */
		0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	{	/* AC index 1 (Chrominance AC) */
		0x00, 0x02, 0x01, 0x02, 0x04, 0x04, 0x03, 0x04,
		0x07, 0x05, 0x04, 0x04, 0x00, 0x01, 0x02, 0x77
	}
};

const Uint8 cDefHuffVal[4][162] =
{
	{	/* DC index 0 (Luminance DC) */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B
	},
	{	/* AC index 0 (Luminance AC) */
		0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12,
		0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
		0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
		0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
		0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16,
		0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
		0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
		0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
		0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
		0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4,
		0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
		0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
		0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
		0xF9, 0xFA
	},
	{	/* DC index 1 (Chrominance DC) */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B
	},
	{	/* AC index 1 (Chrominance AC) */
		0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21,
		0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
		0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
		0xA1, 0xB1, 0xC1, 0x09, 0x23, 0x33, 0x52, 0xF0,
		0x15, 0x62, 0x72, 0xD1, 0x0A, 0x16, 0x24, 0x34,
		0xE1, 0x25, 0xF1, 0x17, 0x18, 0x19, 0x1A, 0x26,
		0x27, 0x28, 0x29, 0x2A, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x79, 0x7A, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96,
		0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5,
		0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4,
		0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3,
		0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2,
		0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
		0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
		0xEA, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
		0xF9, 0xFA
	}
};

int check_start_code(JpgDecInfo *jpg)
{
	if (show_bits(&jpg->gbc, 8) == 0xFF)
		return 1;
	else
		return 0;
}


int find_start_code(JpgDecInfo *jpg)
{
	int word;

	while (1) {
		word = show_bits(&jpg->gbc, 16);
		if ((word > 0xFF00) && (word < 0xFFFF))
			break;

		if (get_bits_left(&jpg->gbc) <= 0)
			return 0;

		get_bits(&jpg->gbc, 8);
	}

	return 1;
}


int decode_app_header(JpgDecInfo *jpg)
{
	int length;

	length = get_bits(&jpg->gbc, 16);
	length -= 2;

	while (length-- > 0)
		get_bits(&jpg->gbc, 8);

	if (!check_start_code(jpg)) {
		find_start_code(jpg);
		return 0;
	}

	return 1;
}


int decode_dri_header(JpgDecInfo *jpg)
{
	get_bits(&jpg->gbc, 16);

	jpg->rstIntval = get_bits(&jpg->gbc, 16);

	if (!check_start_code(jpg)) {
		find_start_code(jpg);
		return 0;
	}

	return 1;
}

int decode_dqt_header(JpgDecInfo *jpg)
{
	int Pq, Tq, i;

	get_bits(&jpg->gbc, 16);

	do {
		Pq = get_bits(&jpg->gbc, 4);
		Tq = get_bits(&jpg->gbc, 4);

		for (i=0; i<64; i++)
			jpg->qMatTab[Tq][i] = get_bits(&jpg->gbc, 8);
	} while(!check_start_code(jpg));

	if (Pq != 0)
		return 0;

	return 1;
}

int decode_dth_header(JpgDecInfo *jpg)
{
	int Tc, Th, ThTc, bitCnt, i;

	get_bits(&jpg->gbc, 16);

	do {
		Tc = get_bits(&jpg->gbc, 4);
		Th = get_bits(&jpg->gbc, 4);
		ThTc = ((Th&1)<<1) | (Tc&1);

		bitCnt = 0;
		for (i=0; i<16;i++) {
			jpg->huffBits[ThTc][i] = get_bits(&jpg->gbc, 8);
			bitCnt += jpg->huffBits[ThTc][i];

			if (cDefHuffBits[ThTc][i] != jpg->huffBits[ThTc][i])
			jpg->userHuffTab = 1;
		}

		for (i=0; i<bitCnt; i++)  {
			jpg->huffVal[ThTc][i] = get_bits(&jpg->gbc, 8);

			if (cDefHuffVal[ThTc][i] != jpg->huffVal[ThTc][i])
				jpg->userHuffTab = 1;
		}
	} while(!check_start_code(jpg));

	return 1;
}

int decode_sof_header(JpgDecInfo *jpg)
{
	int samplePrecision, sampleFactor, i, Tqi, compID;
	int hSampFact[3], vSampFact[3], picX, picY, numComp;

	get_bits(&jpg->gbc, 16);
	samplePrecision = get_bits(&jpg->gbc, 8);

	if (samplePrecision != 8) {
		info_msg("Sample Precision is not 8\n");
		return 0;
	}

	picY = get_bits(&jpg->gbc, 16);
	if (picY > MAX_VSIZE) {
		info_msg("Picture Vertical Size limits Maximum size\n");
		return 0;
	}

	picX = get_bits(&jpg->gbc, 16);
	if (picX > MAX_HSIZE) {
		info_msg("Picture Horizontal Size limits Maximum size\n");
		return 0;
	}

	numComp = get_bits(&jpg->gbc, 8);
	if (numComp > 3)
		info_msg("Picture Horizontal Size limits Maximum size\n");

	for (i=0; i<numComp; i++) {
		compID = get_bits(&jpg->gbc, 8);
		hSampFact[i] = get_bits(&jpg->gbc, 4);
		vSampFact[i] = get_bits(&jpg->gbc, 4);
		Tqi = get_bits(&jpg->gbc, 8);

		jpg->cInfoTab[i][0] = compID;
		jpg->cInfoTab[i][1] = hSampFact[i];
		jpg->cInfoTab[i][2] = vSampFact[i];
		jpg->cInfoTab[i][3] = Tqi;
	}

	if ((hSampFact[0]>2) || (vSampFact[0]>2) || ((numComp == 3) &&
	    ((hSampFact[1]!=1) || (hSampFact[2]!=1) || (vSampFact[1]!=1) || (vSampFact[2]!=1))))
		info_msg("Not Supported Sampling Factor\n");

	if (numComp == 1)
		sampleFactor = SAMPLE_400;
	else
		sampleFactor = ((hSampFact[0]&3)<<2) | (vSampFact[0]&3);

	switch(sampleFactor) {
		case SAMPLE_420:
			jpg->format = CHROMA_FORMAT_420;
			break;
		case SAMPLE_H422:
			jpg->format = CHROMA_FORMAT_422;
			break;
		case SAMPLE_V422:
			jpg->format = CHROMA_FORMAT_224;
			break;
		case SAMPLE_444:
			jpg->format = CHROMA_FORMAT_444;
			break;
		default:
			jpg->format = CHROMA_FORMAT_400;
	}

	jpg->picWidth = picX;
	jpg->picHeight = picY;

	return 1;
}

int decode_sos_header(JpgDecInfo *jpg)
{
	int i, j, len, numComp, compID;
	int ss, se, ah, al;
	int dcHufTblIdx[3], acHufTblIdx[3];

	len = get_bits(&jpg->gbc, 16);

	jpg->ecsPtr = get_bits_count(&jpg->gbc)/8 + len - 2 ;

	numComp = get_bits(&jpg->gbc, 8);

	for (i=0; i<numComp; i++) {
		compID = get_bits(&jpg->gbc, 8);
		dcHufTblIdx[i] = get_bits(&jpg->gbc, 4);
		acHufTblIdx[i] = get_bits(&jpg->gbc, 4);

		for (j=0; j<numComp; j++) {
			if (compID == jpg->cInfoTab[j][0]) {
				jpg->cInfoTab[j][4] = dcHufTblIdx[i];
				jpg->cInfoTab[j][5] = acHufTblIdx[i];
			}
		}
	}

	ss = get_bits(&jpg->gbc, 8);
	se = get_bits(&jpg->gbc, 8);
	ah = get_bits(&jpg->gbc, 4);
	al = get_bits(&jpg->gbc, 4);

	if ((ss != 0) || (se != 0x3F) || (ah != 0) || (al != 0)) {
		info_msg("The Jpeg Image must be another profile\n");
		return 0;
	}

	return 1;
}

static void genDecHuffTab(JpgDecInfo *jpg, int tabNum)
{
	unsigned char *huffPtr, *huffBits;
	unsigned int *huffMax, *huffMin;

	int ptrCnt =0, huffCode = 0, zeroFlag = 0, dataFlag = 0;
	int i;

	huffBits = jpg->huffBits[tabNum];
	huffPtr = jpg->huffPtr[tabNum];
	huffMax = (unsigned int *)(jpg->huffMax[tabNum]);
	huffMin = (unsigned int *)(jpg->huffMin[tabNum]);

	for (i=0; i<16; i++) {
		if (huffBits[i]) {
			huffPtr[i] = ptrCnt;
			ptrCnt += huffBits[i];
			huffMin[i] = huffCode;
			huffMax[i] = huffCode + (huffBits[i] - 1);
			dataFlag = 1;
			zeroFlag = 0;
		} else {
			huffPtr[i] = 0xFF;
			huffMin[i] = 0xFFFF;
			huffMax[i] = 0xFFFF;
			zeroFlag = 1;
		}

		if (dataFlag == 1) {
			if (zeroFlag == 1)
				huffCode <<= 1;
			else
				huffCode = (huffMax[i] + 1) << 1;
		}
	}
}

int JpegDecodeHeader(DecInfo * pDecInfo)
{
	unsigned int code;
	int i, temp;
	JpgDecInfo *jpg = &pDecInfo->jpgInfo;
	Uint8 *b = pDecInfo->jpgInfo.pHeader;
	int size = pDecInfo->jpgInfo.headerSize;

	if (!b || !size)
		return 0;

	memset(jpg, 0x00, sizeof(JpgDecInfo));
	memset(&jpg->gbc, 0x00, sizeof(GetBitContext));

	init_get_bits(&jpg->gbc, b, size*8);

	/* Initialize component information table */
	for (i=0; i<4; i++) {
		jpg->cInfoTab[i][0] = 0;
		jpg->cInfoTab[i][1] = 0;
		jpg->cInfoTab[i][2] = 0;
		jpg->cInfoTab[i][3] = 0;
		jpg->cInfoTab[i][4] = 0;
		jpg->cInfoTab[i][5] = 0;
	}

	for (;;) {
		if (find_start_code(jpg) == 0)
			return 0;

		code = get_bits(&jpg->gbc, 16);

		switch (code) {
		case SOI_Marker:
			break;
		case JFIF_CODE:
		case EXIF_CODE:
			decode_app_header(jpg);
			break;
		case DRI_Marker:
			decode_dri_header(jpg);
			break;
		case DQT_Marker:
			decode_dqt_header(jpg);
			break;
		case DHT_Marker:
			decode_dth_header(jpg);
			break;
		case SOF_Marker:
			decode_sof_header(jpg);
			break;
		case SOS_Marker:
			decode_sos_header(jpg);
			goto DONE_DEC_HEADER;
			break;
		case EOI_Marker:
			goto DONE_DEC_HEADER;
		default:
			switch (code & 0xFFF0) {
			case 0xFFE0:
			case 0xFFF0:
				if (get_bits_left(&jpg->gbc) <=0 )
					return 0;
				else {
					decode_app_header(jpg);
					break;
				}
			default:
				info_msg("code = [%x]\n", code);
				return	0;
			}
			break;
		}
	}

DONE_DEC_HEADER:
	/* Generate Huffman table information */
	for (i=0; i<4; i++)
		genDecHuffTab(jpg, i);

	temp = jpg->cInfoTab[0][3];
	temp = temp << 1 | jpg->cInfoTab[1][3];
	temp = temp << 1 | jpg->cInfoTab[2][3];
	jpg->Qidx = temp;

	temp = jpg->cInfoTab[0][4];
	temp = temp << 1 | jpg->cInfoTab[1][4];
	temp = temp << 1 | jpg->cInfoTab[2][4];
	jpg->huffDcIdx = temp;

	temp = jpg->cInfoTab[0][5];
	temp = temp << 1 | jpg->cInfoTab[1][5];
	temp = temp << 1 | jpg->cInfoTab[2][5];
	jpg->huffAcIdx = temp;

	switch(jpg->format) {
	case CHROMA_FORMAT_420:
		jpg->busReqNum = 2;
		jpg->mcuBlockNum = 6;
		jpg->compNum = 3;
		jpg->compInfo[0] = 10;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+15)&~15);
		jpg->alignedHeight = ((jpg->picHeight+15)&~15);
		break;
	case CHROMA_FORMAT_422:
		jpg->busReqNum = 3;
		jpg->mcuBlockNum = 4;
		jpg->compNum = 3;
		jpg->compInfo[0] = 9;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+15)&~15);
		jpg->alignedHeight = ((jpg->picHeight+7)&~7);
		break;
	case CHROMA_FORMAT_224:
		jpg->busReqNum = 3;
		jpg->mcuBlockNum = 4;
		jpg->compNum = 3;
		jpg->compInfo[0] = 6;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+7)&~7);
		jpg->alignedHeight = ((jpg->picHeight+15)&~15);
		break;
	case CHROMA_FORMAT_444:
		jpg->busReqNum = 4;
		jpg->mcuBlockNum = 3;
		jpg->compNum = 3;
		jpg->compInfo[0] = 5;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+7)&~7);
		jpg->alignedHeight = ((jpg->picHeight+7)&~7);
		break;
	case CHROMA_FORMAT_400:
		jpg->busReqNum = 4;
		jpg->mcuBlockNum = 1;
		jpg->compNum = 1;
		jpg->compInfo[0] = 5;
		jpg->compInfo[1] = 0;
		jpg->compInfo[2] = 0;
		jpg->alignedWidth = ((jpg->picWidth+7)&~7);
		jpg->alignedHeight = ((jpg->picHeight+7)&~7);
		break;
	}

	return 1;
}

