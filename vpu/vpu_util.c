/*
 * Copyright (c) 2006, Chips & Media.  All rights reserved.
 *
 * Copyright (C) 2004-2016 Freescale Semiconductor, Inc.
 */

/* The following programs are the sole property of Freescale Semiconductor Inc.,
 * and contain its proprietary and confidential information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>

#include "vpu_util.h"
#include "vpu_io.h"
#include "vpu_debug.h"

#ifdef BUILD_FOR_ANDROID
#include <cutils/properties.h>
#endif

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
extern shared_mem_t *vpu_shared_mem;
static int mutex_timeout;
static int fd_share;

#ifdef BUILD_FOR_ANDROID
#define FN_SHARE "/mnt/shm/vpu"
#else
#define FN_SHARE "/dev/shm/vpu"
#endif

// thumbnail
typedef enum {
	JPG_LITTLE_ENDIAN = 0,
	JPG_BIG_ENDIAN,
} JpgEndianMode;

const char lendian[4] = {0x49, 0x49, 0x2A, 0x00};
const char bendian[4] = {0x4D, 0x4D, 0x00, 0x2A};

const char *jfif = "JFIF";
const char *jfxx = "JFXX";
const char *exif = "Exif";

#ifndef MIN
#define MIN(a, b)       (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)       (((a) > (b)) ? (a) : (b))
#endif

#define MAX_LEVEL_IDX 16
static const int g_anLevel[MAX_LEVEL_IDX] =
{
	10, 11, 11, 12, 13,
	//10, 16, 11, 12, 13,
	20, 21, 22,
	30, 31, 32,
	40, 41, 42,
	50, 51
};

static const int g_anLevelMaxMBPS[MAX_LEVEL_IDX] =
{
	1485,   1485,   3000,   6000, 11880,
	11880,  19800,  20250,
	40500,  108000, 216000,
	245760, 245760, 522240,
	589824, 983040
};

static const int g_anLevelMaxFS[MAX_LEVEL_IDX] =
{
	99,    99,   396, 396, 396,
	396,   792,  1620,
	1620,  3600, 5120,
	8192,  8192, 8704,
	22080, 36864
};

static const int g_anLevelMaxBR[MAX_LEVEL_IDX] =
{
	64,     64,   192,  384, 768,
	2000,   4000,  4000,
	10000,  14000, 20000,
	20000,  50000, 50000,
	135000, 240000
};

static const int g_anLevelSliceRate[MAX_LEVEL_IDX] =
{
	0,  0,  0,  0,  0,
	0,  0,  0,
	22, 60, 60,
	60, 24, 24,
	24, 24
};

static const int g_anLevelMaxMbs[MAX_LEVEL_IDX] =
{
	28,   28,  56, 56, 56,
	56,   79, 113,
	113, 169, 202,
	256, 256, 263,
	420, 543
};

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
	else if (strlen(fw_path) > 200) {
		err_msg("VPU_FW_PATH can have at most 200 characters\n");
		return RETCODE_FAILURE;
	} else
		strcpy(fw_name, fw_path);

	strcat(fw_name, "/");
	if (cpu_is_mx27_rev(CHIP_REV_2_0) > 0)
		strcat(fw_name, "vpu_fw_imx27_TO2.bin");
	else if (cpu_is_mx27_rev(CHIP_REV_1_0) > 0)
		strcat(fw_name, "vpu_fw_imx27_TO1.bin");
	else if cpu_is_mx6q()
		strcat(fw_name, "vpu_fw_imx6q.bin");
	else if cpu_is_mx6dl()
		strcat(fw_name, "vpu_fw_imx6d.bin");
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

	if (cpu_is_mx6x()) {
		ret = fread(pBitCode, sizeof(Uint16), MAX_FW_BINARY_LEN, fp);
		*size = ret;
	}
	else {
		ret = fread(&info, sizeof(headerInfo), 1, fp);

		if (info.size > MAX_FW_BINARY_LEN) {
			err_msg("Size in VPU header is too large.Size: %d\n",
					(Uint16) info.size);
			goto err;
		}

		ret = fread(pBitCode, sizeof(Uint16), info.size, fp);
		if (ret < (int)info.size) {
			err_msg("VPU firmware binary file is wrong or corrupted.\n");
			goto err;
		}

		memset(temp_str, 0, 64);
		sprintf(temp_str, "%2x", mxc_cpu());
		if (strcmp(temp_str, "63") == 0)
			strcpy(temp_str, "6Q");
		else if (strcmp(temp_str, "61") == 0)
			strcpy(temp_str, "6D");

		info.platform[sizeof(info.platform) - 1] = '\0';
		if (strstr((char *)info.platform, temp_str) == NULL) {
			err_msg("VPU firmware platform version isn't matched\n");
			goto err;
		}

		*size = (int)info.size;
	}
	fclose(fp);
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
	if (cpu_is_mx6x()) {
		memcpy(virt_codeBuf, bit_code, size*2);
	} else {
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
		pCodecInst = (CodecInst *) (&vpu_shared_mem->codecInstPool[i]);
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
		pCodecInst = (CodecInst *) (&vpu_shared_mem->codecInstPool[i]);
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
	} else if (cpu_is_mx6x()) {
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

#ifdef MEM_PROTECT
int SetDecWriteProtectRegions(CodecInst *inst)
{
	int i;
	WriteMemProtectCfg *pCfg = NULL;
	Uint32 regionEnable = 0;

	pCfg = &inst->CodecInfo.decInfo.writeMemProtectCfg;

	for (i=0; i < sizeof(pCfg->region) / sizeof(pCfg->region[0]); i++)
	{
		WriteMemProtectRegion *p = &pCfg->region[i];
		int enable               = p->enable != 0;
		int isSecondary          = p->is_secondary != 0;

		regionEnable |= (enable << i);
		regionEnable |= (isSecondary << (i + 6));
		VpuWriteReg(GDI_WPROT_RGN0_STA + 8*i, p->start_address         >> 12);	/* round down */
		VpuWriteReg(GDI_WPROT_RGN0_END + 8*i, (p->end_address + 0xFFF) >> 12);	/* round up */
	}
	VpuWriteReg(GDI_WPROT_RGN_EN, regionEnable);
	return 1;
}
#endif

void BitIssueCommand(CodecInst *pCodecInst, int cmd)
{
	int instIdx = MAX_NUM_INSTANCE, cdcMode = 0, auxMode = 0;

	LockVpuReg(vpu_semap);

	dprintf(4, "BitIssueCommand %d\n", cmd);

	if (pCodecInst != NULL) {
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
		VpuWriteReg(BIT_WORK_BUF_ADDR, pCodecInst->contextBufMem.phy_addr);
		instIdx = pCodecInst->instIndex;
		cdcMode = pCodecInst->codecMode;
		auxMode = pCodecInst->codecModeAux;

		if (cpu_is_mx6x()) {
			VpuWriteReg(GDI_WPROT_ERR_CLR, 1);
			VpuWriteReg(GDI_WPROT_RGN_EN, 0);
#ifdef MEM_PROTECT
			SetDecWriteProtectRegions(pCodecInst);
#endif
		}
	}

	VpuWriteReg(BIT_BUSY_FLAG, 0x1);
	VpuWriteReg(BIT_RUN_INDEX, instIdx);
	VpuWriteReg(BIT_RUN_COD_STD, cdcMode);
	VpuWriteReg(BIT_RUN_AUX_STD, auxMode);
	dump_regs(0, 128);
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

		if (param->avc_frameCroppingFlag != 0 &&
		    param->avc_frameCroppingFlag != 1) {
			return RETCODE_INVALID_PARAM;
		}

		if (param->avc_frameCropLeft & 0x01 ||
		    param->avc_frameCropRight & 0x01 ||
		    param->avc_frameCropTop & 0x01 ||
		    param->avc_frameCropBottom & 0x01) {
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
	int data = 0, frameCroppingFlag = 0;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	IOClkGateSet(true);
	if (cpu_is_mx6x() && (pEncInfo->ringBufferEnable == 0)) {
		VpuWriteReg(CMD_ENC_HEADER_BB_START, pEncInfo->streamBufStartAddr);
		VpuWriteReg(CMD_ENC_HEADER_BB_SIZE, pEncInfo->streamBufSize / 1024);
	} else if (!cpu_is_mx6x() && (pEncInfo->dynamicAllocEnable == 1)) {
		VpuWriteReg(CMD_ENC_HEADER_BB_START, encHeaderParam->buf);
		VpuWriteReg(CMD_ENC_HEADER_BB_SIZE, encHeaderParam->size);
	}

	if (cpu_is_mx6x() && (encHeaderParam->headerType == 0) &&
	    (pEncInfo->openParam.bitstreamFormat == STD_AVC)) {
		EncOpenParam *encOP;
		Uint32 CropV, CropH;

		encOP = &(pEncInfo->openParam);
		if (encOP->EncStdParam.avcParam.avc_frameCroppingFlag == 1) {
			frameCroppingFlag = 1;
			CropH = encOP->EncStdParam.avcParam.avc_frameCropLeft << 16;
			CropH |= encOP->EncStdParam.avcParam.avc_frameCropRight;
			CropV = encOP->EncStdParam.avcParam.avc_frameCropTop << 16;
			CropV |= encOP->EncStdParam.avcParam.avc_frameCropBottom;
			VpuWriteReg(CMD_ENC_HEADER_FRAME_CROP_H, CropH);
			VpuWriteReg(CMD_ENC_HEADER_FRAME_CROP_V, CropV);
		}
	}

	if (cpu_is_mx6x()) {
		VpuWriteReg(CMD_ENC_HEADER_CODE, encHeaderParam->headerType |
			frameCroppingFlag << 3);
	} else {
		if (encHeaderParam->headerType == VOS_HEADER ||
		    encHeaderParam->headerType == SPS_RBSP) {
			data = (((encHeaderParam->userProfileLevelIndication & 0xFF) << 8) |
				((encHeaderParam->userProfileLevelEnable & 0x01) << 4) |
				(encHeaderParam->headerType & 0x0F));
			VpuWriteReg(CMD_ENC_HEADER_CODE, data);
		} else {
			VpuWriteReg(CMD_ENC_HEADER_CODE, encHeaderParam->headerType); /* 0: SPS, 1: PPS */
		}
	}

	BitIssueCommand(pCodecInst, ENCODE_HEADER);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	IOClkGateSet(false);

	LockVpuReg(vpu_semap);
	if ((cpu_is_mx6x() && (pEncInfo->ringBufferEnable == 0)) ||
	    (!cpu_is_mx6x() && (pEncInfo->dynamicAllocEnable == 1))) {
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

	if (cpu_is_mx6x()) {
		if (pop->bitstreamBuffer % 512) { /* not 512-byte aligned */
			return RETCODE_INVALID_PARAM;
		}
	} else {
		if (pop->bitstreamBuffer % 8) {	/* not 8-byte aligned */
			return RETCODE_INVALID_PARAM;
		}
	}

	if (cpu_is_mx6x() & (pop->bitstreamFormat == STD_MJPG)) {
		if (!pop->jpgLineBufferMode) {
			if (pop->bitstreamBufferSize % 1024 ||
			    pop->bitstreamBufferSize < 1024)
				return RETCODE_INVALID_PARAM;
		}
	} else if (pop->bitstreamBufferSize % 1024 ||
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
	} else if (cpu_is_mx6x()) {
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
		if (pop->filePlayEnable) {
			err_msg("Not support file play mode and prescan of mx6 vpu\n");
			return RETCODE_INVALID_PARAM;
		}
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
	int frameCroppingFlag = 0;

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	IOClkGateSet(true);

	if (cpu_is_mx6x() && (paraSetType == 0) &&
	    (pEncInfo->openParam.bitstreamFormat == STD_AVC)) {
		EncOpenParam *encOP;
		Uint32 CropV, CropH;

		encOP = &(pEncInfo->openParam);
		if (encOP->EncStdParam.avcParam.avc_frameCroppingFlag == 1) {
			frameCroppingFlag = 1;
			CropH = encOP->EncStdParam.avcParam.avc_frameCropLeft << 16;
			CropH |= encOP->EncStdParam.avcParam.avc_frameCropRight;
			CropV = encOP->EncStdParam.avcParam.avc_frameCropTop << 16;
			CropV |= encOP->EncStdParam.avcParam.avc_frameCropBottom;
			VpuWriteReg(CMD_ENC_HEADER_FRAME_CROP_H, CropH);
			VpuWriteReg(CMD_ENC_HEADER_FRAME_CROP_V, CropV);
		}
	}

	/* SPS: 0, PPS: 1, VOS: 1, VO: 2, VOL: 0 */
	VpuWriteReg(CMD_ENC_PARA_SET_TYPE, paraSetType | (frameCroppingFlag << 2));
	BitIssueCommand(pCodecInst, ENC_PARA_SET);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;

	para->paraSet = virt_paraBuf;
	para->size = VpuReadReg(RET_ENC_PARA_SET_SIZE);

	IOClkGateSet(false);
}

void SetParaSet(DecHandle handle, int paraSetType, DecParamSet * para)
{
	CodecInst *pCodecInst;
	int i;
	Uint32 *src;
	int byteSize;

	pCodecInst = handle;

	src = para->paraSet;
	byteSize = para->size / 4;

	for (i = 0; i < byteSize; i += 1) {
		virt_paraBuf[i] = *src++;
	}

	IOClkGateSet(true);

	VpuWriteReg(CMD_DEC_PARA_SET_TYPE, paraSetType);
	VpuWriteReg(CMD_DEC_PARA_SET_SIZE, para->size);

	BitIssueCommand(pCodecInst, DEC_PARA_SET);
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
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

RetCode SetIntraRefreshNum(EncHandle handle, Uint32 * pIntraRefreshNum)
{
	CodecInst *pCodecInst;
	Uint32 intraRefreshNum = *pIntraRefreshNum;
	int data = 0;
	EncInfo *pEncInfo;

	IOClkGateSet(true);

	pCodecInst = handle;
	pEncInfo = &pCodecInst->CodecInfo.encInfo;

	data = 1 << 4;
	VpuWriteReg(CMD_ENC_SEQ_PARA_CHANGE_ENABLE, data);
	data = intraRefreshNum;
	if (intraRefreshNum > 0)
		data |= pEncInfo->intraRefreshMode << 16;
	VpuWriteReg(CMD_ENC_SEQ_PARA_INTRA_MB_NUM, data);
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
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
	BitIssueCommand(pCodecInst, RC_CHANGE_PARAMETER);
	while (VpuReadReg(BIT_BUSY_FLAG)) ;
	IOClkGateSet(false);

	return RETCODE_SUCCESS;
}

void SetDecSecondAXIIRAM(SecAxiUse *psecAxiIramInfo, SetIramParam *parm)
{
	iram_t iram;
	int size, dbk_size, bitram_size, ipacdc_size, ovl_size, btp_size;
	int mbNumX, mbNumY;

	if (!parm->width) {
		err_msg("Width is zero when calling SetDecSecondAXIIRAM function\n");
		return;
	}

	memset(psecAxiIramInfo, 0, sizeof(SecAxiUse));

	if (IOGetIramBase(&iram)) {
		iram.start = 0;
		iram.end = 0;
	}
	size = iram.end - iram.start + 1;

	mbNumX = (parm->width + 15 ) / 16;
	mbNumY = (parm->height + 15 ) / 16;

	/* Setting internal iram usage per priority when iram isn't enough */
	if ((parm->codecMode == VC1_DEC) && (parm->profile == 2))
		dbk_size = (512 * mbNumX + 1023) & ~1023;
	else
		dbk_size = (256 * mbNumX + 1023) & ~1023;

	if (size >= dbk_size) {
		psecAxiIramInfo->useHostDbkEnable = 1;
		psecAxiIramInfo->bufDbkYUse = iram.start;
		psecAxiIramInfo->bufDbkCUse = iram.start + dbk_size / 2;
		size -= dbk_size;
	} else
		goto out;

	bitram_size = (128 * mbNumX + 1023) & ~1023;
	if (size >= bitram_size) {
		psecAxiIramInfo->useHostBitEnable = 1;
		psecAxiIramInfo->bufBitUse = psecAxiIramInfo->bufDbkCUse + dbk_size / 2;
		size -= bitram_size;
	} else
		goto out;

	ipacdc_size = (128 * mbNumX + 1023) & ~1023;
	if (size >= ipacdc_size) {
		psecAxiIramInfo->useHostIpEnable = 1;
		psecAxiIramInfo->bufIpAcDcUse = psecAxiIramInfo->bufBitUse + bitram_size;
		size -= ipacdc_size;
	} else
		goto out;

	ovl_size = (80 * mbNumX + 1023) & ~1023;
	if (parm->codecMode == VC1_DEC) {
		if (size >= ovl_size) {
			psecAxiIramInfo->useHostOvlEnable = 1;
			psecAxiIramInfo->bufOvlUse = psecAxiIramInfo->bufIpAcDcUse + ipacdc_size;
			size -= ovl_size;
		} else
			goto out;
		if (cpu_is_mx6x()) {
			btp_size = ((((mbNumX + 15) / 16) * mbNumY + 1) * 6 + 255) & ~255;
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
	if (cpu_is_mx53() || cpu_is_mx6x()) {
		/* i.MX53/i.MX6 uses secondary AXI for IRAM access */
		psecAxiIramInfo->useBitEnable = psecAxiIramInfo->useHostBitEnable;
		psecAxiIramInfo->useIpEnable = psecAxiIramInfo->useHostIpEnable;
		psecAxiIramInfo->useDbkEnable = psecAxiIramInfo->useHostDbkEnable;
		psecAxiIramInfo->useOvlEnable = psecAxiIramInfo->useHostOvlEnable;
		psecAxiIramInfo->useBtpEnable = psecAxiIramInfo->useHostBtpEnable = 0;
	}

	if (((parm->codecMode == VC1_DEC) && !psecAxiIramInfo->useHostOvlEnable) ||
	    !psecAxiIramInfo->useHostIpEnable)
		warn_msg("VPU iram is less than needed, some parts don't use iram\n");
}

void SetEncSecondAXIIRAM(SecAxiUse *psecAxiIramInfo, SetIramParam *parm)
{
	iram_t iram;
	int size, dbk_size, bitram_size, ipacdc_size, mbNumX;

	if (!parm->width) {
		err_msg("Width is zero when calling SetEncSecondAXIIRAM function\n");
		return;
	}

	memset(psecAxiIramInfo, 0, sizeof(SecAxiUse));

	if (IOGetIramBase(&iram)) {
		iram.start = 0;
		iram.end = 0;
	}
	size = iram.end - iram.start + 1;

	mbNumX = (parm->width + 15 ) / 16;

	if (cpu_is_mx6x()) {
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
	dbk_size = (128 * mbNumX + 1023) & ~1023;
	if (size >= dbk_size) {
		psecAxiIramInfo->useHostDbkEnable = 1;
		psecAxiIramInfo->bufDbkYUse = iram.start + psecAxiIramInfo->searchRamSize;
		psecAxiIramInfo->bufDbkCUse = psecAxiIramInfo->bufDbkYUse + dbk_size / 2;
		size -= dbk_size;
	} else
		goto out;

	bitram_size = (128 * mbNumX + 1023) & ~1023;
	if (size >= bitram_size) {
		psecAxiIramInfo->useHostBitEnable = 1;
		psecAxiIramInfo->bufBitUse = psecAxiIramInfo->bufDbkCUse + dbk_size / 2;
		size -= bitram_size;
	} else
		goto out;

	ipacdc_size = (128 * mbNumX + 1023) & ~1023;
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
	   i.MX53/i.MX6 uses secondary AXI for IRAM access, also needs to set
	   useXXXX. */
	if (cpu_is_mx53() || cpu_is_mx6x()) {
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

static void *get_shared_buf(int size, int create) {
	int ret;
	void *buf;

	if (create) {
		fd_share = open(FN_SHARE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if(-1 == (ret = fd_share)) {
			perror("open failed");
			return NULL;
		}

		ret = chmod(FN_SHARE, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		if(-1 == ret) {
			perror("chmod failed");
		}

		ret = ftruncate(fd_share, size);
		if(-1 == ret) {
			perror("ftruncate failed");
			return NULL;
		}

		buf = (void *)mmap(NULL, size, PROT_READ|PROT_WRITE,
				MAP_SHARED, fd_share, SEEK_SET);
		if(NULL == buf)
			perror("mmap failed");

		memset(buf, 0, size);

		return buf;
	} else {
		fd_share = open(FN_SHARE, O_RDWR, S_IRUSR|S_IWUSR);
		if(-1 == (ret = fd_share)) {
			perror("open failed");
			return NULL;
		}

		buf = (void *)mmap(NULL, size, PROT_READ|PROT_WRITE,
				MAP_SHARED, fd_share, SEEK_SET);
		if(NULL == buf)
			perror("mmap failed");
		return buf;
	}
}

static void release_shared_buf(void *buf, int size, int destroy) {
	int ret;

	ret = munmap(buf, size);
	if(-1 == ret)
		perror("munmap failed");

	ret = close(fd_share);
	if(-1 == ret)
		perror("close failed");
}

shared_mem_t *vpu_semaphore_open(void)
{
	shared_mem_t *shared_mem;
	pthread_mutexattr_t psharedm;
#ifdef FIFO_MUTEX
	pthread_condattr_t psharedc;
#endif
	CodecInst *pCodecInst;
	char *timeout_env;
	int i;

	/* Use vmalloced share memory for all platforms */
	shared_mem = (shared_mem_t *)IOGetVShareMem(sizeof(shared_mem_t));
	if (!shared_mem) {
		err_msg("Unable to Get VShare memory\n");
		return NULL;
	}

	IOLockDev(1);

	vpu_semap = (semaphore_t *)get_shared_buf(sizeof(semaphore_t), !shared_mem->is_initialized);
	if (vpu_semap == NULL) {
		munmap((void *)shared_mem, sizeof(shared_mem_t));
		IOLockDev(0);
		return NULL;
	}

	if (!shared_mem->is_initialized) {
		dprintf(4, "sema not init\n");
		pthread_mutexattr_init(&psharedm);
		pthread_mutexattr_setpshared(&psharedm, PTHREAD_PROCESS_SHARED);
#ifndef BUILD_FOR_ANDROID
		pthread_mutexattr_setrobust(&psharedm, PTHREAD_MUTEX_ROBUST);
#endif
#ifdef FIFO_MUTEX
		pthread_mutex_init(&vpu_semap->api_lock.mutex, &psharedm);
		pthread_condattr_init(&psharedc);
		pthread_condattr_setpshared(&psharedc, PTHREAD_PROCESS_SHARED);
		pthread_cond_init(&vpu_semap->api_lock.cond, &psharedc);
		vpu_semap->api_lock.ts_late = 0;
		vpu_semap->api_lock.locked = 0;
		vpu_semap->api_lock.buf_head = 0;
		vpu_semap->api_lock.buf_tail = -1;
		for (i=0; i<MAX_ITEM_NUM; i++)
			vpu_semap->api_lock.ts_buf[i].inUse = 0;
#else
		pthread_mutex_init(&vpu_semap->api_lock, &psharedm);
#endif
		pthread_mutex_init(&vpu_semap->reg_lock, &psharedm);
		for (i = 0; i < MAX_NUM_INSTANCE; ++i) {
			pCodecInst = (CodecInst *) (&shared_mem->codecInstPool[i]);
			pCodecInst->instIndex = i;
			pCodecInst->inUse = 0;
		}
		shared_mem->is_initialized = 1;
		dprintf(4, "sema inited\n");
	}

	shared_mem->numInst++;
	IOLockDev(0);

	timeout_env = getenv("VPU_MUTEX_TIMEOUT");
	if (timeout_env == NULL)
		mutex_timeout = 10;
	else
		mutex_timeout = atoi(timeout_env);

	return shared_mem;
}

#ifdef FIFO_MUTEX
static inline int get_free_idx(ts_item_t *ts_buf)
{
	int i;

	for (i=0; i<MAX_ITEM_NUM; i++) {
		if (!ts_buf[i].inUse)
			break;
	}
	if (i == MAX_ITEM_NUM) {
		err_msg("no free idx\n");
		i = -1;
	}
	return i;
}

static inline int get_ts_early(fifo_mutex_t *fifo_mutex)
{
	int ts = -1;

	if (fifo_mutex->buf_tail != -1)
		ts = fifo_mutex->ts_buf[fifo_mutex->buf_head].ts;
	return ts;
}

static inline int is_ts_ok(int ts, fifo_mutex_t *fifo_mutex)
{
	int ts_early;
	int ret = 0;

	ts_early = get_ts_early(fifo_mutex);
	if (ts_early == -1)
		ret = 1;
	else if (ts_early <= ts) {
		if (ts - ts_early < MAX_REORDER)
			ret = 1;
	} else {
		if (ts + MAX_TS - ts_early < MAX_REORDER)
			ret = 1;
	}
	return ret;
}

static inline int enqueue_ts(int ts, fifo_mutex_t *fifo_mutex)
{
	int idx;

	if (fifo_mutex->buf_tail == -1) {
		idx = fifo_mutex->buf_head;
	} else {
		idx = get_free_idx(fifo_mutex->ts_buf);
		if (idx < 0)
			return -1;
		fifo_mutex->ts_buf[fifo_mutex->buf_tail].next = idx;
	}
	fifo_mutex->ts_buf[idx].ts = ts;
	fifo_mutex->ts_buf[idx].inUse = 1;
	fifo_mutex->ts_buf[idx].prev = fifo_mutex->buf_tail;
	fifo_mutex->ts_buf[idx].next = -1;
	fifo_mutex->buf_tail = idx;
	return idx;
}

static inline void dequeue_ts(int index, fifo_mutex_t *fifo_mutex)
{
	int prev;
	int next;

	fifo_mutex->ts_buf[index].inUse = 0;
	prev = fifo_mutex->ts_buf[index].prev;
	next = fifo_mutex->ts_buf[index].next;

	if ((prev == -1) && (next != -1))
		fifo_mutex->buf_head = next;

	if (index == fifo_mutex->buf_tail)
		fifo_mutex->buf_tail = prev;

	if (prev != -1)
		fifo_mutex->ts_buf[prev].next = next;

	if (next != -1)
		fifo_mutex->ts_buf[next].prev = prev;
}

static int fifo_mutex_timedlock(fifo_mutex_t *fifo_mutex, struct timespec *ts)
{
	int ret = 0;
	int ts_curr;
	int idx = -1;

	pthread_mutex_lock(&fifo_mutex->mutex);
	ts_curr = fifo_mutex->ts_late++;
	if (fifo_mutex->ts_late == MAX_TS)
		fifo_mutex->ts_late = 0;

	while (fifo_mutex->locked || !is_ts_ok(ts_curr, fifo_mutex)) {
		if (idx == -1) {
			idx = enqueue_ts(ts_curr, fifo_mutex);
			if (idx < 0)
				return -1;
		}
		pthread_cond_wait(&fifo_mutex->cond, &fifo_mutex->mutex);
	}

	if (idx != -1)
		dequeue_ts(idx, fifo_mutex);
	fifo_mutex->locked = 1;
	pthread_mutex_unlock(&fifo_mutex->mutex);
	return ret;
}

static void fifo_mutex_unlock(fifo_mutex_t *fifo_mutex)
{
	pthread_mutex_lock(&fifo_mutex->mutex);
	fifo_mutex->locked = 0;
	pthread_cond_broadcast(&fifo_mutex->cond);
	pthread_mutex_unlock(&fifo_mutex->mutex);
}
#endif

void semaphore_post(semaphore_t *semap, int mutex)
{
	if (mutex == API_MUTEX)
#ifdef FIFO_MUTEX
		fifo_mutex_unlock(&semap->api_lock);
#else
		pthread_mutex_unlock(&semap->api_lock);
#endif
	else if (mutex == REG_MUTEX)
		pthread_mutex_unlock(&semap->reg_lock);
}

unsigned char semaphore_wait(semaphore_t *semap, int mutex)
{
	int ret = -1;

#ifdef BUILD_FOR_ANDROID
	unsigned int msec = mutex_timeout * 1000;

	if (mutex == API_MUTEX)
		ret = pthread_mutex_lock_timeout_np(&semap->api_lock, msec);
	else if (mutex == REG_MUTEX)
		ret = pthread_mutex_lock_timeout_np(&semap->reg_lock, msec);
	else
		err_msg("Not supported mutex\n");
	if (ret) {
		err_msg("VPU mutex couldn't be locked,ret = %d\n", ret);
		return false;
	}
	return true;
#else
	struct timespec ts;

	ts.tv_sec = time(NULL) + mutex_timeout;
	ts.tv_nsec = 0;
	if (mutex == API_MUTEX)
#ifdef FIFO_MUTEX
		ret = fifo_mutex_timedlock(&semap->api_lock, &ts);
#else
	{
		ret = pthread_mutex_timedlock(&semap->api_lock, &ts);
#ifndef BUILD_FOR_ANDROID
		if (ret == EOWNERDEAD) {
			pthread_mutex_consistent(&semap->api_lock);
			ret = 0;
		}
#endif
	}
#endif
	else if (mutex == REG_MUTEX)
		ret = pthread_mutex_timedlock(&semap->reg_lock, &ts);
	else
		warn_msg("Not supported mutex\n");
	if (ret) {
		warn_msg("VPU mutex couldn't be locked before timeout expired or get lock failure %d\n", ret);
		return false;
	}
	return true;
#endif
}

void vpu_semaphore_close(shared_mem_t * shared_mem)
{
	IOLockDev(1);

	shared_mem->numInst--;

	release_shared_buf(vpu_semap, sizeof(semaphore_t), shared_mem->numInst == 0);

	if (shared_mem->numInst == 0)
		shared_mem->is_initialized = 0;

	if (munmap((void *)shared_mem, sizeof(shared_mem_t)) != 0)
		err_msg("munmap share mem failed\n");

	IOLockDev(0);

	return;
}

/* Following is MX6 Jpg related */
#define PUT_BYTE(_p, _b) \
	    if (tot++ > len) return 0; \
		    *_p++ = (unsigned char)(_b);

int vpu_mx6_swreset(int forcedReset)
{
	volatile int i;
	Uint32 cmd;
	unsigned long instIndexSave;

	instIndexSave = VpuReadReg(BIT_RUN_INDEX);
	if (forcedReset == 0) {
		VpuWriteReg(GDI_BUS_CTRL, 0x11);
		while (VpuReadReg(GDI_BUS_STATUS) != 0x77);
	}

	cmd =  VPU_SW_RESET_BPU_CORE | VPU_SW_RESET_BPU_BUS;
	cmd |= VPU_SW_RESET_VCE_CORE | VPU_SW_RESET_VCE_BUS;
	VpuWriteReg(BIT_SW_RESET, cmd);
	/* delay more than 64 vpu cycles */
	for (i = 0; i < 50; i++);
	while(VpuReadReg(BIT_SW_RESET_STATUS) != 0);

	VpuWriteReg(BIT_SW_RESET, 0);
	if (forcedReset == 0)
		VpuWriteReg(GDI_BUS_CTRL, 0x00);
	VpuWriteReg(BIT_RUN_INDEX, instIndexSave);
	return RETCODE_SUCCESS;
}

int vpu_mx6_hwreset()
{
	unsigned long instIndexSave;

	instIndexSave = VpuReadReg(BIT_RUN_INDEX);
	VpuWriteReg(GDI_BUS_CTRL, 0x11);
	while (VpuReadReg(GDI_BUS_STATUS) != 0x77);
	IOSysSWReset();

	VpuWriteReg(GDI_BUS_CTRL, 0x00);
	VpuWriteReg(BIT_BUSY_FLAG, 1);
	VpuWriteReg(BIT_CODE_RUN, 1);
	while (VpuReadReg(BIT_BUSY_FLAG));
	VpuWriteReg(BIT_RUN_INDEX, instIndexSave);

	return RETCODE_SUCCESS;
}

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
		for (i = 0; i < 64; i++) {
			divisor = pEncInfo->jpgInfo.pQMatTab[quantID][i];
			quotient= dividend / divisor;
			VpuWriteReg(MJPEG_QMAT_DATA_REG, (int) quotient);
		}
		VpuWriteReg(MJPEG_QMAT_CTRL_REG, t);
	}

	return 1;
}

int JpgEncEncodeHeader(EncHandle handle, EncParamSet *para)
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
	PUT_BYTE(p, 0xFF);
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

	for (i = 0; i < 64; i++) {
		PUT_BYTE(p, pEncInfo->jpgInfo.pQMatTab[0][i]);
	}
	if (pEncInfo->jpgInfo.format != FORMAT_400) {
		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xDB);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0x43);
		PUT_BYTE(p, 0x01);

		for (i = 0; i < 64; i++) {
			PUT_BYTE(p, pEncInfo->jpgInfo.pQMatTab[1][i]);
		}
	}

	// DHT Header
	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xC4);
	PUT_BYTE(p, 0x00);
	PUT_BYTE(p, 0x1F);
	PUT_BYTE(p, 0x00);

	for (i = 0; i < 16; i++) {
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[0][i]);
	}

	for (i = 0; i < 12; i++) {
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[0][i]);
	}

	PUT_BYTE(p, 0xFF);
	PUT_BYTE(p, 0xC4);
	PUT_BYTE(p, 0x00);
	PUT_BYTE(p, 0xB5);
	PUT_BYTE(p, 0x10);

	for (i = 0; i < 16; i++) {
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[1][i]);
	}

	for (i = 0; i < 162; i++) {
		PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[1][i]);
	}

	if (pEncInfo->jpgInfo.format != FORMAT_400) {
		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xC4);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0x1F);
		PUT_BYTE(p, 0x01);

		for (i=0; i<16; i++) {
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[2][i]);
		}
		for (i=0; i<12; i++) {
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[2][i]);
		}

		PUT_BYTE(p, 0xFF);
		PUT_BYTE(p, 0xC4);
		PUT_BYTE(p, 0x00);
		PUT_BYTE(p, 0xB5);
		PUT_BYTE(p, 0x11);

		for (i = 0; i < 16; i++) {
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffBits[3][i]);
		}

		for (i = 0; i < 162; i++) {
			PUT_BYTE(p, pEncInfo->jpgInfo.pHuffVal[3][i]);
		}
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
		PUT_BYTE(p, (i + 1));
		PUT_BYTE(p, ((pEncInfo->jpgInfo.pCInfoTab[i][1]<<4) & 0xF0) +
				 (pEncInfo->jpgInfo.pCInfoTab[i][2] & 0x0F));
		PUT_BYTE(p, pEncInfo->jpgInfo.pCInfoTab[i][3]);
	}

	if(pEncInfo->jpgInfo.enableSofStuffing) {
		pad = 0;
		if (tot % 8) {
			pad = tot % 8;
			pad = 8 - pad;
			for (i = 0; i < pad; i++) {
				PUT_BYTE(p, 0x00);
			}
		}
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
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffMin[0][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* DC Chroma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffMin[2][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* AC Luma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffMin[1][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* AC Chroma */
	for(j = 0; j < 16; j++) {
		HuffData = jpg->huffMin[3][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* MAX Tables */
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0x403);
	VpuWriteReg(MJPEG_HUFF_ADDR_REG, 0x440);

	/* DC Luma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffMax[0][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* DC Chroma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffMax[2][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* AC Luma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMax[1][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* AC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffMax[3][j];
		temp = ((HuffData & 0x8000) != 0) ? 0xFFFF0000 + HuffData : HuffData & 0xFFFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* PTR Tables */
	VpuWriteReg (MJPEG_HUFF_CTRL_REG, 0x803);
	VpuWriteReg (MJPEG_HUFF_ADDR_REG, 0x880);

	/* DC Luma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffPtr[0][j];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* DC Chroma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffPtr[2][j];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* AC Luma */
	for (j = 0; j < 16; j++) {
		HuffData = jpg->huffPtr[1][j];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* AC Chroma */
	for (j=0; j<16; j++) {
		HuffData = jpg->huffPtr[3][j];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}

	/* VAL Tables */
	VpuWriteReg(MJPEG_HUFF_CTRL_REG, 0xC03);

	/* VAL DC Luma */
	HuffLength = 0;
	for(i = 0; i < 12; i++)
		HuffLength += jpg->huffBits[0][i];

	if (HuffLength > HUFF_VAL_SIZE)
		HuffLength = HUFF_VAL_SIZE;

	for (i = 0; i < HuffLength; i++) {
		HuffData = jpg->huffVal[0][i];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}
	for (i = 0; i < 12 - HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* VAL DC Chroma */
	HuffLength = 0;
	for(i = 0; i < 12; i++)
		HuffLength += jpg->huffBits[2][i];
	if (HuffLength > HUFF_VAL_SIZE)
		HuffLength = HUFF_VAL_SIZE;
	for (i = 0; i < HuffLength; i++) {
		HuffData = jpg->huffVal[2][i];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}
	for (i = 0; i < 12 - HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* VAL AC Luma */
	HuffLength = 0;
	for(i = 0; i < HUFF_VAL_SIZE; i++)
		HuffLength += jpg->huffBits[1][i];
	if (HuffLength > HUFF_VAL_SIZE)
		HuffLength = HUFF_VAL_SIZE;
	for (i = 0; i < HuffLength; i++) {
		HuffData = jpg->huffVal[1][i];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}
	for (i = 0; i < 162 - HuffLength; i++)
		VpuWriteReg(MJPEG_HUFF_DATA_REG, 0xFFFFFFFF);

	/* VAL AC Chroma */
	HuffLength = 0;
	for (i = 0; i < HUFF_VAL_SIZE; i++)
		HuffLength += jpg->huffBits[3][i];
	if (HuffLength > HUFF_VAL_SIZE)
		HuffLength = HUFF_VAL_SIZE;
	for (i = 0; i < HuffLength; i++) {
		HuffData = jpg->huffVal[3][i];
		temp = ((HuffData & 0x80) != 0) ? 0xFFFFFF00 + HuffData : HuffData & 0xFF;
		VpuWriteReg (MJPEG_HUFF_DATA_REG, temp);
	}
	for (i = 0; i < 162 - HuffLength; i++)
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
	for (i = 0; i < 64; i++) {
		val = jpg->qMatTab[table][i];
		VpuWriteReg(MJPEG_QMAT_DATA_REG, val);
	}
	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x00);

	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x43);
	table = jpg->cInfoTab[1][3];
	for (i = 0; i < 64; i++) {
		val = jpg->qMatTab[table][i];
		VpuWriteReg(MJPEG_QMAT_DATA_REG, val);
	}
	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x00);

	VpuWriteReg(MJPEG_QMAT_CTRL_REG, 0x83);
	table = jpg->cInfoTab[2][3];
	for (i = 0; i < 64; i++) {
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

	dMibStatus = 1;
	dExtBitBufCurPos = pDecInfo->jpgInfo.pagePtr;
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
	if (pDecInfo->jpgInfo.lastRound
			&& (dExtBitBufCurPos >= pDecInfo->jpgInfo.curPosStreamEnd)) {
		pDecInfo->jpgInfo.bbcStreamCtl |= (1 << 28);
		VpuWriteReg(MJPEG_BBC_STRM_CTRL_REG, pDecInfo->jpgInfo.bbcStreamCtl);
	}

	VpuWriteReg(MJPEG_BBC_CUR_POS_REG, dExtBitBufCurPos);
	VpuWriteReg(MJPEG_BBC_CTRL_REG, 1);
	VpuWriteReg(MJPEG_GBU_WD_PTR_REG, pDecInfo->jpgInfo.wordPtr);
	VpuWriteReg(MJPEG_GBU_BBSR_REG, 0);
	VpuWriteReg(MJPEG_GBU_BBER_REG, ((256 / 4) * 2) - 1);
	if (pDecInfo->jpgInfo.pagePtr & 1) {
		VpuWriteReg(MJPEG_GBU_BBIR_REG, 0);
		VpuWriteReg(MJPEG_GBU_BBHR_REG, 0);
	} else {
		VpuWriteReg(MJPEG_GBU_BBIR_REG, 256 / 4);
		VpuWriteReg(MJPEG_GBU_BBHR_REG, 256 / 4);
	}

	VpuWriteReg(MJPEG_GBU_CTRL_REG, 4);
	VpuWriteReg(MJPEG_GBU_FF_RPTR_REG, pDecInfo->jpgInfo.bitPtr);

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
	if (get_bits_left(&jpg->gbc) < 8 + 24)
		return 0;

	if (show_bits(&jpg->gbc, 8) == 0xFF)
		return 1;
	else
		return 0;
}


int find_start_code(JpgDecInfo *jpg)
{
	int word;

	while (1) {
		if (get_bits_left(&jpg->gbc) < 16 + 24)
			return 0;

		word = show_bits(&jpg->gbc, 16);
		if ((word > 0xFF00) && (word < 0xFFFF))
			break;

		if (get_bits_left(&jpg->gbc) < 8 + 24)
			return 0;

		get_bits(&jpg->gbc, 8);
	}

	return word;
}

int find_start_soi_code_one_shot(JpgDecInfo *jpg)
{
	int size;
	unsigned char *buf;
	unsigned char *ptr;
	unsigned short word = 0;

	size = get_bits_left(&jpg->gbc)/8;
	buf = jpg->gbc.buffer + jpg->gbc.index;
	ptr = buf;

	while (ptr < buf + size) {
		word = (word << 8) | *ptr++;
		if (word == SOI_Marker) {
			jpg->gbc.index += (int)(ptr - 2 - buf);
			return 0;
		}
	}

	jpg->gbc.index += (int)(ptr - 1 - buf);
	return -1;
}

int find_start_soi_code(JpgDecInfo *jpg)
{
	unsigned int word;

	while (1) {
		if (get_bits_left(&jpg->gbc) < 16 + 24)
			return 0;

		word = show_bits(&jpg->gbc, 16);
		if ((word > 0xFF00) && (word < 0xFFFF)) {
			if (word != SOI_Marker) {
				if (get_bits_left(&jpg->gbc) < 8 + 24)
					return 0;
				get_bits(&jpg->gbc, 8);
			}
			break;
		}

		if (get_bits_left(&jpg->gbc) < 8 + 24)
			return 0;
		get_bits(&jpg->gbc, 8);
	}

	return word;
}

int decode_app_header(JpgDecInfo *jpg)
{
	int length;

	if (get_bits_left(&jpg->gbc) < 16 + 24)
		return 0;

	length = get_bits(&jpg->gbc, 16);
	length -= 2;

	while (length-- > 0) {
		if (get_bits_left(&jpg->gbc) < 8 + 24)
			return 0;
		get_bits(&jpg->gbc, 8);
	}

	return 1;
}


int decode_dri_header(JpgDecInfo *jpg)
{
	if (get_bits_left(&jpg->gbc) < 16 * 2 + 24)
		return 0;

	get_bits(&jpg->gbc, 16);

	jpg->rstIntval = get_bits(&jpg->gbc, 16);

	return 1;
}

int decode_dqt_header(JpgDecInfo *jpg)
{
	int Pq, Tq, i, tmp;

	if (get_bits_left(&jpg->gbc) < 16 + 24)
		return 0;

	get_bits(&jpg->gbc, 16);

	do {
		if (get_bits_left(&jpg->gbc) < (4 + 4 + 8 * 64 + 24))
			return 0;

		tmp = get_bits(&jpg->gbc, 8);
		Pq = (tmp>>4) & 0xf;
		Tq = tmp&0xf;

		if (Tq > 3) {
			info_msg("Tq is more than 3\n");
			jpg->header_status = 1;
			return 1;
		}
		for (i = 0; i < 64; i++)
			jpg->qMatTab[Tq][i] = get_bits(&jpg->gbc, 8);
	} while(!check_start_code(jpg));

	if (Pq != 0) {
		info_msg("Pq isn't 0\n");
		jpg->header_status = 1;
		return 1;
	}

	return 1;
}

int decode_dth_header(JpgDecInfo *jpg)
{
	int Tc, Th, ThTc, bitCnt, i, tmp;

	if (get_bits_left(&jpg->gbc) < 16 + 24)
		return 0;

	get_bits(&jpg->gbc, 16);

	do {
		if (get_bits_left(&jpg->gbc) < 8 + 8 * 16 + 24)
			return 0;

		tmp = get_bits(&jpg->gbc, 8);
		Tc = (tmp>>4) & 0xf;
		Th = tmp&0xf;

		ThTc = ((Th & 1) << 1) | (Tc & 1);
		if (ThTc > 3) {
			info_msg("ThTc is more than 3\n");
			jpg->header_status = 1;
			return 1;
		}

		bitCnt = 0;
		for (i = 0; i < 16; i++) {
			jpg->huffBits[ThTc][i] = get_bits(&jpg->gbc, 8);
			bitCnt += jpg->huffBits[ThTc][i];

			if (cDefHuffBits[ThTc][i] != jpg->huffBits[ThTc][i])
				jpg->userHuffTab = 1;
		}

		if (get_bits_left(&jpg->gbc) <  8 * bitCnt + 24)
			return 0;
		for (i = 0; i < bitCnt; i++)  {
			if (i < HUFF_VAL_SIZE) {
				jpg->huffVal[ThTc][i] = get_bits(&jpg->gbc, 8);
				if (cDefHuffVal[ThTc][i] != jpg->huffVal[ThTc][i])
					jpg->userHuffTab = 1;
			}
			else
				get_bits(&jpg->gbc, 8);
		}
	} while(!check_start_code(jpg));

	return 1;
}

int decode_sof_header(JpgDecInfo *jpg)
{
	int samplePrecision, sampleFactor, i, Tqi, compID;
	int hSampFact[3], vSampFact[3], picX, picY, numComp, tmp;

	if (get_bits_left(&jpg->gbc) < 16 + 8 + 16 + 16 + 8 + 24)
		return 0;

	get_bits(&jpg->gbc, 16);
	samplePrecision = get_bits(&jpg->gbc, 8);

	if (samplePrecision != 8) {
		info_msg("Sample Precision is not 8\n");
		jpg->header_status = 1;
		return 1;
	}

	picY = get_bits(&jpg->gbc, 16);
	if (picY > MAX_VSIZE) {
		info_msg("Picture Vertical Size limits Maximum size\n");
		jpg->header_status = 1;
		return 1;
	}

	picX = get_bits(&jpg->gbc, 16);
	if (picX > MAX_HSIZE) {
		info_msg("Picture Horizontal Size limits Maximum size\n");
		jpg->header_status = 1;
		return 1;
	}

	numComp = get_bits(&jpg->gbc, 8);
	if (numComp > 3) {
		info_msg("Components number limits Maximum size: numComp %d\n", numComp);
		jpg->header_status = 1;
		return 1;
	}

	if (get_bits_left(&jpg->gbc) < (numComp * ( 8 + 4 + 4 + 8) + 24))
		return 0;

	for (i = 0; i < numComp; i++) {
		compID = get_bits(&jpg->gbc, 8);
		tmp = get_bits(&jpg->gbc, 8);
		hSampFact[i] = (tmp>>4) & 0xf;
		vSampFact[i] = tmp&0xf;

		Tqi = get_bits(&jpg->gbc, 8);

		jpg->cInfoTab[i][0] = compID;
		jpg->cInfoTab[i][1] = hSampFact[i];
		jpg->cInfoTab[i][2] = vSampFact[i];
		jpg->cInfoTab[i][3] = Tqi;
	}

	if ((hSampFact[0] > 2) || (vSampFact[0] > 2) || ((numComp == 3) &&
	    ((hSampFact[1] != 1) || (hSampFact[2] != 1) ||
	     (vSampFact[1] != 1) || (vSampFact[2] != 1)))) {
		info_msg("Not Supported Sampling Factor\n");
		jpg->header_status = 1;
		return 1;
	}

	if (numComp == 1)
		sampleFactor = SAMPLE_400;
	else
		sampleFactor = ((hSampFact[0] & 3) << 2) | (vSampFact[0] & 3);

	switch(sampleFactor) {
		case SAMPLE_420:
			jpg->format = FORMAT_420;
			break;
		case SAMPLE_H422:
			jpg->format = FORMAT_422;
			break;
		case SAMPLE_V422:
			jpg->format = FORMAT_224;
			break;
		case SAMPLE_444:
			jpg->format = FORMAT_444;
			break;
		default:
			jpg->format = FORMAT_400;
	}

	jpg->picWidth = picX;
	jpg->picHeight = picY;

	return 1;
}

int decode_sos_header(JpgDecInfo *jpg)
{
	int i, j, len, numComp, compID;
	int ss, se, ah, al, ecsPtr;
	int dcHufTblIdx[3], acHufTblIdx[3], tmp;

	if (get_bits_left(&jpg->gbc) < 8 + 24)
		return 0;

	len = get_bits(&jpg->gbc, 16);

	jpg->ecsPtr = get_bits_count(&jpg->gbc) / 8 + len - 2 ;

	ecsPtr = jpg->ecsPtr + jpg->frameOffset;
	jpg->pagePtr = ecsPtr / 256;
	jpg->wordPtr = (ecsPtr % 256) / 4;	/* word unit */
	if (jpg->pagePtr & 1)
		jpg->wordPtr += 64;
	if (jpg->wordPtr & 1)
		jpg->wordPtr -= 1; /* to make even */

	jpg->bitPtr = (ecsPtr % 4) * 8; /* bit unit */
	if (((ecsPtr % 256) / 4) & 1)
		jpg->bitPtr += 32;

	if (get_bits_left(&jpg->gbc) < 8 + 24)
		return 0;

	numComp = get_bits(&jpg->gbc, 8);

	if (numComp > 3) {
		info_msg("The numComp is more than 3\n");
		jpg->ecsPtr = 0;
		jpg->header_status = 1;
		return 1;
	}

	if (get_bits_left(&jpg->gbc) < (numComp * (8 + 4 + 4) + 24))
		return 0;

	for (i = 0; i < numComp; i++) {
		compID = get_bits(&jpg->gbc, 8);
		tmp = get_bits(&jpg->gbc, 8);
		dcHufTblIdx[i] = (tmp>>4) & 0xf;
		acHufTblIdx[i] = tmp&0xf;

		for (j = 0; j < numComp; j++) {
			if (compID == jpg->cInfoTab[j][0]) {
				jpg->cInfoTab[j][4] = dcHufTblIdx[i];
				jpg->cInfoTab[j][5] = acHufTblIdx[i];
			}
		}
	}

	if (get_bits_left(&jpg->gbc) < 8 + 8 + 4 + 4 + 24)
		return 0;

	ss = get_bits(&jpg->gbc, 8);
	se = get_bits(&jpg->gbc, 8);
	tmp = get_bits(&jpg->gbc, 8);
	ah = (i>>4) & 0xf;
	al = tmp&0xf;

	if ((ss != 0) || (se != 0x3F) || (ah != 0) || (al != 0)) {
		jpg->ecsPtr = 0;
		info_msg("The Jpeg Image must be another profile\n");
		jpg->header_status = 1;
		return 1;
	}

	return 1;
}

void genDecHuffTab(JpgDecInfo *jpg, int tabNum)
{
	unsigned char *huffPtr, *huffBits;
	unsigned int *huffMax, *huffMin;

	int ptrCnt =0, huffCode = 0, zeroFlag = 0, dataFlag = 0;
	int i;

	huffBits = jpg->huffBits[tabNum];
	huffPtr = jpg->huffPtr[tabNum];
	huffMax = (unsigned int *)(jpg->huffMax[tabNum]);
	huffMin = (unsigned int *)(jpg->huffMin[tabNum]);

	for (i = 0; i < 16; i++) {
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

int JpuGbuInit(vpu_getbit_context_t *ctx, Uint8 *buffer, int size)
{

	ctx->buffer = buffer;
	ctx->index = 0;
	ctx->size = size/8;

	return 1;
}

int JpuGbuGetUsedBitCount(vpu_getbit_context_t *ctx)
{
	return ctx->index*8;
}

int JpuGbuGetLeftBitCount(vpu_getbit_context_t *ctx)
{
	return (ctx->size*8) - JpuGbuGetUsedBitCount(ctx);
}

unsigned int JpuGbuGetBit(vpu_getbit_context_t *ctx, int bit_num)
{
	Uint8 *p;
	unsigned int b = 0x0;

	if (bit_num > JpuGbuGetLeftBitCount(ctx))
		return -1;

	p = ctx->buffer + ctx->index;

	if (bit_num == 8)
	{
		b = *p;
		ctx->index++;
	}
	else if(bit_num == 16)
	{
		b = *p++<<8;
		b |= *p++;
		ctx->index += 2;
	}
	else if(bit_num == 32)
	{
		b = *p++<<24;
		b |= (*p++<<16);
		b |= (*p++<<8);
		b |= (*p++<<0);
		ctx->index += 4;
	}
	else
	{
		err_msg("Get bit_num is not 8,16,32\n");
	}


	return b;
}

unsigned int JpuGbuShowBit(vpu_getbit_context_t *ctx, int bit_num)
{
	Uint8 *p;
	unsigned int b = 0x0;

	if (bit_num > JpuGbuGetLeftBitCount(ctx))
		return -1;

	p = ctx->buffer + ctx->index;

	if (bit_num == 8)
	{
		b = *p;
	}
	else if(bit_num == 16)
	{
		b = *p++<<8;
		b |= *p++;
	}
	else if(bit_num == 32)
	{
		b = *p++<<24;
		b |= (*p++<<16);
		b |= (*p++<<8);
		b |= (*p++<<0);
	}
	else
	{
		err_msg("Show bit_num is not 8,16,32\n");
	}

	return b;
}

// thumbnail: User should make sure it's one picture and fits in the bs buffer. SW doesn't handle wrap around case.
static Uint32 tGetBits(DecInfo *pDecInfo, int endian, int byteCnt)
{
	int i;
	Uint8 byte;
	Uint32 retData = 0;

	for (i=0; i<byteCnt; i++) {

		byte = (Uint8)get_bits(&pDecInfo->jpgInfo.gbc, 8);

		if (endian)
			retData = (retData<<8) | byte;
		else
			retData = retData | (byte<<((i&3)*8));
	}

	return retData;
}

static void thumbRaw(DecInfo *pDecInfo, Uint8 pal[][3])
{
	int i;
	int pixelCnt;

	dprintf(4, "checking raw thumbnail\n");

	if (pDecInfo->jpgInfo.ThumbInfo.ThumbType == JFXX_PAL) {
		for (i = 0; i < 256; i++) {
			pal[i][0] = get_bits(&pDecInfo->jpgInfo.gbc, 8);
			pal[i][1] = get_bits(&pDecInfo->jpgInfo.gbc, 8);
			pal[i][2] = get_bits(&pDecInfo->jpgInfo.gbc, 8);
		}
	}

	pixelCnt = pDecInfo->jpgInfo.picWidth
		* pDecInfo->jpgInfo.picHeight
		* (pDecInfo->jpgInfo.thumbInfo.MbSize/64);

	for (i=0; i<pixelCnt; i++) {
		get_bits(&pDecInfo->jpgInfo.gbc, 8);
	}
}

int ParseJFIF(DecInfo *pDecInfo, int jfif, int length)
{
	int exCode;
	int picX, picY;
	THUMB_INFO *pThumbInfo;
	pThumbInfo = &(pDecInfo->jpgInfo.ThumbInfo);

	/* if EXIF thumbnail contains JFIF APP0 */
	if (pThumbInfo->ThumbType == EXIF_JPG)
	{
		if(jfif)
		{
			get_bits(&pDecInfo->jpgInfo.gbc, 16);
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
			get_bits(&pDecInfo->jpgInfo.gbc, 16);
			get_bits(&pDecInfo->jpgInfo.gbc, 16);
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
			get_bits(&pDecInfo->jpgInfo.gbc, 8);

			length -= 9;
		}
		else
		{
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
			length -= 3;
		}

		return length;

	}
	if (jfif)						//JFIF
	{
		pThumbInfo->ThumbType = JFIF;
		pThumbInfo->Version = get_bits(&pDecInfo->jpgInfo.gbc, 16);
		get_bits(&pDecInfo->jpgInfo.gbc, 8);
		get_bits(&pDecInfo->jpgInfo.gbc, 16);
		get_bits(&pDecInfo->jpgInfo.gbc, 16);

		picX = pDecInfo->jpgInfo.picWidth = get_bits(&pDecInfo->jpgInfo.gbc, 8);
		picY = pDecInfo->jpgInfo.picHeight = get_bits(&pDecInfo->jpgInfo.gbc, 8);

		if (pDecInfo->jpgInfo.picWidth != 0 && pDecInfo->jpgInfo.picHeight != 0)
		{
			pDecInfo->jpgInfo.thumbInfo.MbNumX = (picX + 7)/8;
			pDecInfo->jpgInfo.thumbInfo.MbNumY = (picY + 7)/8;
			pDecInfo->jpgInfo.thumbInfo.MbSize = 192;
			pDecInfo->jpgInfo.thumbInfo.DecFormat = FORMAT_444;
		}

		length -= 9;

	}
	else /* JFXX */
	{
		exCode = get_bits(&pDecInfo->jpgInfo.gbc, 8);
		length -= 1;
		if (exCode == 0x10)
		{
			pThumbInfo->ThumbType = JFXX_JPG;
		}
		else if (exCode == 0x11)
		{
			picX = pDecInfo->jpgInfo.picWidth = get_bits(&pDecInfo->jpgInfo.gbc, 8);
			picY = pDecInfo->jpgInfo.picHeight = get_bits(&pDecInfo->jpgInfo.gbc, 8);

			pDecInfo->jpgInfo.thumbInfo.MbNumX = (picX + 7)/8;
			pDecInfo->jpgInfo.thumbInfo.MbNumY = (picY + 7)/8;
			pDecInfo->jpgInfo.thumbInfo.MbSize = 64;
			pThumbInfo->ThumbType = JFXX_PAL;
			pDecInfo->jpgInfo.thumbInfo.DecFormat = FORMAT_444;
			length -= 2;

		}
		else if (exCode == 0x13)
		{
			picX = pDecInfo->jpgInfo.picWidth = get_bits(&pDecInfo->jpgInfo.gbc, 8);
			picY = pDecInfo->jpgInfo.picHeight = get_bits(&pDecInfo->jpgInfo.gbc, 8);

			pDecInfo->jpgInfo.thumbInfo.MbNumX = (picX + 7)/8;
			pDecInfo->jpgInfo.thumbInfo.MbNumY = (picY + 7)/8;
			pDecInfo->jpgInfo.thumbInfo.MbSize = 192;
			pThumbInfo->ThumbType = JFXX_RAW;
			pDecInfo->jpgInfo.thumbInfo.DecFormat = FORMAT_444;
			length -= 2;
		}
		else
			return length;

	}


	return length;
}

int ParseEXIF(DecInfo *pDecInfo, int length)
{
	int i;
	Uint32 iFDValOffset = 0;
	Uint32 runIdx = 0;
	Uint32 j;
	Uint32 ifdSize;
	Uint32 nextIFDOffset;
	Uint32 size;
	TAG tags;
	Uint8 id;
	int endian;
	Uint8 big_e = true;
	Uint8 little_e = true;
	THUMB_INFO *pThumbInfo;
	pThumbInfo = &(pDecInfo->jpgInfo.ThumbInfo);

	//------------------------------------------------------------------------------
	// TIFF HEADER, {endian[1:0],0x002A,offset(4bytes)}
	//------------------------------------------------------------------------------

	for (i = 0; i < 2; i++)
	{
		id = (Uint8) get_bits(&pDecInfo->jpgInfo.gbc, 8);

		if (id != lendian[i])
			little_e = false;
		if (id != bendian[i])
			big_e = false;
	}
	length -= 2;

	if (little_e == false && big_e == false)
		dprintf(4,"ERROR\n");

	endian = (little_e) ? JPG_LITTLE_ENDIAN : JPG_BIG_ENDIAN;

	tGetBits(pDecInfo, endian, 2);
	length -= 2;

	size = tGetBits(pDecInfo, endian, 4) -8;
	length -= 4;

	for (j = 0; j < size; j++)
	{
		get_bits(&pDecInfo->jpgInfo.gbc, 8);
		length -= 1;
	}

	//------------------------------------------------------------------------------
	// 0TH IFD
	//------------------------------------------------------------------------------

	ifdSize = tGetBits(pDecInfo, endian, 2);
	length -= 2;

	for (j = 0; j < ifdSize; j++)
	{
		tGetBits(pDecInfo, endian, 2); //Tag
		tGetBits(pDecInfo, endian, 2); //Type
		tGetBits(pDecInfo, endian, 4); //count
		tGetBits(pDecInfo, endian, 4); //offset
		length -= 12;
	}

	nextIFDOffset = tGetBits(pDecInfo, endian, 4);
	length -= 4;

	if(nextIFDOffset == 0x00)
	{
		while (length--)
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
		return length;
	}
	else if ((int) nextIFDOffset > length)
	{
		while (length--)
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
		return length;
	}
	nextIFDOffset -= (ifdSize *12 + 10 + size + 4);

	for (j = 0; j < nextIFDOffset; j++)
	{
		get_bits(&pDecInfo->jpgInfo.gbc, 8);
		length -= 1;
	}
	runIdx += (8 + size + 2 + ifdSize*12 + 4 + nextIFDOffset);

	//------------------------------------------------------------------------------
	// 1TH IFD, thumbnail
	//------------------------------------------------------------------------------

	ifdSize = tGetBits(pDecInfo, endian, 2);
	length -= 2;
	for (j=0; j<ifdSize; j++) {
		tags.tag    = tGetBits(pDecInfo,endian,2); // Tag
		tags.type   = tGetBits(pDecInfo, endian,2); // Type
		tags.count  = tGetBits(pDecInfo, endian,4); // count
		tags.offset = tGetBits(pDecInfo, endian,4); // offset
		length -= 12;

		if (endian != JPG_LITTLE_ENDIAN) {
			if (tags.type == 1 && tags.count < 4)
				tags.offset >>= (4 - tags.count) * 8;
			if (tags.type == 3 && tags.count < 2)
				tags.offset >>= (2 - tags.count) * 16;
		}

		switch(tags.tag&0xFFFF) {
			case IMAGE_WIDTH :
				pThumbInfo->ExifInfo.PicX = tags.offset;
				break;
			case IMAGE_HEIGHT :
				pThumbInfo->ExifInfo.PicY = tags.offset;
				break;
			case BITS_PER_SAMPLE :
				pThumbInfo->ExifInfo.BitPerSample[0] = tags.offset;
				break;
			case COMPRESSION_SCHEME :
				pThumbInfo->ThumbType = EXIF_JPG;
				pThumbInfo->ExifInfo.Compression = tags.offset & 0xffff;
				break;
			case PIXEL_COMPOSITION :
				pThumbInfo->ExifInfo.PixelComposition = tags.offset;
				break;
			case SAMPLE_PER_PIXEL :
				pThumbInfo->ExifInfo.SamplePerPixel = tags.offset;
				break;
			case YCBCR_SUBSAMPLING : // 2, 1 4:2:2 / 2, 2 4:2:0
				pThumbInfo->ExifInfo.YCbCrSubSample = tags.offset;
				break;
			case JPEG_IC_FORMAT :
				pThumbInfo->ExifInfo.JpegOffset = tags.offset;
				break;
			case PLANAR_CONFIG :
				pThumbInfo->ExifInfo.PlanrConfig = tags.offset;
				break;
			default :
				break;
		}

		if (tags.type == 2)
			iFDValOffset += tags.count;
		else if (tags.type == 3 && tags.count > 2)
			iFDValOffset += (tags.count*2);
		else if (tags.type == 5 || tags.type == 0xA)
			iFDValOffset += (tags.count*8);
	}

	if (pThumbInfo->ExifInfo.Compression == 6) { // jpeg
		runIdx += (2 + ifdSize*12);
		iFDValOffset = pThumbInfo->ExifInfo.JpegOffset - runIdx;
	}

	for (j=0; j<iFDValOffset; j++)
	{
		get_bits(&pDecInfo->jpgInfo.gbc, 8);
		length -= 1;
	}

	return length;


}


int CheckThumbNail(DecInfo *pDecInfo)
{
	Uint8 id;
	Uint8 jfifFlag = true;
	Uint8 jfxxFlag = true;
	Uint8 exifFlag = true;
	int i;
	int length;
	int initLength;

	THUMB_INFO *pThumbInfo;
	pThumbInfo = &(pDecInfo->jpgInfo.ThumbInfo);


	length = get_bits(&pDecInfo->jpgInfo.gbc, 16);
	length -= 2;

	initLength = length;

	if (initLength < 5)
	{
		while(length--)
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
	}
	else
	{
		for (i = 0; i < 4; i++)
		{
			id = (Uint8) get_bits(&pDecInfo->jpgInfo.gbc, 8);

			if (id != jfif[i])
				jfifFlag = false;
			if (id != jfxx[i])
				jfxxFlag = false;
			if (id != exif[i])
				exifFlag = false;

		}
		get_bits(&pDecInfo->jpgInfo.gbc, 8);
		length -= 5;

		if (exifFlag)
		{
			get_bits(&pDecInfo->jpgInfo.gbc, 8);
			length -= 1;
		}
		if (jfifFlag | jfxxFlag) /* JFIF */
		{
			length = ParseJFIF(pDecInfo, jfifFlag, length);

			if (pThumbInfo->ThumbType != EXIF_JPG)
			{
				if(pThumbInfo->ThumbType != JFXX_JPG)
				{
					/* RAW data */
					thumbRaw(pDecInfo, pThumbInfo->Pallette);

				}
			}

		}
		else if (exifFlag) /* EXIF */
		{
			length = ParseEXIF(pDecInfo, length);
			if (length == -1)
				return 0;
		}
	}

	return 1;

}

int JpegDecodeHeader(DecInfo *pDecInfo)
{
	unsigned int code;
	int i, temp, ret = 1, size, val, temp_size = 0, src_size = 0;
	int wrOffset = 0;
	Uint8 *b, *temp_buf = NULL;
	JpgDecInfo *jpg = &pDecInfo->jpgInfo;

	/* Init some variable in jpgInfo */
	jpg->rstIntval = 0;
	jpg->userHuffTab = 0;
	jpg->header_status = 0; /* 0 - valid; 1 - find wrong header info already */

	if (jpg->lineBufferMode) {
		b = jpg->pVirtJpgChunkBase;
		size = jpg->chunkSize;
	} else {
		b = jpg->pVirtBitStream + jpg->frameOffset;
		wrOffset = pDecInfo->streamWrPtr - pDecInfo->streamBufStartAddr;

		if (wrOffset <= jpg->frameOffset)
			size = pDecInfo->streamBufSize - jpg->frameOffset;
		else
			size = wrOffset - jpg->frameOffset;

		if (!b || !size) {
			ret = -1;
			err_msg("b or size is zero\n");
			goto DONE_DEC_HEADER;
		}

		/* find start code of next frame */
		if (!jpg->ecsPtr) {
			int nextOffset = 0, soiOffset = 0;

			/* workaround to avoid to find current incomplete header looply */
			if (jpg->wrappedHeader && jpg->consumeByte == 0)
				jpg->consumeByte++;

			if (jpg->consumeByte != 0)	{ /* meaning is frameIdx > 0 */
				nextOffset = jpg->consumeByte;
				if (nextOffset <= 0)
					nextOffset = 2; /* in order to consume start code */
			}
			dprintf(4, "JpegDecodeHeader: last_consumeByte=0x%x\n", nextOffset);
			/* consume to find the start code of next frame */
			b += nextOffset;
			if (b - jpg->pVirtBitStream > pDecInfo->streamBufSize) { /* wrap around */
				b -= pDecInfo->streamBufSize;
				size = wrOffset - (b - jpg->pVirtBitStream);
				jpg->frameOffset = b - jpg->pVirtBitStream;
				jpg->consumeByte = 0;
			} else {
				jpg->frameOffset +=nextOffset;
				size -= nextOffset;
			}

			if (size < 0) {
				ret = -1;
				err_msg("Size is less than 0\n");
				goto DONE_DEC_HEADER;
			}

			init_get_bits(&jpg->gbc, b, size * 8);
			if (find_start_soi_code_one_shot(jpg) == -1) {
				ret = -1;
				dprintf(4, "return 0 in soi finding\n");
				goto DONE_DEC_HEADER;
			}
			soiOffset = get_bits_count(&pDecInfo->jpgInfo.gbc) / 8;
			b += soiOffset;
			size -= soiOffset;
			jpg->frameOffset += soiOffset;
		}
	}

	init_get_bits(&jpg->gbc, b, size * 8);

	/* Initialize component information table */
	for (i = 0; i < 4; i++) {
		jpg->cInfoTab[i][0] = 0;
		jpg->cInfoTab[i][1] = 0;
		jpg->cInfoTab[i][2] = 0;
		jpg->cInfoTab[i][3] = 0;
		jpg->cInfoTab[i][4] = 0;
		jpg->cInfoTab[i][5] = 0;
	}

	for (;;) {
		if (find_start_code(jpg) == 0) {
			ret = -1;
			dprintf(4, "err in find start code\n");
			goto DONE_DEC_HEADER;
		}

		code = get_bits(&jpg->gbc, 16);
		/*
		 * Skip to analyze coming marker till EOI if found wrong info
		 * in the header already for streaming mode.
		 */
		if (jpg->header_status) {
			if (jpg->lineBufferMode) {
				ret = -1;
				goto DONE_DEC_HEADER;
			} else if (code != EOI_Marker)
				continue;
		}

		switch (code) {
		case SOI_Marker:
			break;
		case JFIF_CODE:
		case EXIF_CODE:
			if (pDecInfo->openParam.mjpg_thumbNailDecEnable == 1) {
				CheckThumbNail(pDecInfo);
				dprintf(4, "ThumbType = %d\n", pDecInfo->jpgInfo.ThumbInfo.ThumbType);
			}
			else {
				if (!decode_app_header(jpg)) {
					dprintf(4, "err in JFIF_CODE or EXIF_CODE\n");
					ret = -1;
					goto DONE_DEC_HEADER;
				}
			}
			break;
		case DRI_Marker:
			if (!decode_dri_header(jpg)) {
				ret = -1;
				dprintf(4, "error in DRI_Marker\n");
				goto DONE_DEC_HEADER;
			}
			break;
		case DQT_Marker:
			if (!decode_dqt_header(jpg)) {
				ret = -1;
				dprintf(4, "error in DQT_Marker\n");
				goto DONE_DEC_HEADER;
			}
			break;
		case DHT_Marker:
			if (!decode_dth_header(jpg)) {
				ret = -1;
				dprintf(4, "error in DHT_Marker\n");
				goto DONE_DEC_HEADER;
			}
			break;
		case SOF_Marker:
			if (!decode_sof_header(jpg)) {
				ret = -1;
				dprintf(4, "error in SOF_Marker\n");
				goto DONE_DEC_HEADER;
			}
			break;
		case SOS_Marker:
			if (!decode_sos_header(jpg)) {
				ret = -1;
				dprintf(4, "error in SOS_Marker\n");
			}
			if (jpg->header_status) {
				if (jpg->lineBufferMode)
					ret = -1;
				else
					break;
			}
			goto DONE_DEC_HEADER;
			break;
		case EOI_Marker:
			ret = -3;
			dprintf(4, "met EOI\n");
			goto DONE_DEC_HEADER;
		default:
			switch (code & 0xFFF0) {
			case 0xFFE0:
			case 0xFFF0:
				if (get_bits_left(&jpg->gbc) <=0 ) {
					dprintf(4, "error in 0xFFF0 or 0xFFE0\n");
					ret = -1;
					goto DONE_DEC_HEADER;
				} else {
					if (!decode_app_header(jpg)) {
						ret = -1;
						dprintf(4, "error in 0xFFF0 or 0xFFE0 app\n");
						goto DONE_DEC_HEADER;
					}
					break;
				}
			default:
				dprintf(4, "code = [%x]\n", code);
			}
			break;
		}
	}

DONE_DEC_HEADER:
	if (pDecInfo->jpgInfo.lineBufferMode) {
		if (ret == -1)
			return -1;
	} else { /* streaming mode */
		if (ret == -1) {
			if (wrOffset < jpg->frameOffset) {
				dprintf(4, "wrap around in header parsing\n");
				jpg->wrappedHeader = 1;
				goto proc_wrap;
			}
			return -1;
		}
	}

	if (!jpg->ecsPtr || ret == -3) {
		if (pDecInfo->jpgInfo.lineBufferMode)
			return -3;
		else {
			/* Skip the bitstream to EOI if EOI marker is found */
			jpg->frameOffset += get_bits_count(&jpg->gbc) / 8 + 2;
			jpg->consumeByte = 0;
			return -3;
		}
	}

	if (!jpg->lineBufferMode) {
		/* Workaround to avoid the case that JPU is run over without interrupt */
		if (pDecInfo->streamBufSize - (jpg->frameOffset + jpg->ecsPtr)
			< JPU_GBU_SIZE) {
proc_wrap:
			temp_size = pDecInfo->streamWrPtr - pDecInfo->streamBufStartAddr;
			if (temp_size) {
				temp_buf = malloc(temp_size);
				if (!temp_buf) {
					err_msg("Allocate memory failure\n");
					return 0;
				}
				else
					memcpy(temp_buf, (void *)jpg->pVirtBitStream, temp_size);
			}
			src_size = pDecInfo->streamBufSize - jpg->frameOffset;
			memcpy((void *)jpg->pVirtBitStream,
				    (void *)(jpg->pVirtBitStream + jpg->frameOffset), src_size);
			memcpy((void *)(jpg->pVirtBitStream + src_size), temp_buf, temp_size);
			free(temp_buf);
			pDecInfo->streamWrPtr += src_size;
			jpg->frameOffset = 0;
			jpg->consumeByte = 0;
			return -2;
		}

		/* Re-calculate bbcEndAddr and bbcStreamCtl after header parsing */
		wrOffset = pDecInfo->streamWrPtr - pDecInfo->streamBufStartAddr;
		if (wrOffset < pDecInfo->jpgInfo.frameOffset)
			pDecInfo->jpgInfo.bbcEndAddr = pDecInfo->streamBufEndAddr;
		else if (pDecInfo->streamEndflag) {
			val = wrOffset / 256;
			if (wrOffset % 256)
				val += 1;
			pDecInfo->jpgInfo.curPosStreamEnd = val;
			val = (1 << 31 | val);
			pDecInfo->jpgInfo.bbcStreamCtl = val;
			pDecInfo->jpgInfo.bbcEndAddr = pDecInfo->streamWrPtr+256;
			pDecInfo->jpgInfo.lastRound = 1;
		}
		else
			pDecInfo->jpgInfo.bbcEndAddr = pDecInfo->streamWrPtr & 0xFFFFFE00;
	}

	/* Generate Huffman table information */
	for (i = 0; i < 4; i++)
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
	case FORMAT_420:
		jpg->busReqNum = 2;
		jpg->mcuBlockNum = 6;
		jpg->compNum = 3;
		jpg->compInfo[0] = 10;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+15)&~15);
		jpg->alignedHeight = ((jpg->picHeight+15)&~15);
		break;
	case FORMAT_422:
		jpg->busReqNum = 3;
		jpg->mcuBlockNum = 4;
		jpg->compNum = 3;
		jpg->compInfo[0] = 9;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+15)&~15);
		jpg->alignedHeight = ((jpg->picHeight+7)&~7);
		break;
	case FORMAT_224:
		jpg->busReqNum = 3;
		jpg->mcuBlockNum = 4;
		jpg->compNum = 3;
		jpg->compInfo[0] = 6;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+7)&~7);
		jpg->alignedHeight = ((jpg->picHeight+15)&~15);
		break;
	case FORMAT_444:
		jpg->busReqNum = 4;
		jpg->mcuBlockNum = 3;
		jpg->compNum = 3;
		jpg->compInfo[0] = 5;
		jpg->compInfo[1] = 5;
		jpg->compInfo[2] = 5;
		jpg->alignedWidth = ((jpg->picWidth+7)&~7);
		jpg->alignedHeight = ((jpg->picHeight+7)&~7);
		break;
	case FORMAT_400:
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

/* User QMAT requirement */
static const int cInvZScan4x4[16] =
{
	0,  1,  4,  8,
	5,  2,  3,  6,
	9, 12, 13, 10,
	7, 11, 14, 15
};

static const int cInvZScan8x8[64] =
{
	 0,  1,  8, 16,  9,  2,  3, 10,
	17, 24, 32, 25, 18, 11,  4,  5,
	12, 19, 26, 33, 40, 48, 41, 34,
	27, 20, 13,  6,  7, 14, 21, 28,
	35, 42, 49, 56, 57, 50, 43, 36,
	29, 22, 15, 23, 30, 37, 44, 51,
	58, 59, 52, 45, 38, 31, 39, 46,
	53, 60, 61, 54, 47, 55, 62, 63
};


/*
 * BITSTREAM GENERATION FUNCTION
 */

void Nal2RBSP(VlcPutBitstream* const pBitstream)
{
	unsigned int   uRBSPBytesUsed = MAX_RBSP_SIZE - pBitstream->uRBSPRemBytes;
	unsigned char* pbyRBSP        = (unsigned char *)pBitstream->adwRBSPStart;
	unsigned char* pbyCodedFrmNow = (unsigned char *)((unsigned int)pBitstream->pbyBitstreamStart
					+ (unsigned int)pBitstream->uCodedBytes);
	unsigned long  dwNext3Bytes   = (pBitstream->uRBSPLast2Bytes << 8);

	do {
		unsigned int uSingleByte = *pbyRBSP++;

		dwNext3Bytes = dwNext3Bytes + uSingleByte;
		dwNext3Bytes <<= 8;
		if (dwNext3Bytes <= 0x0000000300L) {
			*pbyCodedFrmNow++ = 0x03;
			dwNext3Bytes |= 0xFF00;
		}
		*pbyCodedFrmNow++ = (unsigned char)uSingleByte;
	} while (--uRBSPBytesUsed != 0);

	pBitstream->uCodedBytes     = (unsigned int)pbyCodedFrmNow - (unsigned int)pBitstream->pbyBitstreamStart;
	pBitstream->uRBSPLast2Bytes = (unsigned int)(dwNext3Bytes >> 8);
	pBitstream->uRBSPRemBytes   = MAX_RBSP_SIZE;
	pBitstream->pdwRBSPPtr      = pBitstream->adwRBSPStart;
}

void PutBits(VlcPutBitstream* const pBitstream, unsigned long dwValue, int iBitSize)
{
	int           iWordRemBits  = pBitstream->iWordRemBits - iBitSize;
	unsigned long dwWordStorage = pBitstream->dwWordStorage;

	if (iWordRemBits >= 0) {
		dwWordStorage = dwWordStorage | (dwValue << iWordRemBits);
	} else {
		dwWordStorage = dwWordStorage | (dwValue >> (-iWordRemBits));
		dwWordStorage = (dwWordStorage >> 24) + (dwWordStorage << 24)
			+ ((dwWordStorage&0xFF0000) >> 8) + ((dwWordStorage&0xFF00) << 8);
		*pBitstream->pdwRBSPPtr++ = dwWordStorage;

		iWordRemBits  = iWordRemBits + 32;
		dwWordStorage = dwValue << iWordRemBits;
		pBitstream->uRBSPRemBytes -= 4;
		if (pBitstream->uRBSPRemBytes == 0)
			Nal2RBSP(pBitstream);
	}
	pBitstream->dwWordStorage = dwWordStorage;
	pBitstream->iWordRemBits  = iWordRemBits;
}

void VLC_NaluInit(VlcPutBitstream *pBitstream, int iNalRefIdc, int iNaluType)
{
	unsigned char *pbyNalu = (unsigned char *)((unsigned int)pBitstream->pbyBitstreamStart);

	pbyNalu[0] = 0;
	pbyNalu[1] = 0;
	pbyNalu[2] = 0;
	pbyNalu[3] = 1;
	pBitstream->uCodedBytes   = 4;

	pBitstream->dwWordStorage = 0L;
	pBitstream->iWordRemBits  = 32;

	pBitstream->uRBSPRemBytes   = MAX_RBSP_SIZE;
	pBitstream->pdwRBSPPtr      = pBitstream->adwRBSPStart;
	pBitstream->uRBSPLast2Bytes = (unsigned int)-1;

	PutBits(pBitstream, (0<<7) + (iNalRefIdc<<5) + iNaluType, 8); // forbidden_zero_bit | nal_ref_idc | nal_unit_type
}

unsigned int VCL_NaluClose(VlcPutBitstream *pBitstream)
{
	unsigned long dwWordStorage;
	int iLenStuffing = ((pBitstream->iWordRemBits - 1) & 0x7);

	PutBits(pBitstream, (1 << iLenStuffing), iLenStuffing + 1);   // rbsp_trailing_bits

	//Flush WordStorage & RBSP buffer
	dwWordStorage = pBitstream->dwWordStorage;
	dwWordStorage = (dwWordStorage >> 24) + (dwWordStorage << 24)
		+ ((dwWordStorage&0xFF0000) >> 8) + ((dwWordStorage&0xFF00) << 8);
	*pBitstream->pdwRBSPPtr++ = dwWordStorage;
	pBitstream->uRBSPRemBytes -= ((32 - pBitstream->iWordRemBits) >> 3);

	if (pBitstream->uRBSPRemBytes != MAX_RBSP_SIZE)
		Nal2RBSP(pBitstream);

	return pBitstream->uCodedBytes;
}

void PutUE(VlcPutBitstream *pBitstream, int data)
{
	int zeroNum;
	int codeNum;

	zeroNum = 0;
	codeNum = 1;
	while (codeNum <= data + 1) {
		codeNum = codeNum << 1;
		zeroNum++;
	}
	zeroNum--;

	PutBits(pBitstream, 0, zeroNum);
	codeNum = data + 1 - (1 << zeroNum);
	PutBits(pBitstream, 1, 1);
	PutBits(pBitstream, codeNum, zeroNum);

}

void PutSE(VlcPutBitstream *pBitstream, int data, int maxVal)
{
	int codeNum;

	if (data > 0)
		codeNum = data * 2 - 1; // (-1)^(codeNum + 1)
	else
		codeNum = -data * 2;

	PutUE(pBitstream, codeNum);     // -maxVal ~ maxlVal
}

void PutUELong(VlcPutBitstream *pBitstream, int data)
{
	int zeroNum;
	int codeNum;

	if (data < 126) {
		PutUE(pBitstream, data);
		return;
	}

	zeroNum = 0;
	codeNum = 1;
	while (codeNum <= data + 1) {
		codeNum = codeNum << 1;
		zeroNum++;
	}
	zeroNum--;

	PutBits(pBitstream, 0, zeroNum);
	codeNum = data + 1 - (1 << zeroNum);

	PutBits(pBitstream, 1, 1);
	PutBits(pBitstream, codeNum, zeroNum);

}

void PutSELong(VlcPutBitstream *pBitstream, int data)
{
	int codeNum;

	if (data > 0)
		codeNum = data * 2 - 1; // (-1)^(codeNum + 1)
	else
		codeNum = -data * 2;
	PutUELong(pBitstream, codeNum);
}

unsigned int MakeSPS(unsigned char *pbyStream, EncOpenParam *openParam, int RotFlag, int BitRate, int SliceNum)
{
	VlcPutBitstream Bitstream;
	int MbNumX, MbNumY;
	EncAvcParam *avcParam = &openParam->EncStdParam.avcParam;

	Bitstream.pbyBitstreamStart = pbyStream;

	MbNumX = (openParam->picWidth+15)/16;
	MbNumY = (openParam->picHeight+15)/16;

	VLC_NaluInit(&Bitstream, 3, 7);
	PutBits(&Bitstream, 66, 8);                  ///< 8  : profile_idc
	PutBits(&Bitstream, 0, 1);                   ///< 1  : constraint_set0_flag
	PutBits(&Bitstream, 1, 1);                   ///< 1  : constraint_set1_flag
	PutBits(&Bitstream, 0, 1);                   ///< 1  : constraint_set2_flag
	PutBits(&Bitstream, 0, 5);                   ///< 5  : reserved_zero_5bits
	if (!avcParam->avc_level) {
		avcParam->avc_level = LevelCalculation(MbNumX, MbNumY, openParam->frameRateInfo, 0, BitRate, SliceNum);
		if (avcParam->avc_level < 0)
			return -1;
	}
	PutBits(&Bitstream, avcParam->avc_level, 8); ///< 8  : level_idc
	PutUE(&Bitstream, 0);                        ///< ue : seq_parameter_set_id [0-31]
	PutUE(&Bitstream, 1);                        ///< ue : log2_max_frame_num_minus4 [0-12]
	PutUE(&Bitstream, 2);			     ///< ue : pic_order_cnt_type [0-2]

	PutUE(&Bitstream, 1);                        ///< ue : num_ref_frames

	PutBits(&Bitstream, 0, 1);                   ///< 1  : gaps_in_frame_num_value_allowed_flag

	// MaxMbNumY should be MaxMbNumX for the case of rotation
	if (RotFlag) {
		PutUE(&Bitstream, MbNumY-1);         ///< ue : pic_width_in_mbs_minus1
		PutUE(&Bitstream, MbNumX-1);         ///< ue : pic_height_in_map_units_minus1
	}
	else {
		PutUE(&Bitstream, MbNumX-1);         ///< ue : pic_width_in_mbs_minus1
		PutUE(&Bitstream, MbNumY-1);         ///< ue : pic_height_in_map_units_minus1
	}
	PutBits(&Bitstream, 1, 1);                   ///< 1  : frame_mbs_only_flag
	PutBits(&Bitstream, 1, 1);                   ///< 1  : direct_8x8_inference_flag

	if (avcParam->avc_frameCroppingFlag) {
		PutBits(&Bitstream, 1, 1);                        ///< 1  : frame_cropping_flag
		PutUE(&Bitstream, avcParam->avc_frameCropLeft >> 1);   ///< ue : frame_crop_left_offset
		PutUE(&Bitstream, avcParam->avc_frameCropRight >> 1);  ///< ue : frame_crop_right_offset
		PutUE(&Bitstream, avcParam->avc_frameCropTop >> 1);    ///< ue : frame_crop_top_offset
		PutUE(&Bitstream, avcParam->avc_frameCropBottom >> 1); ///< ue : frame_crop_bottom_offset
	}
	else
		PutBits(&Bitstream, 0, 1);                        ///< 1  : frame_cropping_flag
	if (avcParam->avc_vui_present_flag)
	{ // VUI PARAM
		VuiParam *pVuiParam = &avcParam->avc_vui_param;
		PutBits(&Bitstream, 1, 1);                        ///< 1  : vui_parameters_present_flag
		//vui_parameters()
		PutBits(&Bitstream, 0, 1);                        ///< 1  : aspect_ratio_info_present_flag
		PutBits(&Bitstream, 0, 1);                        ///< 1  : overscan_info_present_flag

		PutBits(&Bitstream, pVuiParam->video_signal_type_pres_flag, 1);              ///< 1  : video_signal_type_present_flag
		if (pVuiParam->video_signal_type_pres_flag) {
			PutBits(&Bitstream, pVuiParam->video_format, 3);                     ///< 3  : video_format
			PutBits(&Bitstream, pVuiParam->video_full_range_flag, 1);            ///< 1  : video_full_range_flag
			PutBits(&Bitstream, pVuiParam->colour_descrip_pres_flag, 1);	     ///< 1  : colour_description_present_flag
			if (pVuiParam->colour_descrip_pres_flag) {
				PutBits(&Bitstream, pVuiParam->colour_primaries, 8);         ///< 8  : colour_primaries
				PutBits(&Bitstream, pVuiParam->transfer_characteristics, 8); ///< 8  : transfer_characteristics
				PutBits(&Bitstream, pVuiParam->matrix_coeff, 8);             ///< 8  : matrix_coefficients
			}
		}

		PutBits(&Bitstream, 0, 1); ///< 1  : chroma_loc_info_present_flag
		PutBits(&Bitstream, 0, 1); ///< 1  : timing_info_present_flag
		PutBits(&Bitstream, 0, 1); ///< 1  : nal_hrd_parameters_present_flag
		PutBits(&Bitstream, 0, 1); ///< 1  : vcl_hrd_parameters_present_flag

		PutBits(&Bitstream, 0, 1); ///< 1  : pic_struct_present_flag
		PutBits(&Bitstream, 1, 1); ///< 1  : bitstream_restriction_flag
		PutBits(&Bitstream, 1, 1); ///< 1  : motion_vectors_over_pic_boundaries_flag
		PutUE(&Bitstream, 0);      ///< 1  : max_bytes_per_pic_denom (unlimited)
		PutUE(&Bitstream, 0);      ///< 1  : max_bits_per_mb_denom (unlimited)
		PutUE(&Bitstream, 8);      ///< 1  : log2_max_mv_length_horizontal
		PutUE(&Bitstream, 8);      ///< 1  : log2_max_mv_length_vertical
		PutUE(&Bitstream, 0);      ///< 1  : num_reoder_frames 0
		PutUE(&Bitstream, 1);      ///< 1  : max_dec_frame_buffering 16
	}
	else
		PutBits(&Bitstream, 0, 1);

	return VCL_NaluClose(&Bitstream);
}


/* 32 bit / 16 bit ==> 32-n bit remainder, n bit quotient */
static int fixDivRq(int a, int b, int n)
{
	Int64 c;
	Int64 a_36bit;
	Int64 mask, signBit, signExt;
	int  i;

	// DIVS emulation for BPU accumulator size
	// For SunOS build
	mask = 0x0F; mask <<= 32; mask |= 0x00FFFFFFFF; // mask = 0x0FFFFFFFFF;
	signBit = 0x08; signBit <<= 32;                 // signBit = 0x0800000000;
	signExt = 0xFFFFFFF0; signExt <<= 32;           // signExt = 0xFFFFFFF000000000;

	a_36bit = (Int64) a;

	for (i=0; i<n; i++) {
		c =  a_36bit - (b << 15);
		if (c >= 0)
			a_36bit = (c << 1) + 1;
		else
			a_36bit = a_36bit << 1;

		a_36bit = a_36bit & mask;
		if (a_36bit & signBit)
			a_36bit |= signExt;
	}

	a = (int) a_36bit;
	return a;               // R = [31:n], Q = [n-1:0]
}

static int fixDivRnd(int a, int b)
{
	int  c;
	c = fixDivRq(a, b, 17); // R = [31:17], Q = [16:0]
	c = c & 0xFFFF;
	c = (c + 1) >> 1;       // round
	return (c & 0xFFFF);
}

int RcFixDivRnd(int res, int div)
{
	return fixDivRnd(res, div);
}

int LevelCalculation(int MbNumX, int MbNumY, int frameRateInfo, int interlaceFlag, int BitRate, int SliceNum)
{
	int mbps;
	int frameRateDiv, frameRateRes, frameRate;
	int mbPicNum = (MbNumX*MbNumY);
	int mbFrmNum;
	int MaxSliceNum;

	int LevelIdc = 0;
	int i, maxMbs;

	if (interlaceFlag) {
		mbFrmNum = mbPicNum * 2;
		MbNumY   *= 2;
	}
	else mbFrmNum = mbPicNum;

	frameRateDiv = (frameRateInfo >> 16) + 1;
	frameRateRes = frameRateInfo & 0xFFFF;
	frameRate = fixDivRnd(frameRateRes, frameRateDiv);
	mbps = mbFrmNum * frameRate;

	for(i=0; i<MAX_LEVEL_IDX; i++) {
		maxMbs = g_anLevelMaxMbs[i];
		if (mbps <= g_anLevelMaxMBPS[i]
				&& mbFrmNum <= g_anLevelMaxFS[i]
				&& MbNumX   <= maxMbs
				&& MbNumY   <= maxMbs
				&& BitRate  <= g_anLevelMaxBR[i])
		{
			LevelIdc = g_anLevel[i];
			break;
		}
	}

	if (i == MAX_LEVEL_IDX)
		i = MAX_LEVEL_IDX - 1;

	if (SliceNum) {
		SliceNum = fixDivRnd(mbPicNum, SliceNum);

		if (g_anLevelSliceRate[i]) {
			MaxSliceNum = fixDivRnd(MAX(mbPicNum, g_anLevelMaxMBPS[i]/(172/(1+interlaceFlag))), g_anLevelSliceRate[i]);

			if (SliceNum > MaxSliceNum)
				return -1;
		}
	}

	return LevelIdc;
}

#ifdef LOG_TIME
int log_time(int inst, Event evt)
{
	struct timeval tv;
	long long sec, usec;
	long long time;

	gettimeofday(&tv, NULL);
	sec = tv.tv_sec;
	usec = tv.tv_usec;
	time = (sec * 1000) + usec/1000;
	info_msg("[%d][%d]%lld\n", inst, evt, time);
	return 0;
}
#endif

