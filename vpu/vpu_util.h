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

#ifndef _VPU_UTIL_H_
#define _VPU_UTIL_H_

#include "vpu_reg.h"
#include "vpu_lib.h"

#define MAX_FW_BINARY_LEN		100000
#define MAX_NUM_INSTANCE		4

#if defined(IMX37_3STACK)
enum {
	AVC_DEC = 0,
	VC1_DEC = 1,
	MP2_DEC = 2,
	MP4_DEC = 3,
	DV3_DEC = 4,
	/* dummy */
	AVC_ENC = 0x7F,
	MP4_ENC = 0x80,
	RV_DEC = 0x81,
	MJPG_DEC = 0x82,
	MJPG_ENC = 0x83
};
#elif defined(IMX51_3STACK)
enum {
	AVC_DEC = 0,
	VC1_DEC = 1,
	MP2_DEC = 2,
	MP4_DEC = 3,
	DV3_DEC = 3,
	RV_DEC = 4,
	MJPG_DEC = 5,
	AVC_ENC = 8,
	MP4_ENC = 11,
	MJPG_ENC = 13
} ;
#else
enum {
	MP4_DEC = 0,
	MP4_ENC = 1,
	AVC_DEC = 2,
	AVC_ENC = 3,
	VC1_DEC = 4,
	MP2_DEC = 5,
	DV3_DEC = 6,
	/* dummy */
	RV_DEC = 0x81,
	MJPG_DEC = 0x82,
	MJPG_ENC = 0x83
};
#endif

enum {
	SEQ_INIT = 1,
	SEQ_END = 2,
	PIC_RUN = 3,
	SET_FRAME_BUF = 4,
	ENCODE_HEADER = 5,
	ENC_PARA_SET = 6,
	DEC_PARA_SET = 7,
	DEC_BUF_FLUSH = 8,
	RC_CHANGE_PARAMETER = 9,
	FIRMWARE_GET = 0xf
};

void BitIssueCommand(int instIdx, int cdcMode, int cmd);

RetCode LoadBitCodeTable(Uint16 * pBitCode, int *size);

RetCode GetCodecInstance(CodecInst ** ppInst);
void FreeCodecInstance(CodecInst * pCodecInst);

RetCode CheckInstanceValidity(CodecInst * pci);
RetCode CheckEncInstanceValidity(EncHandle handle);
RetCode CheckEncOpenParam(EncOpenParam * pop);
RetCode CheckEncParam(CodecInst * pCodecInst, EncParam * param);
void EncodeHeader(EncHandle handle, EncHeaderParam * encHeaderParam);
void GetParaSet(EncHandle handle, int paraSetType, EncParamSet * para);

RetCode CheckDecInstanceValidity(DecHandle handle);
RetCode CheckDecOpenParam(DecOpenParam * pop);
int DecBitstreamBufEmpty(DecInfo * pDecInfo);
void SetParaSet(DecHandle handle, int paraSetType, DecParamSet * para);

RetCode SetGopNumber(EncHandle handle, Uint32 *gopNumber);
RetCode SetIntraQp(EncHandle handle, Uint32 *intraQp);
RetCode SetBitrate(EncHandle handle, Uint32 *bitrate);
RetCode SetFramerate(EncHandle handle, Uint32 *framerate);
RetCode SetIntraRefreshNum(EncHandle handle, Uint32 *pIntraRefreshNum);
RetCode SetSliceMode(EncHandle handle, EncSliceMode *pSliceMode);
RetCode SetHecMode(EncHandle handle, int mode);
#endif
