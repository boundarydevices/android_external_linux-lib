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
 * @file vpu_lib.h
 *
 * @brief header file for codec API funcitons for VPU
 *
 * @ingroup VPU
 */

#ifndef __VPU__LIB__H
#define __VPU__LIB__H

typedef unsigned char Uint8;
typedef unsigned long Uint32;
typedef unsigned short Uint16;
typedef Uint32 PhysicalAddress;

#define	USE_BIT_INTERNAL_BUF		1
#define USE_IP_INTERNAL_BUF		1
#define	USE_DBK_INTERNAL_BUF		1
#define	USE_OVL_INTERNAL_BUF		1

#define STREAM_FULL_EMPTY_CHECK_DISABLE 0

#define BIT_REG_MARGIN			0x1000

#define PRJ_TRISTAN     		0xF000
#define PRJ_TRISTAN_REV			0xF001
#define PRJ_PRISM_CX			0xF002
#define PRJ_SHIVA       		0xF003
#define PRJ_PRISM_EX			0xF004
#define PRJ_BODA_CX_4			0xF005
#define PRJ_CODA_DX_6M			0xF100
#define PRJ_CODA_DX_8			0xF306
#define PRJ_BODA_DX_4V			0xF405
#define PRJ_BODADX7X			0xF009

typedef enum {
	STD_MPEG4 = 0,
	STD_H263,
	STD_AVC,
	STD_VC1,
	STD_MPEG2,
	STD_DIV3
} CodStd;

typedef enum {
	RETCODE_SUCCESS = 0,
	RETCODE_FAILURE = -1,
	RETCODE_INVALID_HANDLE = -2,
	RETCODE_INVALID_PARAM = -3,
	RETCODE_INVALID_COMMAND = -4,
	RETCODE_ROTATOR_OUTPUT_NOT_SET = -5,
	RETCODE_ROTATOR_STRIDE_NOT_SET = -11,
	RETCODE_FRAME_NOT_COMPLETE = -6,
	RETCODE_INVALID_FRAME_BUFFER = -7,
	RETCODE_INSUFFICIENT_FRAME_BUFFERS = -8,
	RETCODE_INVALID_STRIDE = -9,
	RETCODE_WRONG_CALL_SEQUENCE = -10,
	RETCODE_CALLED_BEFORE = -12,
	RETCODE_NOT_INITIALIZED = -13,
	RETCODE_DEBLOCKING_OUTPUT_NOT_SET = -14,
	RETCODE_NOT_SUPPORTED = -15
} RetCode;

typedef enum {
	ENABLE_ROTATION,
	DISABLE_ROTATION,
	ENABLE_MIRRORING,
	DISABLE_MIRRORING,
	ENABLE_DERING,
	DISABLE_DERING,
	SET_MIRROR_DIRECTION,
	SET_ROTATION_ANGLE,
	SET_ROTATOR_OUTPUT,
	SET_ROTATOR_STRIDE,
	ENC_GET_SPS_RBSP,
	ENC_GET_PPS_RBSP,
	DEC_SET_SPS_RBSP,
	DEC_SET_PPS_RBSP,
	ENC_PUT_MP4_HEADER,
	ENC_PUT_AVC_HEADER,
	ENC_SET_SEARCHRAM_PARAM,
	ENC_GET_VOS_HEADER,
	ENC_GET_VO_HEADER,
	ENC_GET_VOL_HEADER,
	DEC_SET_DEBLOCK_OUTPUT,
	ENC_SET_INTRA_MB_REFRESH_NUMBER,
	ENC_ENABLE_HEC,
	ENC_DISABLE_HEC,
	ENC_SET_SLICE_INFO,
	ENC_SET_GOP_NUMBER,
	ENC_SET_INTRA_QP,
	ENC_SET_BITRATE,
	ENC_SET_FRAME_RATE
} CodecCommand;

typedef struct {
	PhysicalAddress bufY;
	PhysicalAddress bufCb;
	PhysicalAddress bufCr;
	PhysicalAddress bufMvCol;
} FrameBuffer;

typedef struct {
	Uint32 left;
	Uint32 top;
	Uint32 right;
	Uint32 bottom;
} Rect;

typedef enum {
	MIRDIR_NONE,
	MIRDIR_VER,
	MIRDIR_HOR,
	MIRDIR_HOR_VER
} MirrorDirection;

/* Decode struct and definition */
typedef struct CodecInst DecInst;
typedef DecInst *DecHandle;

typedef struct {
	CodStd bitstreamFormat;
	PhysicalAddress bitstreamBuffer;
	int bitstreamBufferSize;
	int qpReport;
	int mp4DeblkEnable;
	int reorderEnable;
	int chromaInterleave;
	int filePlayEnable;
	int picWidth;
	int picHeight;
	int dynamicAllocEnable;
	int streamStartByteOffset;
	PhysicalAddress psSaveBuffer;
	int psSaveBufferSize;
} DecOpenParam;

typedef struct {
	int picWidth;		// {(PicX+15)/16} * 16
	int picHeight;		// {(PicY+15)/16} * 16
	Uint32 frameRateInfo;
	Rect picCropRect;
	
	int mp4_dataPartitionEnable;
	int mp4_reversibleVlcEnable;
	int mp4_shortVideoHeader;
	int h263_annexJEnable;

	int minFrameBufferCount;
	int frameBufDelay;
	int nextDecodedIdxNum;
	int normalSliceSize;
	int worstSliceSize;
} DecInitialInfo;

typedef struct {
	int sliceMode;
	int sliceSizeMode;
	int sliceSize;
} EncSliceMode;

typedef struct {
	PhysicalAddress sliceSaveBuffer;
	int sliceSaveBufferSize;
} DecAvcSliceBufInfo;

typedef struct {
	DecAvcSliceBufInfo avcSliceBufInfo;
} DecBufInfo;

typedef struct {
	int prescanEnable;
	int prescanMode;
	int dispReorderBuf;
	int iframeSearchEnable;
	int skipframeMode;
	int skipframeNum;
	int vpuCountEnable;
	int chunkSize;
	int picStartByteOffset;
	PhysicalAddress picStreamBufferAddr;
} DecParam;

typedef struct {
	int indexFrameDisplay;
	int indexFrameDecoded;
	int picType;
	int numOfErrMBs;
	PhysicalAddress qpInfo;
	int DecVpuCount;
	int hScaleFlag;
	int vScaleFlag;
	int prescanresult;
	int indexFrameNextDecoded[3];
	int notSufficientPsBuffer;
	int notSufficientSliceBuffer;
} DecOutputInfo;

typedef struct {
	Uint32 *paraSet;
	int size;
} DecParamSet;

/* encode struct and definition */
typedef struct CodecInst EncInst;
typedef EncInst *EncHandle;

typedef struct {
	int mp4_dataPartitionEnable;
	int mp4_reversibleVlcEnable;
	int mp4_intraDcVlcThr;
	int mp4_hecEnable;
	int mp4_verid;
} EncMp4Param;

typedef struct {
	int h263_annexJEnable;
	int h263_annexKEnable;
	int h263_annexTEnable;
} EncH263Param;

typedef struct {
	int avc_constrainedIntraPredFlag;
	int avc_disableDeblk;
	int avc_deblkFilterOffsetAlpha;
	int avc_deblkFilterOffsetBeta;
	int avc_chromaQpOffset;
	int avc_audEnable;
	int avc_fmoEnable;
	int avc_fmoSliceNum;
	int avc_fmoType;
} EncAvcParam;

typedef struct {
	PhysicalAddress bitstreamBuffer;
	Uint32 bitstreamBufferSize;
	CodStd bitstreamFormat;

	int picWidth;
	int picHeight;
	Uint32 frameRateInfo;
	int bitRate;
	int initialDelay;
	int vbvBufferSize;
	int enableAutoSkip;
	int gopSize;
	
	EncSliceMode slicemode;
	int intraRefresh;

	int sliceReport;
	int mbReport;
	int mbQpReport;
	int rcIntraQp;
	int chromaInterleave;
	int dynamicAllocEnable;
	int ringBufferEnable;

	union {
		EncMp4Param mp4Param;
		EncH263Param h263Param;
		EncAvcParam avcParam;
	} EncStdParam;
} EncOpenParam;

typedef struct {
	int minFrameBufferCount;
} EncInitialInfo;

typedef struct {
	FrameBuffer *sourceFrame;
	int forceIPicture;
	int skipPicture;
	int quantParam;
	int vpuCountEnable;
	PhysicalAddress picStreamBufferAddr;
	int picStreamBufferSize;
	int intraRefresh;
	int hecEnable;
	EncSliceMode slicemode;
} EncParam;

typedef struct {
	PhysicalAddress bitstreamBuffer;
	Uint32 bitstreamSize;
	int bitstreamWrapAround;
	int picType;
	int numOfSlices;
	Uint32 *sliceInfo;
	Uint32 *mbInfo;
	int EncVpuCount;
	Uint32 *mbQpInfo;
} EncOutputInfo;

typedef struct {
	Uint32 *paraSet;
	int size;
} EncParamSet;

typedef struct {
	PhysicalAddress searchRamAddr;
	int SearchRamSize;
} SearchRamParam;

typedef struct {
	PhysicalAddress buf;
	int size;
	int headerType;
} EncHeaderParam;

typedef enum {
	VOL_HEADER,		/* video object layer header */
	VOS_HEADER,		/* visual object sequence header */
	VIS_HEADER		/* video object header */
} Mp4HeaderType;

typedef enum {
	SPS_RBSP,
	PPS_RBSP
} AvcHeaderType;

typedef struct {
	Uint32 gopNumber;
	Uint32 intraQp;
	Uint32 bitrate;
	Uint32 framerate;
} stChangeRcPara;

typedef struct {
	EncOpenParam openParam;
	EncInitialInfo initialInfo;

	PhysicalAddress streamRdPtr;
	PhysicalAddress streamRdPtrRegAddr;
	PhysicalAddress streamWrPtrRegAddr;
	PhysicalAddress streamBufStartAddr;
	PhysicalAddress streamBufEndAddr;
	int streamBufSize;
	
	FrameBuffer *frameBufPool;
	int numFrameBuffers;
	int stride;
	
	int rotationEnable;
	int mirrorEnable;
	MirrorDirection mirrorDirection;
	int rotationAngle;
	
	int initialInfoObtained;
	int vpuCountEnable;
	int dynamicAllocEnable;
	int ringBufferEnable;
} EncInfo;

typedef struct {
	DecOpenParam openParam;
	DecInitialInfo initialInfo;

	PhysicalAddress streamWrPtr;
	PhysicalAddress streamRdPtrRegAddr;
	PhysicalAddress streamWrPtrRegAddr;
	PhysicalAddress streamBufStartAddr;
	PhysicalAddress streamBufEndAddr;
	int streamBufSize;
	
	FrameBuffer *frameBufPool;
	int numFrameBuffers;
	FrameBuffer *recFrame;
	int stride;
	
	int rotationEnable;
	int deringEnable;
	int mirrorEnable;
	MirrorDirection mirrorDirection;
	int rotationAngle;
	FrameBuffer rotatorOutput;
	int rotatorStride;
	int rotatorOutputValid;
	int initialInfoObtained;
	
	FrameBuffer deBlockingFilterOutput;
	int deBlockingFilterOutputValid;
	
	int vpuCountEnable;
	int filePlayEnable;
	int picSrcSize;
	int dynamicAllocEnable;
	int vc1BframeDisplayValid;
} DecInfo;

typedef struct CodecInst {
	int instIndex;
	int inUse;
	int codecMode;
	union {
		EncInfo encInfo;
		DecInfo decInfo;
	} CodecInfo;
} CodecInst;

typedef struct vpu_versioninfo {
	int fw_major;		/* firmware major version */
	int fw_minor;		/* firmware minor version */
	int fw_release;		/* firmware release version */
	int lib_major;		/* library major version */
	int lib_minor;		/* library minor version */
	int lib_release;	/* library release version */
} vpu_versioninfo;

#define VPU_FW_VERSION(major, minor, release)	 \
	(((major) << 12) + ((minor) << 8) + (release))

#define VPU_LIB_VERSION(major, minor, release)	 \
	(((major) << 12) + ((minor) << 8) + (release))

#define VPU_LIB_VERSION_CODE	VPU_LIB_VERSION(3, 0, 1)

RetCode vpu_Init(PhysicalAddress workBuf);
RetCode vpu_GetVersionInfo(vpu_versioninfo * verinfo);

RetCode vpu_EncOpen(EncHandle *, EncOpenParam *);
RetCode vpu_EncClose(EncHandle);
RetCode vpu_EncGetInitialInfo(EncHandle, EncInitialInfo *);
RetCode vpu_EncRegisterFrameBuffer(EncHandle handle,
				   FrameBuffer * bufArray, int num, int stride);
RetCode vpu_EncGetBitstreamBuffer(EncHandle handle, PhysicalAddress * prdPrt,
				  PhysicalAddress * pwrPtr, Uint32 * size);
RetCode vpu_EncUpdateBitstreamBuffer(EncHandle handle, Uint32 size);
RetCode vpu_EncStartOneFrame(EncHandle handle, EncParam * param);
RetCode vpu_EncGetOutputInfo(EncHandle handle, EncOutputInfo * info);
RetCode vpu_EncGiveCommand(EncHandle handle, CodecCommand cmd, void *parameter);

RetCode vpu_DecOpen(DecHandle *, DecOpenParam *);
RetCode vpu_DecClose(DecHandle);
RetCode vpu_DecSetEscSeqInit(DecHandle handle, int escape);
RetCode vpu_DecGetInitialInfo(DecHandle handle, DecInitialInfo * info);
RetCode vpu_DecRegisterFrameBuffer(DecHandle handle,
				   FrameBuffer * bufArray, int num, int stride,
				   DecBufInfo *pBufInfo);
RetCode vpu_DecGetBitstreamBuffer(DecHandle handle, PhysicalAddress * paRdPtr,
				  PhysicalAddress * paWrPtr, Uint32 * size);
RetCode vpu_DecUpdateBitstreamBuffer(DecHandle handle, Uint32 size);
RetCode vpu_DecStartOneFrame(DecHandle handle, DecParam * param);
RetCode vpu_DecGetOutputInfo(DecHandle handle, DecOutputInfo * info);
RetCode vpu_DecBitBufferFlush(DecHandle handle);
RetCode vpu_DecGiveCommand(DecHandle handle, CodecCommand cmd, void *parameter);

int vpu_IsBusy(void);
int platform_is_mx27(void);
int platform_is_mx27to2(void);
int platform_is_mx27to1(void);
int platform_is_mx32(void);
int platform_is_mx37(void);
int platform_is_mxc30031(void);
int vpu_WaitForInt(int timeout_in_ms);

void SaveQpReport(PhysicalAddress qpReportAddr, int picWidth, int picHeight,
		  int frameIdx, char *fileName);
void SaveGetEncodeHeader(EncHandle handle, int encHeaderType, char *filename);

#endif
