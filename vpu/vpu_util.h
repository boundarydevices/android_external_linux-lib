/*
 * Copyright 2004-2011 Freescale Semiconductor, Inc.
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

#include <sys/types.h>
#include <pthread.h>
#include <errno.h>

#include "vpu_reg.h"
#include "vpu_lib.h"
#include "vpu_io.h"
#include "sw_gbu.h"

#define MAX_FW_BINARY_LEN		200 * 1024
#define MAX_NUM_INSTANCE		8

#define BIT_WORK_SIZE			0x20000
#define SIZE_CONTEXT_BUF		BIT_WORK_SIZE

#define SIZE_PIC_PARA_BASE_BUF          0x100
#define SIZE_MV_DATA                    0x20000
#define SIZE_MB_DATA                    0x4000
#define SIZE_FRAME_BUF_STAT             0x100
#define SIZE_SLICE_INFO                 0x4000
#define USER_DATA_INFO_OFFSET           8*17

#define ADDR_PIC_PARA_BASE_OFFSET       0
#define ADDR_MV_BASE_OFFSET             ADDR_PIC_PARA_BASE_OFFSET + SIZE_PIC_PARA_BASE_BUF
#define ADDR_MB_BASE_OFFSET             ADDR_MV_BASE_OFFSET + SIZE_MV_DATA
#define ADDR_FRAME_BUF_STAT_BASE_OFFSET ADDR_MB_BASE_OFFSET + SIZE_MB_DATA
#define ADDR_SLICE_BASE_OFFSET          ADDR_MB_BASE_OFFSET + SIZE_MB_DATA
#define ENC_ADDR_END_OF_RPT_BUF         ADDR_FRAME_BUF_STAT_BASE_OFFSET + SIZE_SLICE_INFO
#define DEC_ADDR_END_OF_RPT_BUF         ADDR_FRAME_BUF_STAT_BASE_OFFSET + SIZE_FRAME_BUF_STAT

#define DC_TABLE_INDEX0		    0
#define AC_TABLE_INDEX0		    1
#define DC_TABLE_INDEX1		    2
#define AC_TABLE_INDEX1		    3
#define Q_COMPONENT0		    0
#define Q_COMPONENT1		    0x40
#define Q_COMPONENT2		    0x80

#if defined(IMX51) || defined(IMX53)
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
	MJPG_ENC = 13,
	/* dummy */
	AVS_DEC = 0x81,
	VPX_DEC = 0x82
} ;
#elif defined(IMX6Q)
enum {
	AVC_DEC = 0,
	VC1_DEC = 1,
	MP2_DEC = 2,
	MP4_DEC = 3,
	DV3_DEC = 3,
	RV_DEC = 4,
	AVS_DEC = 5,
	MJPG_DEC = 6,
	VPX_DEC = 7,
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
	MP4_AUX_MPEG4 = 0,
	MP4_AUX_DIVX3 = 1
};

enum {
	VPX_AUX_THO = 0,
	VPX_AUX_VP6 = 1,
	VPX_AUX_VP8 = 2
};

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
	VPU_WAKE = 11,
	FIRMWARE_GET = 0xf
};

enum {
	API_MUTEX = 0,
	REG_MUTEX = 1
};

enum {
	CTX_BIT_STREAM_PARAM = 0,
	CTX_BIT_FRM_DIS_FLG,
	CTX_BIT_WR_PTR,
	CTX_BIT_RD_PTR,
	CTX_BIT_FRAME_MEM_CTRL,
	CTX_MAX_REGS
};

enum {
	Marker          = 0xFF,
	FF_Marker       = 0x00,
	SOI_Marker      = 0xFFD8,           // Start of image
	EOI_Marker      = 0xFFD9,           // End of image
	JFIF_CODE       = 0xFFE0,           // Application
	EXIF_CODE       = 0xFFE1,
	DRI_Marker      = 0xFFDD,           // Define restart interval
	RST_Marker      = 0xD,              // 0xD0 ~0xD7
	DQT_Marker      = 0xFFDB,           // Define quantization table(s)
	DHT_Marker      = 0xFFC4,           // Define Huffman table(s)
	SOF_Marker      = 0xFFC0,           // Start of frame : Baseline DCT
	SOS_Marker      = 0xFFDA,           // Start of scan
};
typedef struct {
	int useBitEnable;
	int useIpEnable;
	int useDbkEnable;
	int useDbkYEnable;
	int useDbkCEnable;
	int useOvlEnable;
	int useBtpEnable;
	int useMeEnable;

	int useHostBitEnable;
	int useHostIpEnable;
	int useHostDbkEnable;
	int useHostDbkYEnable;
	int useHostDbkCEnable;
	int useHostBtpEnable;
	int useHostOvlEnable;
	int useHostMeEnable;

	PhysicalAddress bufBitUse;
	PhysicalAddress bufIpAcDcUse;
	PhysicalAddress bufDbkYUse;
	PhysicalAddress bufDbkCUse;
	PhysicalAddress bufOvlUse;
	PhysicalAddress bufBtpUse;

	PhysicalAddress searchRamAddr;
	int searchRamSize;

} SecAxiUse;

typedef struct CacheSizeCfg {
    unsigned BufferSize : 8;
    unsigned PageSizeX  : 4;
    unsigned PageSizeY  : 4;
    unsigned CacheSizeX : 4;
    unsigned CacheSizeY : 4;
    unsigned Reserved   : 8;
} CacheSizeCfg;

typedef struct {
    union {
        Uint32 word;
        CacheSizeCfg cfg;
    } luma;
    union {
        Uint32 word;
        CacheSizeCfg cfg;
    } chroma;
    unsigned Bypass : 1;
    unsigned DualConf : 1;
    unsigned PageMerge : 2;
} MaverickCacheConfig;

typedef struct {
    Uint32 *paraSet;
    int size;
} DecParamSet;

typedef struct {
    int enable;
    int is_secondary;
    PhysicalAddress start_address;
    PhysicalAddress end_address;
} WriteMemProtectRegion;

typedef struct {
    WriteMemProtectRegion region[6];
} WriteMemProtectCfg;

typedef struct {
	int width;
	int codecMode;
	int profile;
} SetIramParam;

typedef struct {
	unsigned subFrameSyncOn : 1;
	unsigned sourceBufNumber : 7;
	unsigned sourceBufIndexBase : 8;
} EncSubFrameSyncConfig;

typedef struct {
	int picWidth;
	int picHeight;
	int alignedWidth;
	int alignedHeight;
	int seqInited;
	int frameIdx;
	int format;

	int rstIntval;
	int busReqNum;
	int mcuBlockNum;
	int compNum;
	int compInfo[3];

	Uint32 huffCode[4][256];
	Uint32 huffSize[4][256];
	Uint8 *pHuffVal[4];
	Uint8 *pHuffBits[4];
	Uint8 *pCInfoTab[4];
	Uint8 *pQMatTab[4];

} JpgEncInfo;

typedef struct {
	EncOpenParam openParam;
	EncInitialInfo initialInfo;

	PhysicalAddress streamRdPtr;
	PhysicalAddress streamBufStartAddr;
	PhysicalAddress streamBufEndAddr;
	int streamBufSize;

	FrameBuffer *frameBufPool;
	int numFrameBuffers;
	int stride;
	int srcFrameWidth;
	int srcFrameHeight;

	int rotationEnable;
	int mirrorEnable;
	MirrorDirection mirrorDirection;
	int rotationAngle;

	int initialInfoObtained;
	int dynamicAllocEnable;
	int ringBufferEnable;

	SecAxiUse secAxiUse;
	MaverickCacheConfig cacheConfig;
	EncSubFrameSyncConfig subFrameSyncConfig;
	JpgEncInfo jpgInfo;

	EncReportInfo encReportMBInfo;
	EncReportInfo encReportMVInfo;
	EncReportInfo encReportSliceInfo;

	vpu_mem_desc picParaBaseMem;
	vpu_mem_desc searchRamMem; /* Used if IRAM is disabled */

} EncInfo;

typedef struct {
    /* for Nieuport */
    int picWidth;
    int picHeight;
    int alignedWidth;
    int alignedHeight;

    int ecsPtr;
    int format;
    int rstIntval;

    int userHuffTab;

    int huffDcIdx;
    int huffAcIdx;
    int Qidx;

    Uint8 huffVal[4][162];
    Uint8 huffBits[4][256];
    Uint8 cInfoTab[4][6];
    Uint8 qMatTab[4][64];

    Uint32 huffMin[4][16];
    Uint32 huffMax[4][16];
    Uint8 huffPtr[4][16];

    int busReqNum;
    int compNum;
    int mcuBlockNum;
    int compInfo[3];

    int frameIdx;
    int seqInited;

    Uint8 *pHeader;
    int headerSize;
    GetBitContext gbc;
} JpgDecInfo;

typedef struct {
	DecOpenParam openParam;
	DecInitialInfo initialInfo;

	PhysicalAddress streamWrPtr;
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

	int filePlayEnable;
	int picSrcSize;
	int dynamicAllocEnable;
	int vc1BframeDisplayValid;
	int mapType;
	int tiledLinearEnable;

	DbkOffset dbkOffset;

	SecAxiUse secAxiUse;
	MaverickCacheConfig cacheConfig;
	JpgDecInfo jpgInfo;

	vpu_mem_desc picParaBaseMem;
	vpu_mem_desc userDataBufMem;

	DecReportInfo decReportFrameBufStat; /* Frame Buffer Status */
	DecReportInfo decReportMBInfo;      /* Mb Param for Error Concealment */
	DecReportInfo decReportMVInfo;     /* Motion vector */
	DecReportInfo decReportUserData;
} DecInfo;

typedef struct CodecInst {
	int instIndex;
	int inUse;
	int codecMode;
	int codecModeAux;
	vpu_mem_desc contextBufMem; /* For context buffer */
	unsigned long ctxRegs[CTX_MAX_REGS];
	union {
		EncInfo encInfo;
		DecInfo decInfo;
	} CodecInfo;
	union {
		EncParam encParam;
		DecParam decParam;
	} CodecParam;
} CodecInst;

typedef struct {
	int is_initialized;
	pthread_mutex_t api_lock;
	pthread_mutex_t reg_lock;

	/* VPU data for sharing */
	CodecInst codecInstPool[MAX_NUM_INSTANCE];
	CodecInst *pendingInst;
} semaphore_t;

void BitIssueCommand(int instIdx, int cdcMode, int cdcModeAux, int cmd);
void BitIssueCommandEx(CodecInst *pCodecInst, int cmd);

RetCode LoadBitCodeTable(Uint16 * pBitCode, int *size);
RetCode DownloadBitCodeTable(unsigned long *virtCodeBuf, Uint16 *bit_code);

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
int DecBitstreamBufEmpty(DecHandle handle);
void SetParaSet(DecHandle handle, int paraSetType, DecParamSet * para);
RetCode CopyBufferData(Uint8 *dst, Uint8 *src, int size);

RetCode SetGopNumber(EncHandle handle, Uint32 *gopNumber);
RetCode SetIntraQp(EncHandle handle, Uint32 *intraQp);
RetCode SetBitrate(EncHandle handle, Uint32 *bitrate);
RetCode SetFramerate(EncHandle handle, Uint32 *framerate);
RetCode SetIntraRefreshNum(EncHandle handle, Uint32 *pIntraRefreshNum);
RetCode SetSliceMode(EncHandle handle, EncSliceMode *pSliceMode);
RetCode SetHecMode(EncHandle handle, int mode);

void SetDecSecondAXIIRAM(SecAxiUse *psecAxiIramInfo, SetIramParam *parm);
void SetEncSecondAXIIRAM(SecAxiUse *psecAxiIramInfo, SetIramParam *parm);

semaphore_t *vpu_semaphore_open(void);
void semaphore_post(semaphore_t *semap, int mutex);
unsigned char semaphore_wait(semaphore_t *semap, int mutex);
void vpu_semaphore_close(semaphore_t *semap);

static inline unsigned char LockVpu(semaphore_t *semap)
{
	if (!semaphore_wait(semap, API_MUTEX))
		return false;
	IOClkGateSet(1);
	return true;
}

static inline void UnlockVpu(semaphore_t *semap)
{
	semaphore_post(semap, API_MUTEX);
	IOClkGateSet(0);
}

static inline unsigned char LockVpuReg(semaphore_t *semap)
{
	if (!semaphore_wait(semap, REG_MUTEX))
		return false;
	IOClkGateSet(1);
	return true;
}

static inline void UnlockVpuReg(semaphore_t *semap)
{
	semaphore_post(semap, REG_MUTEX);
	IOClkGateSet(0);
}

int JpgEncLoadHuffTab(EncInfo * pEncInfo);
int JpgEncLoadQMatTab(EncInfo * pEncInfo);
int JpgEncEncodeHeader(EncHandle handle, EncParamSet * para);
void JpgDecGramSetup(DecInfo * pDecInfo);
RetCode JpgDecHuffTabSetUp(DecInfo *pDecInfo);
RetCode JpgDecQMatTabSetUp(DecInfo *pDecInfo);
int JpegDecodeHeader(DecInfo * pDecInfo);

#define swab32(x) \
	((Uint32)( \
		(((Uint32)(x) & (Uint32)0x000000ffUL) << 24) | \
		(((Uint32)(x) & (Uint32)0x0000ff00UL) <<  8) | \
		(((Uint32)(x) & (Uint32)0x00ff0000UL) >>  8) | \
		(((Uint32)(x) & (Uint32)0xff000000UL) >> 24) ))

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#endif
