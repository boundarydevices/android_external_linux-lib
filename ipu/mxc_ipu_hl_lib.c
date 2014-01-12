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

/*!
 * @file mxc_ipu_hl_lib.c
 *
 * @brief IPU high level library implementation
 *
 * @ingroup IPU
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/autoconf.h>
#include <linux/videodev.h>
#include <linux/ipu.h>
#include "mxc_ipu_hl_lib.h"

#define FBDEV0	"/dev/fb0"
#define FBDEV1	"/dev/fb1"
#define FBDEV2	"/dev/fb2"

#define DBG_DEBUG		3
#define DBG_INFO		2
#define DBG_WARNING		1
#define DBG_ERR			0

static int debug_level = DBG_INFO;
#define dbg(flag, fmt, args...)	{ if(flag <= debug_level)  printf("%s:%d "fmt, __FILE__, __LINE__,##args); }

/* this mutex only can protect within same process context,
 * for different process, pls add other mutex*/
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int g_task_in_use = 0;

int _ipu_task_enable(ipu_lib_handle_t * ipu_handle);
void _ipu_task_disable(ipu_lib_handle_t * ipu_handle);
int ipu_get_interrupt_event(ipu_event_info *ev);
int _ipu_wait_for_irq(int irq, int ms);

enum {
        IC_ENC = 0x1,
        IC_VF = 0x2,
        IC_PP = 0x4,
        ROT_ENC = 0x8,
        ROT_VF = 0x10,
        ROT_PP = 0x20,
};

typedef enum {
	NULL_MODE = 0,
	IC_MODE = 0x1,
	ROT_MODE = 0x2,
} task_mode_t;

typedef enum {
	RGB_CS,
	YUV_CS,
	NULL_CS
} cs_t;

typedef struct {
        int fd_ipu;
        int mode;
	int enabled;

        int irq;
	int output_bufnum;
	int update_bufnum;
        ipu_mem_info i_minfo[2];
	int iwidth;
	int iheight;
	int i_off;
	int i_uoff;
	int i_voff;

	int input_fr_cnt;
	int output_fr_cnt;

	struct {
		unsigned int task_mode;
		unsigned int ipu_task;
		ipu_channel_t ic_chan;
		ipu_channel_t rot_chan;
		ipu_channel_t begin_chan;
		ipu_channel_t end_chan;

		ipu_mem_info r_minfo[2];
		ipu_mem_info o_minfo[2];

		int show_to_fb;
		int fd_fb;
		int fb_stride;
		void * fb_mem;
		int screen_size;
		ipu_channel_t fb_chan;
	} output[2];
} ipu_lib_priv_handle_t;

static void ipu_msleep(int ms)
{
      struct timeval tv;

      tv.tv_sec = ms/1000;
      tv.tv_usec = (ms % 1000) * 1000;
      select(0, NULL, NULL, NULL, &tv);
}

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

static cs_t colorspaceofpixel(int fmt)
{
	switch(fmt)
	{
		case IPU_PIX_FMT_RGB565:
		case IPU_PIX_FMT_BGR24:
		case IPU_PIX_FMT_RGB24:
		case IPU_PIX_FMT_BGRA32:
		case IPU_PIX_FMT_BGR32:
		case IPU_PIX_FMT_RGBA32:
		case IPU_PIX_FMT_RGB32:
		case IPU_PIX_FMT_ABGR32:
			return RGB_CS;
			break;
		case IPU_PIX_FMT_UYVY:
		case IPU_PIX_FMT_YUYV:
		case IPU_PIX_FMT_YUV420P2:
		case IPU_PIX_FMT_YUV420P:
		case IPU_PIX_FMT_YVU422P:
		case IPU_PIX_FMT_YUV422P:
		case IPU_PIX_FMT_YUV444:
		case IPU_PIX_FMT_NV12:
			return YUV_CS;
			break;
		default:
			return NULL_CS;
	}
}

static int need_csc(int ifmt, int ofmt)
{
	cs_t ics,ocs;

	ics = colorspaceofpixel(ifmt);
	ocs = colorspaceofpixel(ofmt);

	if((ics == NULL_CS) || (ocs == NULL_CS)){
		dbg(DBG_ERR, "Color Space not recognized!\n");
		return -1;
	}else if(ics != ocs)
		return 1;

	return 0;
}

static int get_system_rev(unsigned int * system_rev)
{
        FILE *fp;
        char buf[1024];
        int nread;
        char *tmp, *rev;
        int ret = -1;

        fp = fopen("/proc/cpuinfo", "r");
        if (fp == NULL) {
                dbg(DBG_ERR, "Open /proc/cpuinfo failed!\n");
                return ret;
        }

        nread = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
        if ((nread == 0) || (nread == sizeof(buf))) {
                return ret;
        }

        buf[nread] = '\0';

        tmp = strstr(buf, "Revision");
        if (tmp != NULL) {
                rev = index(tmp, ':');
                if (rev != NULL) {
                        rev++;
                        *system_rev = strtoul(rev, NULL, 16);
                        ret = 0;
                }
        }

        return ret;
}

static int _ipu_get_arch_rot_begin()
{
	unsigned int system_rev, arch;

	if (get_system_rev(&system_rev) < 0)
		return IPU_ROTATE_90_RIGHT;

	dbg(DBG_INFO, "system_rev is 0x%x\n", system_rev);
	arch = system_rev & 0xff000;
	/* for mx37 */
	if (arch == 0x37000)
		return IPU_ROTATE_HORIZ_FLIP;
	else
		return IPU_ROTATE_90_RIGHT;
}

static int _ipu_task_busy_in_hw(int ipu_task)
{
	int ret = 0;

	if (ipu_task & IC_ENC)
		ret |= ipu_is_channel_busy(MEM_PRP_ENC_MEM);
	if (ipu_task & IC_VF)
		ret |= ipu_is_channel_busy(MEM_PRP_VF_MEM);
	if (ipu_task & IC_PP)
		ret |= ipu_is_channel_busy(MEM_PP_MEM);
	if (ipu_task & ROT_ENC)
		ret |= ipu_is_channel_busy(MEM_ROT_ENC_MEM);
	if (ipu_task & ROT_VF)
		ret |= ipu_is_channel_busy(MEM_ROT_VF_MEM);
	if (ipu_task & ROT_PP)
		ret |= ipu_is_channel_busy(MEM_ROT_PP_MEM);

	return ret;
}

static int _ipu_is_task_busy(int ipu_task)
{
	/* g_task_in_use is only useful in same process context*/
	if (g_task_in_use & ipu_task)
		return 1;
	/* IC_ENC and IC_VF can not be enabled together in different task*/
	if (((g_task_in_use & IC_ENC) && (ipu_task & IC_VF)) ||
		((g_task_in_use & IC_VF) && (ipu_task & IC_ENC)))
		return 1;
	/* we need to check low level HW busy status */
	if (_ipu_task_busy_in_hw(ipu_task))
		return 1;
	return 0;
}

static task_mode_t __ipu_task_check(ipu_lib_priv_handle_t * ipu_priv_handle,
		ipu_lib_input_param_t * input,
		ipu_lib_output_param_t * output)
{
	task_mode_t task_mode = NULL_MODE;
	int tmp;

	if(output->rot >= _ipu_get_arch_rot_begin()){
		if(output->rot >= IPU_ROTATE_90_RIGHT){
			/*output swap*/
			tmp = output->width;
			output->width = output->height;
			output->height = tmp;
		}
		task_mode |= ROT_MODE;
	}

	/* make sure width is 8 pixel align*/
	output->width = output->width - output->width%8;
	if (task_mode & ROT_MODE)
		output->height = output->height - output->height%8;

	/*need resize or CSC?*/
	if((ipu_priv_handle->iwidth != output->width) ||
			(ipu_priv_handle->iheight != output->height) ||
			need_csc(input->fmt,output->fmt))
		task_mode |= IC_MODE;

	/*need flip?*/
	if((task_mode == NULL_MODE) && (output->rot > IPU_ROTATE_NONE ))
		task_mode |= IC_MODE;

	/*need IDMAC do format(same color space)?*/
	if((task_mode == NULL_MODE) && (input->fmt != output->fmt))
		task_mode |= IC_MODE;

	return task_mode;
}

static int _ipu_task_check(ipu_lib_input_param_t * input,
		ipu_lib_output_param_t * output0,
		ipu_lib_output_param_t * output1,
		ipu_lib_handle_t * ipu_handle)
{
	int ipu_task_busy = 0;
	int ret = 0, hope_task_mode;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	hope_task_mode = ipu_priv_handle->mode & 0x07;
	if (output1 && hope_task_mode) {
		if (hope_task_mode != (TASK_ENC_MODE | TASK_VF_MODE)) {
			dbg(DBG_ERR, "Must use both ENC & VF task for 2 output case!\n");
			ret = -1;
			goto done;
		}
	}

	if ((input->input_crop_win.win_w > 0) || (input->input_crop_win.win_h > 0)) {
		if ((input->input_crop_win.win_w + input->input_crop_win.pos.x) > input->width)
			input->input_crop_win.win_w = input->width - input->input_crop_win.pos.x;
		if ((input->input_crop_win.win_h + input->input_crop_win.pos.y) > input->height)
			input->input_crop_win.win_h = input->height - input->input_crop_win.pos.y;
		ipu_priv_handle->iwidth = input->input_crop_win.win_w;
		ipu_priv_handle->iheight = input->input_crop_win.win_h;

		/* NOTE: u v offset should based on start point of i_off*/
		switch (input->fmt) {
		case IPU_PIX_FMT_YUV420P2:
		case IPU_PIX_FMT_YUV420P:
			ipu_priv_handle->i_off = input->input_crop_win.pos.y * input->width +
                                input->input_crop_win.pos.x;
			ipu_priv_handle->i_uoff = (input->width * (input->height - input->input_crop_win.pos.y)
				- input->input_crop_win.pos.x)
				+ ((input->width/2 * input->input_crop_win.pos.y/2)
				+ input->input_crop_win.pos.x/2);
			ipu_priv_handle->i_voff = ipu_priv_handle->i_uoff +
				(input->width/2 * input->height/2);
			break;
		case IPU_PIX_FMT_YVU422P:
			ipu_priv_handle->i_off = input->input_crop_win.pos.y * input->width +
                                input->input_crop_win.pos.x;
			ipu_priv_handle->i_voff = (input->width * (input->height - input->input_crop_win.pos.y)
				- input->input_crop_win.pos.x)
				+ ((input->width * input->input_crop_win.pos.y)/2 + input->input_crop_win.pos.x/2);
			ipu_priv_handle->i_uoff = ipu_priv_handle->i_voff +
				(input->width * input->height)/2;
			break;
		case IPU_PIX_FMT_YUV422P:
			ipu_priv_handle->i_off = input->input_crop_win.pos.y * input->width +
                                input->input_crop_win.pos.x;
			ipu_priv_handle->i_uoff = (input->width * (input->height - input->input_crop_win.pos.y)
				- input->input_crop_win.pos.x)
				+ (input->width * input->input_crop_win.pos.y)/2 + input->input_crop_win.pos.x/2;
			ipu_priv_handle->i_voff = ipu_priv_handle->i_uoff +
				(input->width * input->height)/2;
			break;
		case IPU_PIX_FMT_NV12:
			ipu_priv_handle->i_off = input->input_crop_win.pos.y * input->width +
                                input->input_crop_win.pos.x;
			ipu_priv_handle->i_uoff = (input->width * (input->height - input->input_crop_win.pos.y)
				- input->input_crop_win.pos.x)
				+ input->width * input->input_crop_win.pos.y + input->input_crop_win.pos.x;
			break;
		default:
			ipu_priv_handle->i_off = (input->input_crop_win.pos.y * input->width +
				input->input_crop_win.pos.x) * fmt_to_bpp(input->fmt)/8;
			break;
		}
	} else {
		ipu_priv_handle->iwidth = input->width;
		ipu_priv_handle->iheight = input->height;
	}

	ipu_priv_handle->output[0].task_mode = __ipu_task_check(ipu_priv_handle, input, output0);
	if (output1)
		ipu_priv_handle->output[1].task_mode = __ipu_task_check(ipu_priv_handle, input, output1);

	if (output1) {
		/* 2 output case, should use VF & ENC task*/
		if (ipu_priv_handle->output[0].task_mode == ROT_MODE)
			ipu_priv_handle->output[0].ipu_task |= ROT_ENC;
		else if (ipu_priv_handle->output[0].task_mode == (IC_MODE | ROT_MODE))
			ipu_priv_handle->output[0].ipu_task |= IC_ENC | ROT_ENC;
		else
			ipu_priv_handle->output[0].ipu_task |= IC_ENC;

		if (ipu_priv_handle->output[1].task_mode == ROT_MODE)
			ipu_priv_handle->output[1].ipu_task |= ROT_VF;
		else if (ipu_priv_handle->output[1].task_mode == (IC_MODE | ROT_MODE))
			ipu_priv_handle->output[1].ipu_task |= IC_VF | ROT_VF;
		else
			ipu_priv_handle->output[1].ipu_task |= IC_VF;

		if (_ipu_is_task_busy(ipu_priv_handle->output[0].ipu_task |
				ipu_priv_handle->output[1].ipu_task)) {
			/* is it ok switch the ENC & VF */
			ipu_priv_handle->output[0].ipu_task =
				ipu_priv_handle->output[1].ipu_task = 0;

			if (ipu_priv_handle->output[0].task_mode == ROT_MODE)
				ipu_priv_handle->output[0].ipu_task |= ROT_VF;
			else if (ipu_priv_handle->output[0].task_mode == (IC_MODE | ROT_MODE))
				ipu_priv_handle->output[0].ipu_task |= IC_VF | ROT_VF;
			else
				ipu_priv_handle->output[0].ipu_task |= IC_VF;

			if (ipu_priv_handle->output[1].task_mode == ROT_MODE)
				ipu_priv_handle->output[1].ipu_task |= ROT_ENC;
			else if (ipu_priv_handle->output[1].task_mode == (IC_MODE | ROT_MODE))
				ipu_priv_handle->output[1].ipu_task |= IC_ENC | ROT_ENC;
			else
				ipu_priv_handle->output[1].ipu_task |= IC_ENC;

			if (_ipu_is_task_busy(ipu_priv_handle->output[0].ipu_task |
						ipu_priv_handle->output[1].ipu_task))
				ipu_task_busy = 1;
		}
	} else {
		/* 1 output case */
		if (ipu_priv_handle->output[0].task_mode == NULL_MODE) {
			dbg(DBG_ERR, "Do not need any operation! Will do nothing!\n");
			ret = -1;
			goto done;
		}

		/* try ENC first */
		if (ipu_priv_handle->output[0].task_mode & ROT_MODE)
			ipu_priv_handle->output[0].ipu_task |= ROT_ENC;
		if (ipu_priv_handle->output[0].task_mode & IC_MODE)
			ipu_priv_handle->output[0].ipu_task |= IC_ENC;

		if (_ipu_is_task_busy(ipu_priv_handle->output[0].ipu_task) ||
			(hope_task_mode && ((hope_task_mode & TASK_ENC_MODE) == 0))) {

			/* hope mode ENC task is busy ? */
			if (hope_task_mode && (hope_task_mode & TASK_ENC_MODE)) {
				ipu_task_busy = 1;
				goto done;
			}

			/* try PP */
			ipu_priv_handle->output[0].ipu_task = 0;
			if (ipu_priv_handle->output[0].task_mode & ROT_MODE)
				ipu_priv_handle->output[0].ipu_task |= ROT_PP;
			if (ipu_priv_handle->output[0].task_mode & IC_MODE)
				ipu_priv_handle->output[0].ipu_task |= IC_PP;

			if (_ipu_is_task_busy(ipu_priv_handle->output[0].ipu_task) ||
				(hope_task_mode && ((hope_task_mode & TASK_PP_MODE) == 0))) {

				/* hope mode PP task is busy ? */
				if (hope_task_mode && (hope_task_mode & TASK_PP_MODE)) {
					ipu_task_busy = 1;
					goto done;
				}

				/* try VF */
				ipu_priv_handle->output[0].ipu_task = 0;
				if (ipu_priv_handle->output[0].task_mode & ROT_MODE)
					ipu_priv_handle->output[0].ipu_task |= ROT_VF;
				if (ipu_priv_handle->output[0].task_mode & IC_MODE)
					ipu_priv_handle->output[0].ipu_task |= IC_VF;

				if (_ipu_is_task_busy(ipu_priv_handle->output[0].ipu_task) ||
					(hope_task_mode && ((hope_task_mode & TASK_VF_MODE) == 0)))
					ipu_task_busy = 1;
			}
		}
	}
done:
	if (ipu_task_busy) {
		ret = -1;
		dbg(DBG_ERR, "ipu is busy\n");
		if (hope_task_mode)
			dbg(DBG_ERR, " for hope task mode 0x%x!\n", hope_task_mode);
	} else if (ret == 0){
		unsigned int task = ipu_priv_handle->output[0].ipu_task |
				ipu_priv_handle->output[1].ipu_task;
		dbg(DBG_INFO, "\033[0;34mWill take ipu task\033[0m\n");
		if (task & IC_ENC)
			dbg(DBG_INFO, "\tIC_ENC\n");
		if (task & IC_VF)
			dbg(DBG_INFO, "\tIC_VF\n");
		if (task & IC_PP)
			dbg(DBG_INFO, "\tIC_PP\n");
		if (task & ROT_ENC)
			dbg(DBG_INFO, "\tROT_ENC\n");
		if (task & ROT_VF)
			dbg(DBG_INFO, "\tROT_VF\n");
		if (task & ROT_PP)
			dbg(DBG_INFO, "\tROT_PP\n");
	}
	return ret;
}

static int _ipu_mem_alloc(ipu_lib_input_param_t * input,
		ipu_lib_output_param_t * output0,
		ipu_lib_output_param_t * output1,
		ipu_lib_handle_t * ipu_handle)
{
	int i, j, ret = 0, bufcnt, output_num;
	ipu_lib_output_param_t * output;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	if (ipu_priv_handle->mode & OP_STREAM_MODE)
		bufcnt = 2;
	else
		bufcnt = 1;

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	ipu_priv_handle->output[0].show_to_fb = output0->show_to_fb;
	if (output1)
		ipu_priv_handle->output[1].show_to_fb = output1->show_to_fb;

	for (i=0;i<bufcnt;i++) {
		/* user can choose other input phy addr*/
		if (input->paddr[i] == 0) {
			ipu_handle->ifr_size = ipu_priv_handle->i_minfo[i].size =
					input->width/8*input->height*fmt_to_bpp(input->fmt);
			if (ioctl(ipu_priv_handle->fd_ipu, IPU_ALOC_MEM, &(ipu_priv_handle->i_minfo[i])) < 0) {
				dbg(DBG_ERR, "Ioctl IPU_ALOC_MEM failed!\n");
				ret = -1;
				goto err;
			}
			/* mmap virtual addr for user*/
			ipu_handle->inbuf_start[i] = mmap (NULL, ipu_priv_handle->i_minfo[i].size,
					PROT_READ | PROT_WRITE, MAP_SHARED,
					ipu_priv_handle->fd_ipu, ipu_priv_handle->i_minfo[i].paddr);
			if (ipu_handle->inbuf_start[i] == MAP_FAILED) {
				dbg(DBG_ERR, "mmap failed!\n");
				ret = -1;
				goto err;
			}
			dbg(DBG_INFO, "\033[0;35mAlocate %d dma mem [%d] for input, dma addr 0x%x, mmap to %p!\033[0m\n",
					ipu_handle->ifr_size, i, ipu_priv_handle->i_minfo[i].paddr, ipu_handle->inbuf_start[i]);
		} else {
			ipu_priv_handle->i_minfo[i].paddr = input->paddr[i];
			dbg(DBG_INFO, "\033[0;35mSet input dma mem [%d] addr 0x%x by user!\033[0m\n", i, input->paddr[i]);
		}

		for (j=0;j<output_num;j++) {
			if (j == 0)
				output = output0;
			else
				output = output1;

			/* user can choose other output phy addr*/
			if ((output->show_to_fb == 0) && (output->paddr[i] == 0)) {
				ipu_handle->ofr_size[j] = ipu_priv_handle->output[j].o_minfo[i].size =
					output->width/8*output->height*fmt_to_bpp(output->fmt);
				if (ioctl(ipu_priv_handle->fd_ipu, IPU_ALOC_MEM,
						&(ipu_priv_handle->output[j].o_minfo[i])) < 0) {
					dbg(DBG_ERR, "Ioctl IPU_ALOC_MEM failed!\n");
					ret = -1;
					goto err;
				}
				/* mmap virtual addr for user*/
				if (j == 0) {
					ipu_handle->outbuf_start0[i] = mmap (NULL, ipu_priv_handle->output[j].o_minfo[i].size,
							PROT_READ | PROT_WRITE, MAP_SHARED,
							ipu_priv_handle->fd_ipu, ipu_priv_handle->output[j].o_minfo[i].paddr);
					if (ipu_handle->outbuf_start0[i] == MAP_FAILED) {
						dbg(DBG_ERR, "mmap failed!\n");
						ret = -1;
						goto err;
					}
					dbg(DBG_INFO, "\033[0;35mAlocate %d dma mem [%d] for output0, dma addr 0x%x, mmap to %p!\033[0m\n",
							ipu_handle->ofr_size[j], i, ipu_priv_handle->output[j].o_minfo[i].paddr,
							ipu_handle->outbuf_start0[i]);
				} else {
					ipu_handle->outbuf_start1[i] = mmap (NULL, ipu_priv_handle->output[j].o_minfo[i].size,
							PROT_READ | PROT_WRITE, MAP_SHARED,
							ipu_priv_handle->fd_ipu, ipu_priv_handle->output[j].o_minfo[i].paddr);
					if (ipu_handle->outbuf_start1[i] == MAP_FAILED) {
						dbg(DBG_ERR, "mmap failed!\n");
						ret = -1;
						goto err;
					}
					dbg(DBG_INFO, "\033[0;35mAlocate %d dma mem [%d] for output1, dma addr 0x%x, mmap to %p!\033[0m\n",
							ipu_handle->ofr_size[j], i, ipu_priv_handle->output[j].o_minfo[i].paddr,
							ipu_handle->outbuf_start1[i]);
				}
			} else if (output->paddr[i] != 0) {
				ipu_priv_handle->output[j].o_minfo[i].paddr = output->paddr[i];
				dbg(DBG_INFO, "\033[0;35mSet output%d dma mem [%d] addr 0x%x by user!\033[0m\n", j, i, output->paddr[i]);
			}

			/* allocate dma buffer for rotation? */
			if(ipu_priv_handle->output[j].task_mode == (ROT_MODE | IC_MODE)) {
				ipu_priv_handle->output[j].r_minfo[i].size =
						output->width/8*output->height*fmt_to_bpp(output->fmt);
				if (ioctl(ipu_priv_handle->fd_ipu, IPU_ALOC_MEM,
						&(ipu_priv_handle->output[j].r_minfo[i])) < 0) {
					dbg(DBG_ERR, "Ioctl IPU_ALOC_MEM failed!\n");
					ret = -1;
					goto err;
				}
				dbg(DBG_INFO, "\033[0;35mAlocate %d dma mem [%d] for %d rotation, dma addr 0x%x!\033[0m\n",
						ipu_priv_handle->output[j].r_minfo[i].size, i, j, ipu_priv_handle->output[j].r_minfo[i].paddr);
			}
		}
	}

	/*for the case output direct to framebuffer*/
	for (j=0;j<output_num;j++) {
		if (j == 0)
			output = output0;
		else
			output = output1;

		if (output->show_to_fb) {
			int owidth, oheight;
			struct fb_fix_screeninfo fb_fix;
			struct fb_var_screeninfo fb_var;
			int offset = 0;
			char *fbdev;

			if (output->fb_disp.fb_num == 0)
				fbdev = FBDEV0;
			else if (output->fb_disp.fb_num == 1)
				fbdev = FBDEV1;
			else
				fbdev = FBDEV2;

			dbg(DBG_INFO, "Output %d Show to %s\n", j, fbdev);

			if ((ipu_priv_handle->output[j].fd_fb = open(fbdev, O_RDWR, 0)) < 0) {
				dbg(DBG_ERR, "Unable to open %s\n", fbdev);
				ret = -1;
				goto err;
			}

			if ( ioctl(ipu_priv_handle->output[j].fd_fb, FBIOGET_FSCREENINFO, &fb_fix) < 0) {
				dbg(DBG_ERR, "Get FB fix info failed!\n");
				close(ipu_priv_handle->output[j].fd_fb);
				ret = -1;
				goto err;
			}
			if ( ioctl(ipu_priv_handle->output[j].fd_fb, FBIOGET_VSCREENINFO, &fb_var) < 0) {
				dbg(DBG_ERR, "Get FB var info failed!\n");
				close(ipu_priv_handle->output[j].fd_fb);
				ret = -1;
				goto err;
			}

			if (strcmp(fb_fix.id, "DISP3 FG") == 0)
				ipu_priv_handle->output[j].fb_chan = MEM_FG_SYNC;
			else if (strcmp(fb_fix.id, "DISP3 BG") == 0)
				ipu_priv_handle->output[j].fb_chan = MEM_BG_SYNC;
			else if (strcmp(fb_fix.id, "DISP3 BG - DI1") == 0)
				ipu_priv_handle->output[j].fb_chan = MEM_DC_SYNC;

			if (!ipu_priv_handle->output[j].fb_chan) {
				dbg(DBG_WARNING,
					"Get FB ipu channel failed, fix id %s\n", fb_fix.id);
				if (output->fb_disp.fb_num == 0)
					ipu_priv_handle->output[j].fb_chan = MEM_BG_SYNC;
				else if (output->fb_disp.fb_num == 1)
					ipu_priv_handle->output[j].fb_chan = MEM_DC_SYNC;
				else
					ipu_priv_handle->output[j].fb_chan = MEM_FG_SYNC;
			}

			if(output->rot >= IPU_ROTATE_90_RIGHT){
				owidth = output->height;
				oheight = output->width;
			} else {
				owidth = output->width;
				oheight = output->height;
			}

			if (ipu_priv_handle->output[j].fb_chan == MEM_FG_SYNC) {
				fb_var.xres = owidth;
				fb_var.xres_virtual = fb_var.xres;
				fb_var.yres = oheight;
				fb_var.yres_virtual = fb_var.yres * 2;
				if ( ioctl(ipu_priv_handle->output[j].fd_fb, FBIOPUT_VSCREENINFO, &fb_var) < 0) {
					dbg(DBG_ERR, "Set FB var info failed!\n");
					close(ipu_priv_handle->output[j].fd_fb);
					ret = -1;
					goto err;
				}
				if ( ioctl(ipu_priv_handle->output[j].fd_fb, MXCFB_SET_OVERLAY_POS,
						&(output->fb_disp.pos)) < 0)
					dbg(DBG_ERR, "Set FB position failed!\n");
			} else if ((fb_var.yres == fb_var.yres_virtual)) {
				fb_var.yres_virtual = fb_var.yres * 2;
				if ( ioctl(ipu_priv_handle->output[j].fd_fb, FBIOPUT_VSCREENINFO, &fb_var) < 0) {
					dbg(DBG_ERR, "Set FB var info failed!\n");
					close(ipu_priv_handle->output[j].fd_fb);
					ret = -1;
					goto err;
				}
			}

			if ( ioctl(ipu_priv_handle->output[j].fd_fb, FBIOGET_FSCREENINFO, &fb_fix) < 0) {
				dbg(DBG_ERR, "Get FB fix info failed!\n");
				close(ipu_priv_handle->output[j].fd_fb);
				ret = -1;
				goto err;
			}

			if ( ioctl(ipu_priv_handle->output[j].fd_fb, FBIOGET_VSCREENINFO, &fb_var) < 0) {
				dbg(DBG_ERR, "Get FB var info failed!\n");
				close(ipu_priv_handle->output[j].fd_fb);
				ret = -1;
				goto err;
			}

			dbg(DBG_INFO, "fb xres %d\n", fb_var.xres);
			dbg(DBG_INFO, "fb yres %d\n", fb_var.yres);
			dbg(DBG_INFO, "fb xres_virtual %d\n", fb_var.xres_virtual);
			dbg(DBG_INFO, "fb yres_virtual %d\n", fb_var.yres_virtual);

			if ((owidth > fb_var.xres) || (oheight > fb_var.yres)
					|| (fmt_to_bpp(output->fmt) != fb_var.bits_per_pixel)) {
				dbg(DBG_ERR, "Output image is not fit for %s!\n", fbdev);
				close(ipu_priv_handle->output[j].fd_fb);
				ret = -1;
				goto err;
			}

			ipu_priv_handle->output[j].fb_stride = fb_var.xres * fb_var.bits_per_pixel/8;

			if (ipu_priv_handle->output[j].fb_chan != MEM_FG_SYNC)
				offset = output->fb_disp.pos.y * ipu_priv_handle->output[j].fb_stride
						+ output->fb_disp.pos.x * fb_var.bits_per_pixel/8;

			ipu_priv_handle->output[j].screen_size = fb_var.yres * fb_fix.line_length;

			ipu_priv_handle->output[j].o_minfo[0].paddr = fb_fix.smem_start +
					ipu_priv_handle->output[j].screen_size + offset;
			if (bufcnt > 1)
				ipu_priv_handle->output[j].o_minfo[1].paddr = fb_fix.smem_start + offset;

			ipu_priv_handle->output[j].fb_mem = mmap(0,
					2*ipu_priv_handle->output[j].screen_size,
					PROT_READ | PROT_WRITE, MAP_SHARED,
					ipu_priv_handle->output[j].fd_fb, 0);
			if (ipu_priv_handle->output[j].fb_mem == MAP_FAILED) {
				dbg(DBG_ERR, "mmap failed!\n");
				close(ipu_priv_handle->output[j].fd_fb);
				ret = -1;
				goto err;
			}

			if ((ipu_priv_handle->output[j].fb_chan != MEM_FG_SYNC) &&
					((owidth < fb_var.xres) || (oheight < fb_var.yres)))
				/*make two buffer be the same to avoid flick*/
				memcpy(ipu_priv_handle->output[j].fb_mem +
						ipu_priv_handle->output[j].screen_size,
						ipu_priv_handle->output[j].fb_mem,
						ipu_priv_handle->output[j].screen_size);

			dbg(DBG_INFO, "fb stride %d\n", ipu_priv_handle->output[j].fb_stride);
			dbg(DBG_INFO, "fb screen_size %d\n", ipu_priv_handle->output[j].screen_size);
			dbg(DBG_INFO, "fb phyaddr0 0x%x\n", ipu_priv_handle->output[j].o_minfo[0].paddr);
			dbg(DBG_INFO, "fb phyaddr1 0x%x\n", ipu_priv_handle->output[j].o_minfo[1].paddr);
		}
	}
err:
	return ret;
}

static void _ipu_mem_free(ipu_lib_handle_t * ipu_handle)
{
	int i, j, bufcnt, output_num;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	if (ipu_priv_handle->mode & OP_STREAM_MODE)
		bufcnt = 2;
	else
		bufcnt = 1;

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	for (i=0;i<bufcnt;i++) {
		if (ipu_priv_handle->i_minfo[i].vaddr) {
			if (ipu_handle->inbuf_start[i])
				munmap(ipu_handle->inbuf_start[i], ipu_priv_handle->i_minfo[i].size);
			ioctl(ipu_priv_handle->fd_ipu, IPU_FREE_MEM, &(ipu_priv_handle->i_minfo[i]));
			dbg(DBG_INFO, "\033[0;35mFree %d dma mem [%d] for input, dma addr 0x%x!\033[0m\n",
					ipu_handle->ifr_size, i, ipu_priv_handle->i_minfo[i].paddr);
		}

		for (j=0;j<output_num;j++) {
			if (ipu_priv_handle->output[j].show_to_fb == 0) {
				if (ipu_priv_handle->output[j].o_minfo[i].vaddr) {
					if (j == 0) {
						if (ipu_handle->outbuf_start0[i])
							munmap(ipu_handle->outbuf_start0[i],
								ipu_priv_handle->output[j].o_minfo[i].size);
					} else {
						if (ipu_handle->outbuf_start1[i])
							munmap(ipu_handle->outbuf_start1[i],
								ipu_priv_handle->output[j].o_minfo[i].size);
					}
					ioctl(ipu_priv_handle->fd_ipu, IPU_FREE_MEM,
							&(ipu_priv_handle->output[j].o_minfo[i]));

					dbg(DBG_INFO, "\033[0;35mFree %d dma mem [%d] for output%d, dma addr 0x%x!\033[0m\n",
							ipu_handle->ofr_size[j], i, j, ipu_priv_handle->output[j].o_minfo[i].paddr);
				}
			}

			if (ipu_priv_handle->output[j].r_minfo[i].vaddr) {
				ioctl(ipu_priv_handle->fd_ipu, IPU_FREE_MEM, &(ipu_priv_handle->output[j].r_minfo[i]));
				dbg(DBG_INFO, "\033[0;35mFree %d dma mem [%d] for %d rotation, dma addr 0x%x!\033[0m\n",
						ipu_priv_handle->output[j].r_minfo[i].size, i, j, ipu_priv_handle->output[j].r_minfo[i].paddr);
			}
		}
	}

	for (j=0;j<output_num;j++) {
		if (ipu_priv_handle->output[j].show_to_fb){
			if (((ipu_priv_handle->mode & OP_STREAM_MODE) == 0) ||
				((ipu_priv_handle->input_fr_cnt % 2) &&
				(ipu_priv_handle->mode & OP_STREAM_MODE))) {
				/* make sure buffer1 still at fbmem base*/
				memcpy(ipu_priv_handle->output[j].fb_mem,
					ipu_priv_handle->output[j].fb_mem +
					ipu_priv_handle->output[j].screen_size,
					ipu_priv_handle->output[j].screen_size);
				ipu_select_buffer(ipu_priv_handle->output[j].fb_chan, IPU_INPUT_BUFFER, 1);
			}
			if (ipu_priv_handle->output[j].fb_mem)
				munmap(ipu_priv_handle->output[j].fb_mem, 2*ipu_priv_handle->output[j].screen_size);
			close(ipu_priv_handle->output[j].fd_fb);
		}
	}
}

static int _ipu_channel_setup(ipu_lib_input_param_t * input,
		ipu_lib_output_param_t * output0,
		ipu_lib_output_param_t * output1,
		ipu_lib_handle_t * ipu_handle)
{
	ipu_channel_params_t params;
	int i, tmp, ret = 0, out_stride, output_num;
	ipu_lib_output_param_t * output;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	dbg(DBG_INFO, "\033[0;34mmode:\033[0m\n");
	if (ipu_priv_handle->mode & TASK_ENC_MODE)
		dbg(DBG_INFO, "\tTASK_ENC_MODE\n");
	if (ipu_priv_handle->mode & TASK_VF_MODE)
		dbg(DBG_INFO, "\tTASK_VF_MODE\n");
	if (ipu_priv_handle->mode & TASK_PP_MODE)
		dbg(DBG_INFO, "\tTASK_PP_MODE\n");
	if (ipu_priv_handle->mode & OP_NORMAL_MODE)
		dbg(DBG_INFO, "\tOP_NORMAL_MODE\n");
	if (ipu_priv_handle->mode & OP_STREAM_MODE)
		dbg(DBG_INFO, "\tOP_STREAM_MODE\n");

	dbg(DBG_INFO, "\033[0;34minput info:\033[0m\n");
	dbg(DBG_INFO, "\tw: %d\n", input->width);
	dbg(DBG_INFO, "\th: %d\n", input->height);
	dbg(DBG_INFO, "\tfmt: 0x%x\n", input->fmt);
	dbg(DBG_INFO, "\t\tw_posx: %d\n", input->input_crop_win.pos.x);
	dbg(DBG_INFO, "\t\tw_posy: %d\n", input->input_crop_win.pos.y);
	dbg(DBG_INFO, "\t\tw_w: %d\n", input->input_crop_win.win_w);
	dbg(DBG_INFO, "\t\tw_h: %d\n", input->input_crop_win.win_h);

	dbg(DBG_INFO, "\t\033[0;34minput crop:\033[0m\n");
	dbg(DBG_INFO, "\t\tiwidth: %d\n", ipu_priv_handle->iwidth);
	dbg(DBG_INFO, "\t\tiheight: %d\n", ipu_priv_handle->iheight);
	dbg(DBG_INFO, "\t\ti_off 0x%x\n", ipu_priv_handle->i_off);
	dbg(DBG_INFO, "\t\ti_uoff 0x%x\n", ipu_priv_handle->i_uoff);
	dbg(DBG_INFO, "\t\ti_voff 0x%x\n", ipu_priv_handle->i_voff);

	dbg(DBG_INFO, "\t\033[0;34minput buf paddr:\033[0m\n");
	dbg(DBG_INFO, "\t\tbuf0 0x%x\n", ipu_priv_handle->i_minfo[0].paddr);
	dbg(DBG_INFO, "\t\tbuf1 0x%x\n", ipu_priv_handle->i_minfo[1].paddr);

	dbg(DBG_INFO, "\033[0;34moutput0 info:\033[0m\n");
	dbg(DBG_INFO, "\tw: %d\n", output0->width);
	dbg(DBG_INFO, "\th: %d\n", output0->height);
	dbg(DBG_INFO, "\trot: %d\n", output0->rot);
	dbg(DBG_INFO, "\tfmt: 0x%x\n", output0->fmt);
	dbg(DBG_INFO, "\tshow_to_fb: %d\n", output0->show_to_fb);
	if (output0->show_to_fb) {
		dbg(DBG_INFO, "\t\tfb_num: %d\n", output0->fb_disp.fb_num);
		dbg(DBG_INFO, "\t\tfb_w_posx: %d\n", output0->fb_disp.pos.x);
		dbg(DBG_INFO, "\t\tfb_w_posy: %d\n", output0->fb_disp.pos.y);
	}
	dbg(DBG_INFO, "\t\033[0;34moutput0 buf paddr:\033[0m\n");
	dbg(DBG_INFO, "\t\tbuf0 0x%x\n", ipu_priv_handle->output[0].o_minfo[0].paddr);
	dbg(DBG_INFO, "\t\tbuf1 0x%x\n", ipu_priv_handle->output[0].o_minfo[1].paddr);

	if (output1) {
		dbg(DBG_INFO, "\033[0;34moutput1 info:\033[0m\n");
		dbg(DBG_INFO, "\tw: %d\n", output1->width);
		dbg(DBG_INFO, "\th: %d\n", output1->height);
		dbg(DBG_INFO, "\trot: %d\n", output1->rot);
		dbg(DBG_INFO, "\tfmt: 0x%x\n", output1->fmt);
		dbg(DBG_INFO, "\tshow_to_fb: %d\n", output1->show_to_fb);
		if (output1->show_to_fb) {
			dbg(DBG_INFO, "\t\tfb_num: %d\n", output1->fb_disp.fb_num);
			dbg(DBG_INFO, "\t\tfb_w_posx: %d\n", output1->fb_disp.pos.x);
			dbg(DBG_INFO, "\t\tfb_w_posy: %d\n", output1->fb_disp.pos.y);
		}
		dbg(DBG_INFO, "\t\033[0;34moutput1 buf paddr:\033[0m\n");
		dbg(DBG_INFO, "\t\tbuf0 0x%x\n", ipu_priv_handle->output[1].o_minfo[0].paddr);
		dbg(DBG_INFO, "\t\tbuf1 0x%x\n", ipu_priv_handle->output[1].o_minfo[1].paddr);
	}

	dbg(DBG_INFO, "\033[0;34mEnabling:\033[0m\n");
	/*Setup ipu channel*/
	for (i=0;i<output_num;i++) {
		if (i == 0)
			output = output0;
		else
			output = output1;

		dbg(DBG_INFO, "\033[0;34mTask %d:\033[0m \n", i);

		if(ipu_priv_handle->output[i].task_mode == IC_MODE){
			dbg(DBG_INFO, "\tOnly IC, begin & end chan:\n");

			if (ipu_priv_handle->output[i].ipu_task & IC_ENC) {
				ipu_priv_handle->output[i].ic_chan = MEM_PRP_ENC_MEM;
				dbg(DBG_INFO, "\t\tMEM_PRP_ENC_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & IC_VF) {
				ipu_priv_handle->output[i].ic_chan = MEM_PRP_VF_MEM;
				dbg(DBG_INFO, "\t\tMEM_PRP_VF_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & IC_PP) {
				ipu_priv_handle->output[i].ic_chan = MEM_PP_MEM;
				dbg(DBG_INFO, "\t\tMEM_PP_MEM\n");
			}

			memset(&params, 0, sizeof (params));

			params.mem_prp_vf_mem.in_width = ipu_priv_handle->iwidth;
			params.mem_prp_vf_mem.in_height = ipu_priv_handle->iheight;
			params.mem_prp_vf_mem.in_pixel_fmt = input->fmt;

			params.mem_prp_vf_mem.out_width = output->width;
			params.mem_prp_vf_mem.out_height = output->height;
			params.mem_prp_vf_mem.out_pixel_fmt = output->fmt;

			ret = ipu_init_channel(ipu_priv_handle->output[i].ic_chan, &params);
			if (ret < 0)
				goto done;

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].ic_chan,
					IPU_INPUT_BUFFER,
					input->fmt,
					ipu_priv_handle->iwidth,
					ipu_priv_handle->iheight,
					input->width*bytes_per_pixel(input->fmt),
					IPU_ROTATE_NONE,
					ipu_priv_handle->i_minfo[0].paddr + ipu_priv_handle->i_off,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->i_minfo[1].paddr + ipu_priv_handle->i_off : 0,
					ipu_priv_handle->i_uoff, ipu_priv_handle->i_voff);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				goto done;
			}

			if (output->show_to_fb) {
				out_stride = ipu_priv_handle->output[i].fb_stride;
			} else
				out_stride = output->width*bytes_per_pixel(output->fmt);

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].ic_chan,
					IPU_OUTPUT_BUFFER,
					output->fmt,
					output->width,
					output->height,
					out_stride,
					output->rot,
					ipu_priv_handle->output[i].o_minfo[0].paddr,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->output[i].o_minfo[1].paddr : 0,
					0, 0);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				goto done;
			}

			ipu_priv_handle->output[i].begin_chan =
				ipu_priv_handle->output[i].end_chan =
					ipu_priv_handle->output[i].ic_chan;
		}
		/*Only ROT*/
		else if (ipu_priv_handle->output[i].task_mode == ROT_MODE){
			dbg(DBG_INFO, "\tOnly ROT, begin & end chan:\n");

			if (ipu_priv_handle->output[i].ipu_task & ROT_ENC) {
				ipu_priv_handle->output[i].rot_chan = MEM_ROT_ENC_MEM;
				dbg(DBG_INFO, "\t\tMEM_ROT_ENC_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & ROT_VF) {
				ipu_priv_handle->output[i].rot_chan = MEM_ROT_VF_MEM;
				dbg(DBG_INFO, "\t\tMEM_ROT_VF_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & ROT_PP) {
				ipu_priv_handle->output[i].rot_chan = MEM_ROT_PP_MEM;
				dbg(DBG_INFO, "\t\tMEM_ROT_PP_MEM\n");
			}

			ret = ipu_init_channel(ipu_priv_handle->output[i].rot_chan, NULL);
			if (ret < 0) {
				goto done;
			}

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].rot_chan,
					IPU_INPUT_BUFFER,
					input->fmt,
					ipu_priv_handle->iwidth,
					ipu_priv_handle->iheight,
					input->width*bytes_per_pixel(input->fmt),
					output->rot,
					ipu_priv_handle->i_minfo[0].paddr + ipu_priv_handle->i_off,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->i_minfo[1].paddr + ipu_priv_handle->i_off : 0,
					ipu_priv_handle->i_uoff, ipu_priv_handle->i_voff);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
				goto done;
			}

			if(output->rot >= IPU_ROTATE_90_RIGHT){
				/*output swap*/
				tmp = output->width;
				output->width = output->height;
				output->height = tmp;
			}

			if (output->show_to_fb)
				out_stride = ipu_priv_handle->output[i].fb_stride;
			else
				out_stride = output->width*bytes_per_pixel(output->fmt);

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].rot_chan,
					IPU_OUTPUT_BUFFER,
					output->fmt,
					output->width,
					output->height,
					out_stride,
					IPU_ROTATE_NONE,
					ipu_priv_handle->output[i].o_minfo[0].paddr,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->output[i].o_minfo[1].paddr : 0,
					0, 0);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
				goto done;
			}

			ipu_priv_handle->output[i].begin_chan =
				ipu_priv_handle->output[i].end_chan =
					ipu_priv_handle->output[i].rot_chan;
		}
		/*IC ROT*/
		else if(ipu_priv_handle->output[i].task_mode == (IC_MODE | ROT_MODE)){
			dbg(DBG_INFO, "\tIC + ROT, begin chan:\n");

			if (ipu_priv_handle->output[i].ipu_task & IC_ENC) {
				ipu_priv_handle->output[i].ic_chan = MEM_PRP_ENC_MEM;
				dbg(DBG_INFO, "\t\tMEM_PRP_ENC_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & IC_VF) {
				ipu_priv_handle->output[i].ic_chan = MEM_PRP_VF_MEM;
				dbg(DBG_INFO, "\t\tMEM_PRP_VF_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & IC_PP) {
				ipu_priv_handle->output[i].ic_chan = MEM_PP_MEM;
				dbg(DBG_INFO, "\t\tMEM_PP_MEM\n");
			}

			dbg(DBG_INFO, "\tend chan:\n");

			if (ipu_priv_handle->output[i].ipu_task & ROT_ENC) {
				ipu_priv_handle->output[i].rot_chan = MEM_ROT_ENC_MEM;
				dbg(DBG_INFO, "\t\tMEM_ROT_ENC_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & ROT_VF) {
				ipu_priv_handle->output[i].rot_chan = MEM_ROT_VF_MEM;
				dbg(DBG_INFO, "\t\tMEM_ROT_VF_MEM\n");
			} else if (ipu_priv_handle->output[i].ipu_task & ROT_PP) {
				ipu_priv_handle->output[i].rot_chan = MEM_ROT_PP_MEM;
				dbg(DBG_INFO, "\t\tMEM_ROT_PP_MEM\n");
			}

			memset(&params, 0, sizeof (params));

			params.mem_prp_vf_mem.in_width = ipu_priv_handle->iwidth;
			params.mem_prp_vf_mem.in_height = ipu_priv_handle->iheight;
			params.mem_prp_vf_mem.in_pixel_fmt = input->fmt;

			params.mem_prp_vf_mem.out_width = output->width;
			params.mem_prp_vf_mem.out_height = output->height;
			params.mem_prp_vf_mem.out_pixel_fmt = output->fmt;

			ret = ipu_init_channel(ipu_priv_handle->output[i].ic_chan, &params);
			if (ret < 0) {
				goto done;
			}

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].ic_chan,
					IPU_INPUT_BUFFER,
					input->fmt,
					ipu_priv_handle->iwidth,
					ipu_priv_handle->iheight,
					input->width*bytes_per_pixel(input->fmt),
					IPU_ROTATE_NONE,
					ipu_priv_handle->i_minfo[0].paddr + ipu_priv_handle->i_off,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->i_minfo[1].paddr + ipu_priv_handle->i_off : 0,
					ipu_priv_handle->i_uoff, ipu_priv_handle->i_voff);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				goto done;
			}

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].ic_chan,
					IPU_OUTPUT_BUFFER,
					output->fmt,
					output->width,
					output->height,
					output->width*bytes_per_pixel(output->fmt),
					IPU_ROTATE_NONE,
					ipu_priv_handle->output[i].r_minfo[0].paddr,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->output[i].r_minfo[1].paddr : 0,
					0, 0);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				goto done;
			}

			ret = ipu_init_channel(ipu_priv_handle->output[i].rot_chan, NULL);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				goto done;
			}

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].rot_chan,
					IPU_INPUT_BUFFER,
					output->fmt,
					output->width,
					output->height,
					output->width*bytes_per_pixel(output->fmt),
					output->rot,
					ipu_priv_handle->output[i].r_minfo[0].paddr,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->output[i].r_minfo[1].paddr : 0,
					0, 0);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
				goto done;
			}

			if(output->rot >= IPU_ROTATE_90_RIGHT){
				/*output swap*/
				tmp = output->width;
				output->width = output->height;
				output->height = tmp;
			}

			if (output->show_to_fb)
				out_stride = ipu_priv_handle->output[i].fb_stride;
			else
				out_stride = output->width*bytes_per_pixel(output->fmt);

			ret = ipu_init_channel_buffer(ipu_priv_handle->output[i].rot_chan,
					IPU_OUTPUT_BUFFER,
					output->fmt,
					output->width,
					output->height,
					out_stride,
					IPU_ROTATE_NONE,
					ipu_priv_handle->output[i].o_minfo[0].paddr,
					ipu_priv_handle->mode & OP_STREAM_MODE ?
						ipu_priv_handle->output[i].o_minfo[1].paddr : 0,
					0, 0);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
				goto done;
			}

			ret = ipu_link_channels(ipu_priv_handle->output[i].ic_chan,
						ipu_priv_handle->output[i].rot_chan);
			if (ret < 0) {
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
				goto done;
			}

			ipu_priv_handle->output[i].begin_chan = ipu_priv_handle->output[i].ic_chan;
			ipu_priv_handle->output[i].end_chan = ipu_priv_handle->output[i].rot_chan;
		}

		if (output->show_to_fb) {
			dbg(DBG_INFO, "\tdisp chan:\n");
			if (ipu_priv_handle->output[i].fb_chan == MEM_BG_SYNC) {
				dbg(DBG_INFO, "\t\tMEM_BG_SYNC\n")
			}
			if (ipu_priv_handle->output[i].fb_chan == MEM_FG_SYNC) {
				dbg(DBG_INFO, "\t\tMEM_FG_SYNC\n")
			}
			if (ipu_priv_handle->output[i].fb_chan == MEM_DC_SYNC) {
				dbg(DBG_INFO, "\t\tMEM_DC_SYNC\n")
			}

			ret = ipu_link_channels(ipu_priv_handle->output[i].end_chan,
					ipu_priv_handle->output[i].fb_chan);
			if (ret < 0) {
				ipu_unlink_channels(ipu_priv_handle->output[i].ic_chan,
						ipu_priv_handle->output[i].rot_chan);
				ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);
				ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
				goto done;
			}
		}
	}

	/*only need one irq even for 2 output case*/
	switch (ipu_priv_handle->output[0].begin_chan) {
	case MEM_ROT_ENC_MEM:
		ipu_priv_handle->irq = IPU_IRQ_PRP_ENC_ROT_IN_EOF;
		break;
	case MEM_ROT_VF_MEM:
		ipu_priv_handle->irq = IPU_IRQ_PRP_VF_ROT_IN_EOF;
		break;
	case MEM_ROT_PP_MEM:
		ipu_priv_handle->irq = IPU_IRQ_PP_ROT_IN_EOF;
		break;
	case MEM_PRP_ENC_MEM:
	case MEM_PRP_VF_MEM:
		ipu_priv_handle->irq = IPU_IRQ_PRP_IN_EOF;
		break;
	case MEM_PP_MEM:
		ipu_priv_handle->irq = IPU_IRQ_PP_IN_EOF;
		break;
	default:
		dbg(DBG_ERR, "Should not be here!\n");
	}
done:
	return ret;
}

static int _ipu_task_setup(ipu_lib_input_param_t * input,
		ipu_lib_output_param_t * output0,
		ipu_lib_output_param_t * output1,
		ipu_lib_handle_t * ipu_handle)
{
	int ret = 0;

	if ((ret = _ipu_mem_alloc(input, output0, output1, ipu_handle)) < 0) {
		_ipu_mem_free(ipu_handle);
		return ret;
	}

	if ((ret = _ipu_channel_setup(input, output0, output1, ipu_handle)) < 0) {
		_ipu_mem_free(ipu_handle);
		return ret;
	}

	return ret;
}

/*!
 * This function init the ipu task according to param setting.
 *
 * @param	input		Input parameter for ipu task.
 *
 * @param	output0		The first output paramter for ipu task.
 *
 * @param	output1 	Ipu can support 2 output after postprocess
 * 				from 1 input, this is second one's setting.
 *
 * @param	mode		The ipu mode user can define, refer to
 * 				header file.
 *
 * @param	ipu_handle	User just allocate this structure for init.
 * 				this parameter will provide some necessary
 * 				info after task init function.
 *
 * @return	This function returns 0 on success or negative error code on
 * 		fail.
 */
int mxc_ipu_lib_task_init(ipu_lib_input_param_t * input,
		ipu_lib_output_param_t * output0,
		ipu_lib_output_param_t * output1,
		int mode, ipu_lib_handle_t * ipu_handle)
{
	int ret = 0;
	ipu_lib_priv_handle_t * ipu_priv_handle;

	dbg(DBG_INFO, "\033[0;34m*** mxc_ipu_lib_task_init ***\033[0m\n");

	pthread_mutex_lock(&mutex);

	memset(ipu_handle, 0, sizeof(ipu_lib_handle_t));

	ipu_priv_handle = (ipu_lib_priv_handle_t *)malloc(sizeof(ipu_lib_priv_handle_t));
	if (ipu_priv_handle == NULL) {
		dbg(DBG_ERR, "Can not malloc priv handle!\n");
		ret = -1;
		goto done;
	}

	ipu_handle->priv = ipu_priv_handle;
	memset(ipu_priv_handle, 0, sizeof(ipu_lib_priv_handle_t));

	ipu_priv_handle->mode = mode;

	if ((ret = ipu_priv_handle->fd_ipu  = ipu_open()) < 0)
		goto done;

	if ((ret = _ipu_task_check(input, output0, output1, ipu_handle)) < 0)
		goto done;

	if ((ret = _ipu_task_setup(input, output0, output1, ipu_handle)) < 0)
		goto done;

	g_task_in_use |= (ipu_priv_handle->output[0].ipu_task | ipu_priv_handle->output[1].ipu_task);

	dbg(DBG_INFO, "g_task_in_use 0x%x\n", g_task_in_use);
done:
	pthread_mutex_unlock(&mutex);

	return ret;
}

/*!
 * This function uninit the ipu task for special ipu handle.
 *
 * @param	ipu_handle	The ipu task handle need to un-init.
 *
 * @return	This function returns 0 on success or negative error code on
 * 		fail.
 */
void mxc_ipu_lib_task_uninit(ipu_lib_handle_t * ipu_handle)
{
	int i, output_num;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	dbg(DBG_INFO, "\033[0;34m*** mxc_ipu_lib_task_uninit ***\033[0m\n");

	/* if stream mode, wait for latest frame finish */
	if (ipu_priv_handle->mode & OP_STREAM_MODE) {
		if (_ipu_wait_for_irq(ipu_priv_handle->irq, 100)) {
			dbg(DBG_ERR, "wait for irq %d time out!\n", ipu_priv_handle->irq);
		} else
			ipu_priv_handle->output_fr_cnt++;
	}

	pthread_mutex_lock(&mutex);

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	for (i=0;i<output_num;i++) {
		if (ipu_priv_handle->output[i].show_to_fb) {
			if (ipu_priv_handle->output[i].fb_chan == MEM_FG_SYNC) {
				struct mxcfb_pos pos = {0};

				if ( ioctl(ipu_priv_handle->output[i].fd_fb, MXCFB_SET_OVERLAY_POS,
						&pos) < 0)
					dbg(DBG_ERR, "Set FB position failed!\n");
			}
		}
	}

	_ipu_task_disable(ipu_handle);

	dbg(DBG_INFO, "total input frame cnt is %d\n", ipu_priv_handle->input_fr_cnt);
	dbg(DBG_INFO, "total output frame cnt is %d\n", ipu_priv_handle->output_fr_cnt);

	for (i=0;i<output_num;i++) {
		if (ipu_priv_handle->output[i].show_to_fb) {
			ipu_unlink_channels(ipu_priv_handle->output[i].end_chan,
					ipu_priv_handle->output[i].fb_chan);

			if (ipu_priv_handle->output[i].fb_chan == MEM_FG_SYNC) {
				int blank = FB_BLANK_POWERDOWN;
				if ( ioctl(ipu_priv_handle->output[i].fd_fb, FBIOBLANK, blank) < 0) {
					dbg(DBG_ERR, "POWERDOWN FB failed!\n");
				}
			}
		}

		if((ipu_priv_handle->output[i].task_mode & ROT_MODE) &&
			(ipu_priv_handle->output[i].task_mode & IC_MODE))
			ipu_unlink_channels(ipu_priv_handle->output[i].ic_chan,
					ipu_priv_handle->output[i].rot_chan);

		if(ipu_priv_handle->output[i].task_mode & IC_MODE)
			ipu_uninit_channel(ipu_priv_handle->output[i].ic_chan);

		if(ipu_priv_handle->output[i].task_mode & ROT_MODE)
			ipu_uninit_channel(ipu_priv_handle->output[i].rot_chan);
	}

	g_task_in_use &= ~(ipu_priv_handle->output[0].ipu_task | ipu_priv_handle->output[1].ipu_task);

	dbg(DBG_INFO, "g_task_in_use 0x%x\n", g_task_in_use);

	_ipu_mem_free(ipu_handle);

	ipu_close();

	free((void *)ipu_priv_handle);

	pthread_mutex_unlock(&mutex);
}

int _ipu_task_enable(ipu_lib_handle_t * ipu_handle)
{
	int ret = 0, bufcnt, i, output_num;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	if (ipu_priv_handle->mode & OP_STREAM_MODE)
		bufcnt = 2;
	else
		bufcnt = 1;

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	/*setup irq*/
	ipu_clear_irq(ipu_priv_handle->irq);
	ret = ipu_register_generic_isr(ipu_priv_handle->irq, NULL);
	if (ret < 0) {
		dbg(DBG_ERR, "Ioctl IPU_REGISTER_GENERIC_ISR %d failed!\n", ipu_priv_handle->irq);
		goto done;
	}

	/* set channel buffer ready */
	for (i=0;i<output_num;i++) {
		if(ipu_priv_handle->output[i].task_mode == IC_MODE){
			if (i == 0)
				ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_INPUT_BUFFER, 0);
			ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_OUTPUT_BUFFER, 0);
			if (bufcnt == 2) {
				if (i == 0)
					ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_INPUT_BUFFER, 1);
				ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_OUTPUT_BUFFER, 1);
			}
		} else if (ipu_priv_handle->output[i].task_mode == ROT_MODE){
			ipu_select_buffer(ipu_priv_handle->output[i].rot_chan, IPU_INPUT_BUFFER, 0);
			ipu_select_buffer(ipu_priv_handle->output[i].rot_chan, IPU_OUTPUT_BUFFER, 0);
			if (bufcnt == 2) {
				ipu_select_buffer(ipu_priv_handle->output[i].rot_chan, IPU_INPUT_BUFFER, 1);
				ipu_select_buffer(ipu_priv_handle->output[i].rot_chan, IPU_OUTPUT_BUFFER, 1);
			}
		} else if(ipu_priv_handle->output[i].task_mode == (IC_MODE | ROT_MODE)){
			ipu_select_buffer(ipu_priv_handle->output[i].rot_chan, IPU_OUTPUT_BUFFER, 0);
			if (bufcnt == 2)
				ipu_select_buffer(ipu_priv_handle->output[i].rot_chan, IPU_OUTPUT_BUFFER, 1);

			if (i == 0)
				ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_INPUT_BUFFER, 0);
			ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_OUTPUT_BUFFER, 0);
			if (bufcnt == 2) {
				if (i == 0)
					ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_INPUT_BUFFER, 1);
				ipu_select_buffer(ipu_priv_handle->output[i].ic_chan, IPU_OUTPUT_BUFFER, 1);
			}
		}
	}

	/* enable channels */
	for (i=0;i<output_num;i++) {
		if(ipu_priv_handle->output[i].task_mode & ROT_MODE)
			ipu_enable_channel(ipu_priv_handle->output[i].rot_chan);
	}
	for (i=0;i<output_num;i++) {
		if(ipu_priv_handle->output[i].task_mode & IC_MODE)
			ipu_enable_channel(ipu_priv_handle->output[i].ic_chan);
	}
done:
	return ret;
}

void _ipu_task_disable(ipu_lib_handle_t * ipu_handle)
{
	int i, output_num;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	ipu_free_irq(ipu_priv_handle->irq, NULL);

	for (i=0;i<output_num;i++) {
		if(ipu_priv_handle->output[i].task_mode & IC_MODE){
			if (ipu_priv_handle->output[i].ipu_task & IC_ENC) {
				ipu_clear_irq(IPU_IRQ_PRP_IN_EOF);
				ipu_clear_irq(IPU_IRQ_PRP_ENC_OUT_EOF);
			} else if (ipu_priv_handle->output[i].ipu_task & IC_VF) {
				ipu_clear_irq(IPU_IRQ_PRP_IN_EOF);
				ipu_clear_irq(IPU_IRQ_PRP_VF_OUT_EOF);
			} else if (ipu_priv_handle->output[i].ipu_task & IC_PP) {
				ipu_clear_irq(IPU_IRQ_PP_IN_EOF);
				ipu_clear_irq(IPU_IRQ_PP_OUT_EOF);
			}
			ipu_disable_channel(ipu_priv_handle->output[i].ic_chan, 1);
		}

		if(ipu_priv_handle->output[i].task_mode & ROT_MODE){
			if (ipu_priv_handle->output[i].ipu_task & ROT_ENC) {
				ipu_clear_irq(IPU_IRQ_PRP_ENC_ROT_IN_EOF);
				ipu_clear_irq(IPU_IRQ_PRP_ENC_ROT_OUT_EOF);
			} else if (ipu_priv_handle->output[i].ipu_task & ROT_VF) {
				ipu_clear_irq(IPU_IRQ_PRP_VF_ROT_IN_EOF);
				ipu_clear_irq(IPU_IRQ_PRP_VF_ROT_OUT_EOF);
			} else if (ipu_priv_handle->output[i].ipu_task & ROT_PP) {
				ipu_clear_irq(IPU_IRQ_PP_ROT_IN_EOF);
				ipu_clear_irq(IPU_IRQ_PP_ROT_OUT_EOF);
			}
			ipu_disable_channel(ipu_priv_handle->output[i].rot_chan, 1);
		}
	}
}

int _ipu_wait_for_irq(int irq, int ms)
{
	int wait = 0;
	ipu_event_info info;
	info.irq = irq;

	while (ipu_get_interrupt_event(&info) < 0) {
		dbg(DBG_INFO, "Can not get wait irq %d, try again!\n", irq);
		ipu_msleep(10);
		wait += 10;
		if (wait >= ms)
			break;
	}

	if (wait < ms)
		return 0;
	else
		return 1;
}

/*!
 * This function update the buffer for special ipu task, it must be run after
 * init function.
 *
 * @param	ipu_handle	The ipu task handle need to update buffer.
 *
 * @param	phyaddr		User can set phyaddr to their own allocated
 * 				buffer addr, ipu lib will update the buffer
 * 				from this address for process. If user do not
 * 				want to use it, please let it be zero, and
 * 				fill the buffer according to inbuf_start
 * 				parameter in ipu_handle.
 *
 * @param	output_callback	IPU lib will call output_callback funtion
 * 				when there is output data.
 *
 * @param	output_cb_arg	The argument will be passed to output_callback.
 *
 * @return	This function returns the next update buffer index number on success
 * 		or negative error code on fail.
 */
int mxc_ipu_lib_task_buf_update(ipu_lib_handle_t * ipu_handle,
	dma_addr_t phyaddr, void (output_callback)(void *, int),
	void * output_cb_arg)
{
	int ret, i, output_num;
	ipu_lib_priv_handle_t * ipu_priv_handle = (ipu_lib_priv_handle_t *)ipu_handle->priv;

	if (ipu_priv_handle->output[1].ipu_task)
		output_num = 2;
	else
		output_num = 1;

	if (ipu_priv_handle->enabled == 0) {
		pthread_mutex_lock(&mutex);

		if ((ret = _ipu_task_enable(ipu_handle)) < 0) {
			pthread_mutex_unlock(&mutex);
			return ret;
		}

		pthread_mutex_unlock(&mutex);

		dbg(DBG_INFO, "\033[0;34mipu task begin:\033[0m\n");

		if (ipu_priv_handle->mode & OP_STREAM_MODE)
			ipu_priv_handle->input_fr_cnt = 2;
		else
			ipu_priv_handle->input_fr_cnt = 1;

		if (_ipu_wait_for_irq(ipu_priv_handle->irq, 100)) {
			dbg(DBG_ERR, "wait for irq %d time out!\n", ipu_priv_handle->irq);
			return -1;
		}

		for (i=0;i<output_num;i++) {
			if (ipu_priv_handle->output[i].show_to_fb) {
				int blank = FB_BLANK_UNBLANK;
				if ( ioctl(ipu_priv_handle->output[i].fd_fb, FBIOBLANK, blank) < 0) {
					dbg(DBG_ERR, "UNBLANK FB failed!\n");
				}
			}
		}

		if (output_callback)
			output_callback(output_cb_arg, ipu_priv_handle->output_bufnum);

		ipu_priv_handle->output_fr_cnt = 1;
		ipu_priv_handle->enabled = 1;
	} else {
		dbg(DBG_DEBUG, "update pingpang %d\n", ipu_priv_handle->update_bufnum);
		dbg(DBG_DEBUG, "output pingpang %d\n", ipu_priv_handle->output_bufnum);

		if (ipu_priv_handle->mode & OP_STREAM_MODE) {
			if (_ipu_wait_for_irq(ipu_priv_handle->irq, 100)) {
				dbg(DBG_ERR, "wait for irq %d time out!\n", ipu_priv_handle->irq);
				return -1;
			}

			if (output_callback)
				output_callback(output_cb_arg, ipu_priv_handle->output_bufnum);
		}

		for (i=0;i<output_num;i++)
			if (!ipu_priv_handle->output[i].show_to_fb)
				ipu_select_buffer(ipu_priv_handle->output[i].end_chan,
					IPU_OUTPUT_BUFFER, ipu_priv_handle->update_bufnum);
		if (phyaddr) {
			dbg(DBG_DEBUG, "update with user defined buffer phy 0x%x\n", phyaddr);
			ipu_update_channel_buffer(ipu_priv_handle->output[0].begin_chan, IPU_INPUT_BUFFER,
				ipu_priv_handle->update_bufnum, phyaddr);
		}
		ipu_select_buffer(ipu_priv_handle->output[0].begin_chan, IPU_INPUT_BUFFER,
					ipu_priv_handle->update_bufnum);

		if (ipu_priv_handle->mode & OP_STREAM_MODE)
			ipu_priv_handle->update_bufnum = ipu_priv_handle->update_bufnum ? 0 : 1;
		else {
			if (_ipu_wait_for_irq(ipu_priv_handle->irq, 100)) {
				dbg(DBG_ERR, "wait for irq %d time out!\n", ipu_priv_handle->irq);
				return -1;
			}

			if (output_callback)
				output_callback(output_cb_arg, ipu_priv_handle->output_bufnum);
		}

		ipu_priv_handle->input_fr_cnt++;
		ipu_priv_handle->output_fr_cnt++;
	}

	if (ipu_priv_handle->mode & OP_STREAM_MODE)
		ipu_priv_handle->output_bufnum = ipu_priv_handle->output_bufnum ? 0 : 1;

	return ipu_priv_handle->update_bufnum;
}
