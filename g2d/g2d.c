/*
 *  Copyright (C) 2013-2014 Freescale Semiconductor, Inc.
 *  All Rights Reserved.
 *
 *  The following programs are the sole property of Freescale Semiconductor Inc.,
 *  and contain its proprietary and confidential information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/pxp_device.h>
#include "g2d.h"

#define PXP_DEV_NAME "/dev/pxp_device"
#define g2d_printf printf

static int fd = -1;
static int open_count;
static pthread_spinlock_t lock;

#define g2d_config_chan(config)						       \
do {									       \
	int ret;							       \
	ret = ioctl(fd, PXP_IOC_CONFIG_CHAN, config);			       \
	if (ret < 0) {							       \
		g2d_printf("%s: failed to config pxp channel\n", __func__);\
		return -1;						       \
	}								       \
} while(0)

struct g2dContext {
	int handle;          /* allocated dma channel handle from PXP*/
	unsigned int blending;
	unsigned int global_alpha_enable;
	unsigned int current_type;
	bool dither;
	bool blend_dim;
};

static int g2d_has_alpha(enum g2d_format format)
{
	return format == G2D_BGRA8888 ? 1 : 0;
}

static int g2d_decide_overlay_support(unsigned int format)
{
	switch(format) {
	/* supported */
	case G2D_RGB565:
		return PXP_PIX_FMT_RGB565;
	case G2D_BGRX8888:
		return PXP_PIX_FMT_RGB32;
	case G2D_BGRA8888:
		return PXP_PIX_FMT_BGRA32;
	/* unsupported */
	default:
		g2d_printf("%s: unsupported format for overlay\n", __func__);
		break;
	}

	return -1;
}

static int g2d_decide_ps_support(unsigned int format)
{
	switch(format) {
	case G2D_RGB565:
		return PXP_PIX_FMT_RGB565;
	case G2D_BGRX8888:
		return PXP_PIX_FMT_RGB32;
	/* yuv format */
	case G2D_UYVY:
		return PXP_PIX_FMT_UYVY;
	case G2D_VYUY:
		return PXP_PIX_FMT_VYUY;
	case G2D_YUYV:
		return PXP_PIX_FMT_YUYV;
	case G2D_YVYU:
		return PXP_PIX_FMT_YVYU;
	case G2D_I420:
		return PXP_PIX_FMT_YUV420P;
	case G2D_YV12:
		return PXP_PIX_FMT_YVU420P;
	case G2D_NV12:
		return PXP_PIX_FMT_NV12;
	case G2D_NV21:
		return PXP_PIX_FMT_NV21;
	case G2D_NV16:
		return PXP_PIX_FMT_NV16;
	case G2D_NV61:
		return PXP_PIX_FMT_NV61;
	default:
		g2d_printf("%s: unsupported format for ps\n", __func__);
		break;
	}

	return -1;
}

static int g2d_decide_out_support(unsigned int format)
{
	switch(format) {
	case G2D_RGB565:
		return PXP_PIX_FMT_RGB565;
	case G2D_BGRX8888:
		return PXP_PIX_FMT_RGB32;
	case G2D_BGRA8888:
		return PXP_PIX_FMT_BGRA32;
	/* yuv format */
	case G2D_UYVY:
		return PXP_PIX_FMT_UYVY;
	case G2D_VYUY:
		return PXP_PIX_FMT_VYUY;
	case G2D_NV12:
		return PXP_PIX_FMT_NV12;
	case G2D_NV21:
		return PXP_PIX_FMT_NV21;
	case G2D_NV16:
		return PXP_PIX_FMT_NV16;
	case G2D_NV61:
		return PXP_PIX_FMT_NV61;
	default:
		g2d_printf("%s: unsupported format for output\n", __func__);
		break;
	}

	return -1;
}

static int g2d_get_bpp(unsigned int format)
{
	switch(format) {
	case G2D_RGB565:
		return 16;
	case G2D_BGRX8888:
	case G2D_BGRA8888:
		return 32;
	case G2D_UYVY:
	case G2D_YUYV:
	case G2D_VYUY:
	case G2D_YVYU:
		return 16;
	/* for the multi-plane format,
	 * only return the bits number
	 * for Y plane
	 */
	case G2D_NV12:
	case G2D_NV21:
	case G2D_NV16:
	case G2D_NV61:
	case G2D_YV12:
	case G2D_I420:
		return 8;
	default:
		g2d_printf("%s: unsupported format for getting bpp\n", __func__);
	}
	return 0;
}

int g2d_open(void **handle)
{
	int ret;
	static int channel;
	struct g2dContext *context;

	if (handle == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	context = (struct g2dContext *)calloc(1, sizeof(struct g2dContext));
	if (context == NULL) {
		g2d_printf("malloc memory failed for g2dcontext!\n");
		goto err2;
	}

	pthread_spin_lock(&lock);
	if (++open_count == 1) {
		fd = open(PXP_DEV_NAME, O_RDWR);
		if (fd < 0) {
			g2d_printf("open pxp device failed!\n");
			goto err1;
		}
		ret = ioctl(fd, PXP_IOC_GET_CHAN, &channel);
		if (ret < 0) {
			g2d_printf("%s: failed to get pxp channel\n",
				    __func__);
			goto err0;
		}
	}
	context->handle = channel;
	pthread_spin_unlock(&lock);

	*handle = (void*)context;
	return 0;
err0:
	close(fd);
	open_count--;
err1:
	pthread_spin_unlock(&lock);
	free(context);
err2:
	*handle = NULL;
	return -1;
}

int g2d_close(void *handle)
{
	int ret;
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	pthread_spin_lock(&lock);
	if (!open_count) {
		pthread_spin_unlock(&lock);
		return 0;
	}

	if (open_count == 1) {
		ret = ioctl(fd, PXP_IOC_PUT_CHAN, &context->handle);
		if (ret < 0) {
			pthread_spin_unlock(&lock);
			g2d_printf("%s: failed to put pxp channel!\n",
				   __func__);
			return -1;
		}
		close(fd);
		fd = -1;
	}
	open_count--;
	pthread_spin_unlock(&lock);

	free(context);
	handle = NULL;

	return 0;
}

int g2d_make_current(void *handle, enum g2d_hardware_type type)
{
	struct g2dContext *context = (struct g2dContext*)handle;

	if (context == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	if (context->current_type == type)
		return 0;

	switch(type) {
	case G2D_HARDWARE_2D:
		context->current_type = type;
		break;
	default:
		g2d_printf("%s: unsupported hardware type %d\n", __func__, type);
		return -1;
	}
	return 0;
}

int g2d_query_cap(void *handle, enum g2d_cap_mode cap, int *enable)
{
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	if (enable == NULL)
		return -1;

	switch(cap) {
	case G2D_BLEND:
		*enable = (context->blending == 1);
		break;
	case G2D_GLOBAL_ALPHA:
		*enable = (context->global_alpha_enable == 1);
		break;
	default:
		g2d_printf("%s: unsupported capability %d\n", __func__, cap);
		return -1;
	}

	return 0;
}

int g2d_cache_op(struct g2d_buf *buf, enum g2d_cache_mode op)
{
	int ret;
	unsigned int Bytes;
	void *Logical;
	struct pxp_mem_flush flush;

	if (!buf) {
		g2d_printf("%s: invalid buffer !\n", __func__);
		return -1;
	}

	Bytes = buf->buf_size;
	Logical = buf->buf_vaddr;

	if (!Bytes || !Logical) {
		g2d_printf("%s: invalid buffer data !\n", __func__);
		return -1;
	}

	switch (op) {
	case G2D_CACHE_CLEAN:
		flush.type = CACHE_CLEAN;
		break;
	case G2D_CACHE_FLUSH:
		flush.type = CACHE_FLUSH;
		break;
	case G2D_CACHE_INVALIDATE:
		flush.type = CACHE_INVALIDATE;
		break;
	default:
		g2d_printf("%s: invalid cache op !\n", __func__);
		return -1;
	}

	flush.handle = *(unsigned int *)buf->buf_handle;
	ret = ioctl(fd, PXP_IOC_FLUSH_PHYMEM, &flush);
	if (ret < 0) {
		g2d_printf("%s: flush dma buffer failed\n", __func__);
		return -1;
	}

	return 0;
}

int g2d_enable(void *handle, enum g2d_cap_mode cap)
{
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	switch(cap) {
	case G2D_BLEND:
		context->blending = 1;
		break;
	case G2D_GLOBAL_ALPHA:
		context->global_alpha_enable = 1;
		break;
	/*TODO PXP doesn't support dithering yet */
	default:
		g2d_printf("%s: unknown cap %d request\n", __func__, cap);
		return -1;
	}

	return 0;
}

int g2d_disable(void *handle, enum g2d_cap_mode cap)
{
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	switch(cap) {
	case G2D_BLEND:
		context->blending = 0;
		break;
	case G2D_GLOBAL_ALPHA:
		context->global_alpha_enable = 0;
		break;
	default:
		g2d_printf("%s: unknown cap %d request\n", __func__, cap);
		return -1;
	}

	return 0;
}

struct g2d_buf *g2d_alloc(int size, int cacheable)
{
	int ret;
	void *addr;
	struct g2d_buf *buf = NULL;
	struct pxp_mem_desc mem_desc;

	buf = (struct g2d_buf*)calloc(1, sizeof(struct g2d_buf));
	if (buf ==  NULL) {
		g2d_printf("%s: malloc g2d_buf failed\n", __func__);
		return NULL;
	}

	buf->buf_handle = calloc(1, sizeof(unsigned int));
	if (buf->buf_handle == NULL)
		goto err;

	memset(&mem_desc, 0, sizeof(mem_desc));
	mem_desc.size  = size;
	mem_desc.mtype = cacheable ? MEMORY_TYPE_CACHED : MEMORY_TYPE_UNCACHED;

	ret = ioctl(fd, PXP_IOC_GET_PHYMEM, &mem_desc);

	if (ret < 0) {
		g2d_printf("%s: get pxp physical memory failed, ret = %d\n",
			   __func__, ret);
		goto err0;
	}

	addr = mmap(0, mem_desc.size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, mem_desc.phys_addr);
	if (addr < 0) {
		g2d_printf("%s: map buffer failed\n", __func__);
		ioctl(fd, PXP_IOC_PUT_PHYMEM, &mem_desc);
		goto err0;
	}
	mem_desc.virt_uaddr = (unsigned int)addr;
	*(unsigned int *)buf->buf_handle = mem_desc.handle;
	buf->buf_vaddr = addr;
	buf->buf_paddr = (int)mem_desc.phys_addr;
	buf->buf_size  = mem_desc.size;

	return buf;
err0:
	free(buf->buf_handle);
err:
	free(buf);
	return NULL;
}

int g2d_free(struct g2d_buf *buf)
{
	int ret;
	struct pxp_mem_desc mem_desc;

	if (buf == NULL) {
		g2d_printf("%s: Invalid g2d_buf to be freed\n", __func__);
		return -1;
	}

	munmap(buf->buf_vaddr, buf->buf_size);

	memset(&mem_desc, 0, sizeof(struct pxp_mem_desc));
	mem_desc.handle = *(unsigned int *)buf->buf_handle;
	ret = ioctl(fd, PXP_IOC_PUT_PHYMEM, &mem_desc);

	if (ret < 0) {
		g2d_printf("%s: free pxp physical memory failed\n", __func__);
		return -1;
	}

	free(buf->buf_handle);
	free(buf);
	return 0;
}

#define PXP_COPY_THRESHOLD (16*16*4)
int g2d_copy(void *handle, struct g2d_buf *d, struct g2d_buf* s, int size)
{
	unsigned int blit_size;
	struct pxp_config_data pxp_conf;
	struct pxp_layer_param *src_param = NULL, *out_param = NULL;

	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL || s == NULL || d == NULL) {
		g2d_printf("%s: null pointer access\n", __func__);
		return -1;
	}

	memset(&pxp_conf, 0, sizeof(struct pxp_config_data));

	src_param = &(pxp_conf.ol_param[0]);
	out_param = &(pxp_conf.out_param);

	if (size < PXP_COPY_THRESHOLD) {
		memcpy(d->buf_vaddr, s->buf_vaddr, size);
		return 0;
	}
	else if (size <= PXP_COPY_THRESHOLD * 4096) {
		src_param->width = PXP_COPY_THRESHOLD >> 2;
	}
	else {
		src_param->width = PXP_COPY_THRESHOLD;
	}

	src_param->stride = src_param->width;
	src_param->pixel_fmt = PXP_PIX_FMT_BGRA32;
	src_param->height = size / (src_param->width << 2);
	if (src_param->height > 16384)
		src_param->height = 16384;

	memcpy(out_param, src_param, sizeof(struct pxp_layer_param));
	out_param->pixel_fmt = PXP_PIX_FMT_BGRA32;
	src_param->paddr = s->buf_paddr;
	out_param->paddr = d->buf_paddr;

	blit_size = src_param->width * src_param->height * 4;
	pxp_conf.handle = context->handle;
	pxp_conf.proc_data.drect.top = 0;
	pxp_conf.proc_data.drect.left = 0;
	pxp_conf.proc_data.drect.width = src_param->width;
	pxp_conf.proc_data.drect.height = src_param->height;

	g2d_config_chan(&pxp_conf);

	if (blit_size == size)
		return 0;
	else if (size - blit_size > src_param->width * 4) {
		struct g2d_buf subs, subd;
		subs.buf_size = d->buf_size - blit_size;
		subd.buf_paddr = d->buf_paddr + blit_size;
		subd.buf_vaddr = (void*)(((int)d->buf_vaddr) + blit_size);

		subs.buf_size = s->buf_size - blit_size;;
		subs.buf_paddr = s->buf_paddr + blit_size;
		subs.buf_vaddr = (void*)(((int)s->buf_vaddr) + blit_size);
		return g2d_copy(handle, &subs, &subd, size - blit_size);
	}
	else {
		size = size - blit_size;
		memcpy(d->buf_vaddr + blit_size, s->buf_vaddr + blit_size, size);
		return 0;
	}
}

int g2d_clear(void *handle, struct g2d_surface *area)
{
	struct pxp_config_data pxp_conf;
	struct pxp_layer_param *out_param;
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: invalid handle\n", __func__);
		return -1;
	}

	if (area == NULL) {
		g2d_printf("%s: invalid clear area\n", __func__);
		return -1;
	}

	memset(&pxp_conf, 0, sizeof(struct pxp_config_data));
	out_param = &(pxp_conf.out_param);
	out_param->pixel_fmt = g2d_decide_out_support(area->format);
	if (out_param->pixel_fmt < 0) {
		g2d_printf("%s: unsupported output format\n", __func__);
		return -1;
	}

	out_param->width  = area->width;
	out_param->height = area->height;
	out_param->stride = area->stride;
	out_param->paddr  = area->planes[0];

	out_param->global_alpha_enable = 1;
	out_param->global_alpha = (area->clrcolor >> 24) & 0xff;
	pxp_conf.proc_data.bgcolor = area->clrcolor;

	pxp_conf.handle = context->handle;
	g2d_config_chan(&pxp_conf);

	return 0;
}

int g2d_blit(void *handle, struct g2d_surface *src, struct g2d_surface *dst)
{
	int dest_bpp;
	int srcRotate, dstRotate;
	struct pxp_config_data pxp_conf;
	struct pxp_layer_param *src_param, *out_param, *third_param = NULL;
	unsigned int srcWidth,srcHeight,dstWidth,dstHeight;
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: Invalid handle!\n", __func__);
		return -1;
	}

	if(!src || !dst)
	{
		g2d_printf("%s: Invalid src and dst parameters!\n", __func__);
		return -1;
	}

	if (!context->blend_dim) {
		srcWidth = src->right - src->left;
		srcHeight = src->bottom - src->top;

		if(srcWidth <=0 || srcHeight <= 0 || srcWidth > src->width || srcHeight > src->height || src->width > src->stride)
		{
			g2d_printf("%s: Invalid src rect, left %d, top %d, right %d, bottom %d, width %d, height %d, stride %d!\n",
					__FUNCTION__, src->left, src->top, src->right, src->bottom, src->width, src->height, src->stride);
			return -1;
		}

		if(!src->planes[0])
		{
			g2d_printf("%s: Invalid src planes[0] pointer=0x%x !\n", __FUNCTION__, src->planes[0]);
			return -1;
		}
	} else {
		g2d_printf("%s: dim blending is not supported yet!\n", __func__);
		return -1;
	}

	dstWidth = dst->right - dst->left;
	dstHeight = dst->bottom - dst->top;

	if(dstWidth <=0 || dstHeight <= 0 || dstWidth > dst->width || dstHeight > dst->height || dst->width > dst->stride)
	{
		g2d_printf("%s: Invalid dst rect, left %d, top %d, right %d, bottom %d, width %d, height %d, stride %d!\n",
				__FUNCTION__, dst->left, dst->top, dst->right, dst->bottom, dst->width, dst->height, dst->stride);
		return -1;
	}

	if(!dst->planes[0])
	{
		g2d_printf("%s: Invalid dst planes[0] pointer=0x%x !\n", __FUNCTION__, dst->planes[0]);
		return -1;
	}

	memset(&pxp_conf, 0, sizeof(struct pxp_config_data));

	if (g2d_has_alpha(src->format) ||
	    (context->blending && context->global_alpha_enable &&
	     src->global_alpha < 0xff)) {
		src_param = &(pxp_conf.ol_param[0]);
	}
	else {
		src_param = &(pxp_conf.s0_param);
	}
	out_param = &(pxp_conf.out_param);

	src_param->pixel_fmt = (src_param == &(pxp_conf.s0_param)) ?
				g2d_decide_ps_support(src->format) :
				g2d_decide_overlay_support(src->format);
	out_param->pixel_fmt = g2d_decide_out_support(dst->format);

	if (src_param->pixel_fmt == 0 || out_param->pixel_fmt == 0) {
		g2d_printf("%s: unsupport pixel format\n", __func__);
		return -1;
	}
	dest_bpp = g2d_get_bpp(dst->format);

	src_param->stride = src->stride;
	out_param->stride = dst->stride;
	src_param->width  = src->width;
	src_param->height = src->height;
	src_param->paddr  = src->planes[0];
	out_param->paddr  = dst->planes[0] + (dst->top * dst->stride + dst->left) * (dest_bpp >> 3);

	srcRotate = src->rot;
	dstRotate = dst->rot;
	pxp_conf.proc_data.hflip = ((srcRotate == G2D_FLIP_H) | (dstRotate == G2D_FLIP_H)) ? 1 : 0;
	pxp_conf.proc_data.vflip = ((srcRotate == G2D_FLIP_V) | (dstRotate == G2D_FLIP_V)) ? 1 : 0;

	if ((srcRotate == G2D_FLIP_H) || (srcRotate == G2D_FLIP_V))
		srcRotate = 0;
	if ((dstRotate == G2D_FLIP_H) || (dstRotate == G2D_FLIP_V))
		dstRotate = 0;

	switch(dstRotate - srcRotate) {
		case 1:
		case -3:
			pxp_conf.proc_data.rotate = 90;
			break;
		case 2:
		case -2:
			pxp_conf.proc_data.rotate = 180;
			break;
		case 3:
		case -1:
			pxp_conf.proc_data.rotate = 270;
			break;
	}
	if ((pxp_conf.proc_data.rotate == 90) || (pxp_conf.proc_data.rotate == 270)) {
		if ((src->right - src->left) != (dst->bottom - dst->top) ||
		    (src->bottom - src->top) != (dst->right - dst->left)) {
			/* only ps engine can do scaling */
			if (src_param == &(pxp_conf.ol_param[0])) {
				g2d_printf("%s: format with alpha cannot be scaled\n", __func__);
				return -1;
			}
		}
	} else {
		if ((src->right - src->left) != (dst->right - dst->left) ||
		    (src->bottom - src->top) != (dst->bottom - dst->top)) {
			/* only ps engine can do scaling */
			if (src_param == &(pxp_conf.ol_param[0])) {
				g2d_printf("%s: format with alpha cannot be scaled\n", __func__);
				return -1;
			}
		}
	}

	if (pxp_conf.proc_data.rotate && (src_param == &(pxp_conf.s0_param))) {
		pxp_conf.proc_data.rot_pos = 1;
	}

	if ((pxp_conf.proc_data.rotate == 90) || (pxp_conf.proc_data.rotate == 270)) {
		if (src_param == &(pxp_conf.ol_param[0])) {
			out_param->width  = pxp_conf.proc_data.drect.width  = dst->bottom - dst->top;
			out_param->height = pxp_conf.proc_data.drect.height = dst->right  - dst->left;
		} else {
			out_param->width  = pxp_conf.proc_data.drect.width  = dst->right  - dst->left;
			out_param->height = pxp_conf.proc_data.drect.height = dst->bottom - dst->top;
		}
	} else {
		out_param->width  = pxp_conf.proc_data.drect.width  = dst->right  - dst->left;
		out_param->height = pxp_conf.proc_data.drect.height = dst->bottom - dst->top;
	}
	/* need do alpha blending */
	if (context->blending) {
		if (src_param == &(pxp_conf.ol_param[0])) {
			third_param = &(pxp_conf.s0_param);
			third_param->pixel_fmt = g2d_decide_ps_support(dst->format);
		} else {
			third_param = &(pxp_conf.ol_param[0]);
			third_param->pixel_fmt = g2d_decide_overlay_support(dst->format);
		}
		if (third_param->pixel_fmt == 0) {
			g2d_printf("%s: unsupport blending type\n", __func__);
			return -1;
		}

		pxp_conf.proc_data.combine_enable = 1;

		if (src_param == &(pxp_conf.ol_param[0])) {
			switch(src->blendfunc) {
			case G2D_ZERO:  //Cs = Cs * 0
				if (dst->blendfunc != G2D_ONE) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				src_param->global_alpha_enable = 1;
				src_param->global_alpha = 0xff;
				src_param->global_override = 1;
				break;
			case G2D_ONE:   //Cs = Cs * 1
				if (dst->blendfunc != G2D_ZERO) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				src_param->global_alpha_enable = 1;
				src_param->global_alpha = 0x0;
				src_param->global_override = 1;
				break;
			case G2D_SRC_ALPHA: //Cs = Cs * As
				if (dst->blendfunc != G2D_ONE_MINUS_SRC_ALPHA) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				src_param->alpha_invert = 1;
				break;
			case G2D_ONE_MINUS_SRC_ALPHA:  //Cs = Cs * (1 - As)
				if (dst->blendfunc != G2D_SRC_ALPHA) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				break;
			default:
				g2d_printf("%s: unspported source blendfunc\n", __func__);
				return -1;
			}
		} else {
			switch(src->blendfunc) {
			case G2D_ZERO:
				if (dst->blendfunc != G2D_ONE) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				third_param->global_alpha_enable = 1;
				third_param->global_alpha = 0x0;
				third_param->global_override = 1;
				break;
			case G2D_ONE:
				if (dst->blendfunc != G2D_ZERO) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				third_param->global_alpha_enable = 1;
				third_param->global_alpha = 0xff;
				third_param->global_override = 1;
				break;
			case G2D_DST_ALPHA: //Cs = Cs * Ad
				if (dst->blendfunc != G2D_ONE_MINUS_DST_ALPHA) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				break;
			case G2D_ONE_MINUS_DST_ALPHA: //Cs = Cs * (1 - Ad)
				if (dst->blendfunc != G2D_DST_ALPHA) {
					g2d_printf("%s(line %d): unsupported blending operation\n",
						   __func__, __LINE__);
					return -1;
				}
				third_param->alpha_invert = 1;
				break;
			default:
				g2d_printf("%s: unsupported source blendfunc\n", __func__);
				return -1;
			}
		}
		if (context->global_alpha_enable && (src->global_alpha < 0xff)) {
			if (src_param == &(pxp_conf.ol_param[0])) {
				src_param->global_alpha_enable = 1;
				src_param->global_alpha = src->global_alpha & 0xff;
			}
			else {
				g2d_printf("%s: source with global alpha should not be in PS\n", __func__);
				return -1;
			}
		}
		if (context->global_alpha_enable && (dst->global_alpha < 0xff)) {
			if (src_param == &(pxp_conf.s0_param)) {
				third_param->global_alpha_enable = 1;
				third_param->global_alpha = dst->global_alpha & 0xff;
			}
			else {
				g2d_printf("%s: dest with global alpha should not be in PS\n", __func__);
				return -1;
			}
		}
	}

	if (src_param == &(pxp_conf.s0_param)) {
		pxp_conf.proc_data.srect.top    = src->top;
		pxp_conf.proc_data.srect.left   = src->left;
		if (pxp_conf.proc_data.rotate == 90 || pxp_conf.proc_data.rotate == 270) {
			pxp_conf.proc_data.srect.width  = src->bottom - src->top;
			pxp_conf.proc_data.srect.height = src->right  - src->left;
		}
		else {
			pxp_conf.proc_data.srect.width  = src->right  - src->left;
			pxp_conf.proc_data.srect.height = src->bottom - src->top;
		}
	}

	if (context->blending) {
		third_param->stride = out_param->stride;
		third_param->width  = out_param->width;
		third_param->height = out_param->height;
		third_param->paddr  = out_param->paddr;
		if (third_param == &(pxp_conf.s0_param)) {
			pxp_conf.proc_data.srect.width  = out_param->width;
			pxp_conf.proc_data.srect.height = out_param->height;
		}
	}

	pxp_conf.handle = context->handle;
	g2d_config_chan(&pxp_conf);

	return 0;
}

int g2d_flush(void *handle)
{
	int ret;
	struct g2dContext *context = (struct g2dContext *)handle;

	if (context == NULL) {
		g2d_printf("%s: Invalid handle!\n", __func__);
		return -1;
	}

	ret = ioctl(fd, PXP_IOC_START_CHAN, &context->handle);
	if (ret < 0) {
		g2d_printf("%s: failed to commit pxp task\n", __func__);
		return -1;
	}

	return 0;
}

int g2d_finish(void *handle)
{
	int ret;
	struct g2dContext *context = (struct g2dContext *)handle;
	struct pxp_chan_handle chan_handle;

	if (context == NULL) {
		g2d_printf("%s: Invalid handle!\n", __func__);
		return -1;
	}

	ret = ioctl(fd, PXP_IOC_START_CHAN, &context->handle);
	if (ret < 0) {
		g2d_printf("%s: failed to commit pxp task\n", __func__);
		return -1;
	}

	chan_handle.handle = context->handle;
	ret = ioctl(fd, PXP_IOC_WAIT4CMPLT, &chan_handle);
	if (ret < 0) {
		g2d_printf("%s: failed to wait task complete\n", __func__);
		return -1;
	}

	return 0;
}
