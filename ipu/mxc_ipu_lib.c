/*
 * Copyright 2004-2007 Freescale Semiconductor, Inc. All Rights Reserved.
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
 * @file mxc_ipu_lib.c
 *
 * @brief IPU library implementation
 *
 * @ingroup IPU
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>	
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>    
#include <sys/mman.h>
#include <math.h>
#include <string.h>
#include <malloc.h>
#include <sys/time.h>
#include <asm/arch/ipu.h>

static int fd_ipu = -1;


int32_t ipu_init_channel(ipu_channel_t channel, ipu_channel_params_t * params)
{
	ipu_channel_parm parm;
	parm.channel = channel;
	if(params != NULL){
		parm.params = *params;
		parm.flag = 0;
	}else{
		parm.flag = 1;
	}
	return ioctl(fd_ipu, IPU_INIT_CHANNEL, &parm);
}
void ipu_uninit_channel(ipu_channel_t channel)
{
	ioctl(fd_ipu, IPU_UNINIT_CHANNEL, &channel);
}

int32_t ipu_init_channel_buffer(ipu_channel_t channel, ipu_buffer_t type,
				uint32_t pixel_fmt,
				uint16_t width, uint16_t height,
				uint32_t stride,
				ipu_rotate_mode_t rot_mode,
				dma_addr_t phyaddr_0, dma_addr_t phyaddr_1,
				uint32_t u_offset, uint32_t v_offset)
{
	ipu_channel_buf_parm buf_parm;
	buf_parm.channel = channel;
	buf_parm.type = type;
	buf_parm.pixel_fmt = pixel_fmt;
	buf_parm.width = width;
	buf_parm.height = height;
	buf_parm.stride = stride;
	buf_parm.rot_mode = rot_mode;
	buf_parm.phyaddr_0 = phyaddr_0;
	buf_parm.phyaddr_1 = phyaddr_1;
	buf_parm.u_offset = u_offset;
	buf_parm.v_offset = v_offset;
	return ioctl(fd_ipu, IPU_INIT_CHANNEL_BUFFER, &buf_parm);
}

int32_t ipu_update_channel_buffer(ipu_channel_t channel, ipu_buffer_t type,
				  uint32_t bufNum, dma_addr_t phyaddr)
{
	ipu_channel_buf_parm buf_parm;
	buf_parm.channel = channel;
	buf_parm.type = type;
	buf_parm.bufNum = bufNum; 
	if(bufNum == 0){
		buf_parm.phyaddr_0 = phyaddr;
		buf_parm.phyaddr_1 = (dma_addr_t)NULL;
	}
	else{
		buf_parm.phyaddr_1 = phyaddr;
		buf_parm.phyaddr_0 = (dma_addr_t)NULL;
	}
	return ioctl(fd_ipu, IPU_UPDATE_CHANNEL_BUFFER, &buf_parm);
	
}

int32_t ipu_select_buffer(ipu_channel_t channel,
			  ipu_buffer_t type, uint32_t bufNum)
{
	ipu_channel_buf_parm buf_parm;
	buf_parm.channel = channel;
	buf_parm.type = type;
	buf_parm.bufNum = bufNum;
	return ioctl(fd_ipu, IPU_SELECT_CHANNEL_BUFFER, &buf_parm);
}

int32_t ipu_link_channels(ipu_channel_t src_ch, ipu_channel_t dest_ch)
{
	ipu_channel_link link;
	link.src_ch = src_ch;
	link.dest_ch = dest_ch;
	return ioctl(fd_ipu, IPU_LINK_CHANNELS, &link);
}
int32_t ipu_unlink_channels(ipu_channel_t src_ch, ipu_channel_t dest_ch)
{
	ipu_channel_link link;
	link.src_ch = src_ch;
	link.dest_ch = dest_ch;
	return ioctl(fd_ipu, IPU_UNLINK_CHANNELS, &link);
}

int32_t ipu_enable_channel(ipu_channel_t channel)
{
	return ioctl(fd_ipu, IPU_ENABLE_CHANNEL, &channel);
}
int32_t ipu_disable_channel(ipu_channel_t channel, bool wait_for_stop)
{
	ipu_channel_info c_info;
	c_info.channel = channel;
	c_info.stop = wait_for_stop;
	return ioctl(fd_ipu, IPU_DISABLE_CHANNEL, &c_info);
}

void ipu_enable_irq(uint32_t irq)
{
	ioctl(fd_ipu, IPU_ENABLE_IRQ, &irq);
}
void ipu_disable_irq(uint32_t irq)
{
	ioctl(fd_ipu, IPU_DISABLE_IRQ, &irq);
}
void ipu_clear_irq(uint32_t irq)
{
	ioctl(fd_ipu, IPU_CLEAR_IRQ, &irq);
}

void ipu_free_irq(uint32_t irq, void *dev_id)
{
	ipu_irq_info irq_info;
	irq_info.irq = irq;
	irq_info.dev_id = dev_id;
	ioctl(fd_ipu, IPU_FREE_IRQ, &irq_info);
}

bool ipu_get_irq_status(uint32_t irq)
{
	return ioctl(fd_ipu, IPU_REQUEST_IRQ_STATUS, &irq);
}

/* SDC API */
int32_t ipu_sdc_init_panel(ipu_panel_t panel,
			   uint32_t pixel_clk,
			   uint16_t width, uint16_t height,
			   uint32_t pixel_fmt,
			   uint16_t hStartWidth, uint16_t hSyncWidth,
			   uint16_t hEndWidth, uint16_t vStartWidth,
			   uint16_t vSyncWidth, uint16_t vEndWidth,
			   ipu_di_signal_cfg_t sig)
{
	ipu_sdc_panel_info p_info;
	p_info.panel = panel;
	p_info.pixel_clk = pixel_clk;
	p_info.width = width;
	p_info.height = height;
	p_info.pixel_fmt = pixel_fmt;
	p_info.hStartWidth = hStartWidth;
	p_info.hSyncWidth = hSyncWidth;
	p_info.hEndWidth = hEndWidth;	
	p_info.vStartWidth = vStartWidth;
	p_info.vSyncWidth = vSyncWidth;
	p_info.vEndWidth = vEndWidth;
	p_info.signal = sig;	
	return ioctl(fd_ipu,IPU_SDC_INIT_PANEL,&p_info);
}
int32_t ipu_sdc_set_window_pos(ipu_channel_t channel, int16_t x_pos,
			       int16_t y_pos)
{
	ipu_sdc_window_pos w_pos;
	w_pos.channel = channel;
	w_pos.x_pos = x_pos;
	w_pos.y_pos = y_pos;
	return ioctl(fd_ipu, IPU_SDC_SET_WIN_POS, &w_pos);
}
int32_t ipu_sdc_set_global_alpha(bool enable, uint8_t alpha)
{
	ipu_sdc_global_alpha g_alpha;
	g_alpha.enable = enable;
	g_alpha.alpha = alpha;
	return ioctl(fd_ipu, IPU_SDC_SET_GLOBAL_ALPHA, &g_alpha);
}
int32_t ipu_sdc_set_color_key(ipu_channel_t channel, bool enable,
			      uint32_t colorKey)
{
	ipu_sdc_color_key c_key;
	c_key.channel = channel;
	c_key.enable = enable;
	c_key.colorKey = colorKey;
	return ioctl(fd_ipu, IPU_SDC_SET_COLOR_KEY, &c_key);
}
int32_t ipu_sdc_set_brightness(uint8_t value)
{
	return ioctl(fd_ipu, IPU_SDC_SET_BRIGHTNESS, &value);
}

/* ADC API */
int32_t ipu_adc_write_template(display_port_t disp, uint32_t * pCmd,
			       bool write)
{
	ipu_adc_template adc_template;
	adc_template.disp = disp;
	adc_template.pCmd = pCmd;
	adc_template.write = write;
	return ioctl(fd_ipu, IPU_ADC_WRITE_TEMPLATE, &adc_template);
}

int32_t ipu_adc_set_update_mode(ipu_channel_t channel,
				ipu_adc_update_mode_t mode,
				uint32_t refresh_rate, unsigned long addr,
				uint32_t * size)
{
	ipu_adc_update adc_update;
	adc_update.channel = channel;
	adc_update.mode = mode;
	adc_update.refresh_rate = refresh_rate;
	adc_update.addr = addr;
	adc_update.size = size;
	return ioctl(fd_ipu, IPU_ADC_UPDATE, &adc_update);
}

int32_t ipu_adc_get_snooping_status(uint32_t * statl, uint32_t * stath)
{
	ipu_adc_snoop adc_snoop;
	adc_snoop.statl = statl;
	adc_snoop.stath = stath;
	return ioctl(fd_ipu, IPU_ADC_SNOOP, &adc_snoop);
}

int32_t ipu_adc_write_cmd(display_port_t disp, cmddata_t type,
			  uint32_t cmd, const uint32_t * params,
			  uint16_t numParams)
{
	ipu_adc_cmd adc_cmd;
	adc_cmd.disp = disp;
	adc_cmd.type = type;
	adc_cmd.cmd = cmd;
	adc_cmd.params = params;
	adc_cmd.numParams = numParams;
	return ioctl(fd_ipu, IPU_ADC_CMD, &adc_cmd);
}

int32_t ipu_adc_init_panel(display_port_t disp,
			   uint16_t width, uint16_t height,
			   uint32_t pixel_fmt,
			   uint32_t stride,
			   ipu_adc_sig_cfg_t sig,
			   display_addressing_t addr,
			   uint32_t vsync_width, vsync_t mode)
{
	ipu_adc_panel adc_panel;
	adc_panel.disp = disp;
	adc_panel.width = width;
	adc_panel.height = height;
	adc_panel.pixel_fmt = pixel_fmt;
	adc_panel.stride = stride;
	adc_panel.signal = sig;
	adc_panel.addr = addr;
	adc_panel.vsync_width = vsync_width;
	adc_panel.mode = mode;
	return ioctl(fd_ipu, IPU_ADC_INIT_PANEL, &adc_panel);
}

int32_t ipu_adc_init_ifc_timing(display_port_t disp, bool read,
				uint32_t cycle_time,
				uint32_t up_time,
				uint32_t down_time,
				uint32_t read_latch_time, uint32_t pixel_clk)
{
	ipu_adc_ifc_timing adc_ifc;
	adc_ifc.disp = disp;
	adc_ifc.read = read;
	adc_ifc.cycle_time = cycle_time;
	adc_ifc.up_time = up_time;
	adc_ifc.down_time = down_time;
	adc_ifc.read_latch_time = read_latch_time;
	adc_ifc.pixel_clk = pixel_clk;
	return ioctl(fd_ipu, IPU_ADC_IFC_TIMING, &adc_ifc);
}

/* CMOS Sensor Interface API */
int32_t ipu_csi_init_interface(uint16_t width, uint16_t height,
			       uint32_t pixel_fmt, ipu_csi_signal_cfg_t sig)
{
	ipu_csi_interface csi_interface;
	csi_interface.width = width;
	csi_interface.height = height;
	csi_interface.pixel_fmt = pixel_fmt;
	csi_interface.signal = sig;
	return ioctl(fd_ipu, IPU_CSI_INIT_INTERFACE, &csi_interface);
}

int32_t ipu_csi_enable_mclk(int src, bool flag, bool wait)
{
	ipu_csi_mclk csi_mclk;
	csi_mclk.src = src;
	csi_mclk.flag = flag;
	csi_mclk.wait = wait;
	return ioctl(fd_ipu, IPU_CSI_ENABLE_MCLK, &csi_mclk);
}

int ipu_csi_read_mclk_flag(void)
{
	return ioctl(fd_ipu, IPU_CSI_READ_MCLK_FLAG, NULL);
}

void ipu_csi_flash_strobe(bool flag)
{
	ioctl(fd_ipu, IPU_CSI_FLASH_STROBE, &flag);
}

void ipu_csi_get_window_size(uint32_t * width, uint32_t * height)
{
	ipu_csi_window_size csi_win;
	ioctl(fd_ipu, IPU_CSI_GET_WIN_SIZE, &csi_win);
	*width = csi_win.width;
	*height = csi_win.height;
}

void ipu_csi_set_window_size(uint32_t width, uint32_t height)
{
	ipu_csi_window_size csi_win;
	csi_win.width = width;
	csi_win.height = height;
	ioctl(fd_ipu, IPU_CSI_SET_WIN_SIZE, &csi_win);
}

void ipu_csi_set_window_pos(uint32_t left, uint32_t top)
{
	ipu_csi_window csi_win;
	csi_win.left = left;
	csi_win.top = top;
	ioctl(fd_ipu, IPU_CSI_SET_WINDOW, &csi_win);
}

/* Post Filter functions */
int32_t ipu_pf_set_pause_row(uint32_t pause_row)
{
	return ioctl(fd_ipu, IPU_PF_SET_PAUSE_ROW, &pause_row);
}

uint32_t bytes_per_pixel(uint32_t fmt)
{
        switch (fmt) {
        case IPU_PIX_FMT_GENERIC:       /*generic data */
        case IPU_PIX_FMT_RGB332:
        case IPU_PIX_FMT_YUV420P:
        case IPU_PIX_FMT_YUV422P:
                return 1;
                break;
        case IPU_PIX_FMT_RGB565:
        case IPU_PIX_FMT_YUYV:
        case IPU_PIX_FMT_UYVY:
                return 2;
                break;
        case IPU_PIX_FMT_BGR24: 
        case IPU_PIX_FMT_RGB24:
                return 3;
                break;
        case IPU_PIX_FMT_GENERIC_32:    /*generic data */
        case IPU_PIX_FMT_BGR32:
        case IPU_PIX_FMT_RGB32:
        case IPU_PIX_FMT_ABGR32:
                return 4;
                break;
        default:
                return 1;
                break;
        }
        return 0;
}


/* Extra IPU-lib functions that are required */

int ipu_open()
{
	fd_ipu = open("/dev/mxc_ipu",O_RDWR);
	if(fd_ipu < 0)
		printf("Unable to Open IPU device\n");
	return fd_ipu;
}

void ipu_close()
{
	close(fd_ipu);
}

int ipu_register_generic_isr(int irq, void *dev)
{
	ipu_event_info ev; /* Defined in the ipu.h header file */
	ev.irq = irq;
	ev.dev = dev;
	return ioctl(fd_ipu,IPU_REGISTER_GENERIC_ISR,&ev);
}

int ipu_get_interrupt_event(ipu_event_info *ev)
{
	return ioctl(fd_ipu,IPU_GET_EVENT,ev);
}
