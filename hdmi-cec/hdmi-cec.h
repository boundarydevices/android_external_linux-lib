/*
 * Copyright 2005-2012 Freescale Semiconductor, Inc.
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
 * @defgroup HDMI low level library
 */
/*!
 *
 * @brief This file contains the HDMI low level API declarations.
 *
 * @ingroup HDMI
 */
#ifndef __HDMI_CEC_H__
#define __HDMI_CEC_H__

#define MAX_CEC_MESSAGE_LEN		16

#define HDMI_CEC_DEVICE_READY	1
#define HDMI_CEC_RECEIVE_MESSAGE 2


#define TV_ADDRESS		0
#define RECORD_DEVICE1_ADDRESS		1
#define RECORD_DEVICE2_ADDRESS		2
#define TUNER_DEVICE1_ADDRESS		3
#define PLAYBACK_DEVICE1_ADDRESS	4
#define AUDIO_SYSTEM_ADDRESS		5
#define TUNER_DEVICE2_ADDRESS		6
#define TUNER_DEVICE3_ADDRESS		7
#define PLAYBACK_DEVICE2_ADDRESS	8
#define RECORD_DEVICE3_ADDRESS		9
#define TUNER_DEVICE4_ADDRESS		10
#define PLAYBACK_DEVICE3_ADDRESS	11
#define SPECIFIC_USE_ADDRESS		14
#define UNREGISTERED_DEVICE_ADDRESS		15

#ifndef	true
#define true	1
#endif
#ifndef	false
#define false	0
#endif

typedef unsigned char bool;

/*!
 * Enumeration of device type.
 */
enum {
	TV_Device = 0,
	Playback_Device,
	Record_Device,
	Tuner_Device,
	Specific_Device,
};

/*!
 * Enumeration of device status.
 */
enum {
	IDLE = 0,
	CABLE_PLUGOUT,
	CABLE_PLUGIN,
	ALLOCADDR,
	READY,
};

typedef struct hdmi_cec_message {
	unsigned char source_addr;
	unsigned char opcode;
	int operand_len;
	unsigned char *operand;
}hdmi_cec_message;

typedef int (*hdmi_cec_callback)(unsigned char event_type, void *parg);
/*!
 * @brief Initilize device module of HDMI CEC
 *
 * @param None;
 *
 * @return
 * @li 0        success.
 * @li -1		failure.
 */
int hdmi_cec_init(void);
/*!
 * @brief deinitilize device module of HDMI CEC
 *
 * @param None;
 *
 * @return
 * @li 0        success.
 * @li -1		failure.
 */
int hdmi_cec_deinit(void);
/*!
 * @brief Open HDMI CEC device
 *  When CEC high-level procotol wants to communicate with other CEC device by HDMI CEC line,
 *  this function call is needed, to open the CEC device,
 *  pass the device type which it want to advertise functionality as,
 *  and callback function to receive CEC message from other device on CEC bus,
 *  the function is called when CEC module receive a message on bus.
 *
 * @param  Device_Type  a type of HDMI CEC device, such as Playback_Device;
 *         callback     a callback function to receive CEC message
 * @return
 * @li 0        success.
 * @li -1		failure if Device type is not support.
 */
int hdmi_cec_open(int Device_Type,hdmi_cec_callback callback);
/*!
 * @brief Close HDMI CEC device
 *  When CEC high-level procotol wants to stop the current functionality,
 *  this function call is needed, to close the CEC device,
 *  pass the device type which it open previouly.
 *
 * @param  Device_Type  a type of HDMI CEC device, such as Playback_Device;

 * @return
 * @li 0        success.
 * @li -1		failure if Device type don't opened.
 */
int hdmi_cec_close(int Device_Type);
/*!
 * @brief Close HDMI CEC device
 *  When CEC high-level procotol wants to send a message to other device,
 *  this function call is needed.
 *
 * @param  dest_addr  a destination logical address to identify the Destination of the current message;
           opcode     used to identify the current message
		   operand_len the length of operand
		   operand    the parameter of opcode
 * @return
 * @li 0        success.
 * @li -1		failure if Device type don't opened.
 */
int hdmi_cec_send_message(unsigned char dest_addr, unsigned char opcode, int operand_len,unsigned char *operand);
#endif
