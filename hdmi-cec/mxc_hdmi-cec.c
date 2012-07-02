/*
 * Copyright 2009-2012 Freescale Semiconductor, Inc. All Rights Reserved.
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
 * @file mxc_hdmi-cec.c
 *
 * @brief HDMI low level library implementation
 *
 * @ingroup HDMI
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include "hdmi-cec.h"

/*
 * Ioctl definitions
 */

/* Use 'k' as magic number */
#define HDMICEC_IOC_MAGIC  'H'
/*
 * S means "Set" through a ptr,
 * T means "Tell" directly with the argument value
 * G means "Get": reply by setting through a pointer
 * Q means "Query": response is on the return value
 * X means "eXchange": G and S atomically
 * H means "sHift": T and Q atomically
 */
#define HDMICEC_IOC_SETLOGICALADDRESS	_IOW(HDMICEC_IOC_MAGIC,  1, unsigned char)
#define HDMICEC_IOC_STARTDEVICE	_IO(HDMICEC_IOC_MAGIC,  2)
#define HDMICEC_IOC_STOPDEVICE     	_IO(HDMICEC_IOC_MAGIC,  3)
#define HDMICEC_IOC_GETPHYADDRESS     	_IOR(HDMICEC_IOC_MAGIC,  4, unsigned char[4])

#define MAX_MESSAGE_LEN		16

#define MESSAGE_TYPE_RECEIVE_SUCCESS		1
#define MESSAGE_TYPE_NOACK		2
#define MESSAGE_TYPE_DISCONNECTED		3
#define MESSAGE_TYPE_CONNECTED		4
#define MESSAGE_TYPE_SEND_SUCCESS		5

typedef struct hdmi_cec_event{
	int event_type;
	int msg_len;
	unsigned char  msg[MAX_MESSAGE_LEN];
}hdmi_cec_event;

static int fd_cec = -1;
static bool cec_init_flag = false;
static bool cec_open_flag = false;
static int logical_address = UNREGISTERED_DEVICE_ADDRESS;
static int device_type;
static int device_status = IDLE;
static pthread_t poll_cec_pid;
pthread_mutex_t lockdevice;
static struct pollfd poll_fds[1];
static hdmi_cec_callback client_callback = NULL;

void *poll_cec_thread(void *pArg)
{
	int iret = pthread_detach(pthread_self());
	int timeout = 30;
	hdmi_cec_event event;
	hdmi_cec_message msg;
	unsigned char message[MAX_CEC_MESSAGE_LEN];
	unsigned char phy_address[4];
	if(iret != 0){
		printf("Can't detach at poll_cec_thread thread\n");
		pthread_exit(NULL);
	}
	iret = ioctl(fd_cec,HDMICEC_IOC_SETLOGICALADDRESS,logical_address);
	if(iret < 0){
		printf("Don't set logical address of Hdmi cec device!\n");
		pthread_exit(NULL);
	}
	else{
		pthread_mutex_lock(&lockdevice);
		device_status = ALLOCADDR;
		pthread_mutex_unlock(&lockdevice);
	}
	while(1){
		iret = poll(poll_fds, (unsigned long)1, timeout);
		pthread_mutex_lock(&lockdevice);
		if(false == cec_open_flag){
			printf("CEC Device is closed! \n");
			pthread_mutex_unlock(&lockdevice);
			break;
		}
		pthread_mutex_unlock(&lockdevice);
		if (iret == -1){
			printf("\n poll error !\n");
			continue;
		}
		if (iret == 0){
			//poll timeout
			continue;
		}
		memset(&event,0,sizeof(hdmi_cec_event));
		iret = read(fd_cec,&event,sizeof(hdmi_cec_event));
		if(iret < 0){
			printf("\n read error !\n");
			continue;
		}

		//printf("%s:line %d. event type=0x%x device status = 0x%x !\n",__func__,__LINE__,event.event_type,device_status);
		switch (device_status){
		case ALLOCADDR:
			if(MESSAGE_TYPE_DISCONNECTED == event.event_type){
				device_status = CABLE_PLUGOUT;
			} else if(MESSAGE_TYPE_NOACK == event.event_type){
				device_status = READY;
				ioctl(fd_cec,HDMICEC_IOC_GETPHYADDRESS,phy_address);
				memset(message,0,MAX_CEC_MESSAGE_LEN);
				/*Send <Report Physical Address> broadcast message*/
				message[0] = logical_address << 4 | 0x0F;
				message[1] = 0x84;
				message[2] = phy_address[0]<<4 | phy_address[1];
				message[3] = phy_address[2]<<4 | phy_address[3];
				switch (device_type){
				case Playback_Device:
					message[4] = 4;
					break;
				case Record_Device:
					message[4] = 1;
					break;
				case Tuner_Device:
					message[4] = 3;
					break;
				case TV_Device:
					message[4] = 0;
					break;
				default:
					message[4] = 7;
					break;
				}
				iret = write(fd_cec,message,5);
				if(iret < 0){
					printf("Don't send message by Hdmi cec device!\n");
				}
				if(client_callback)
					client_callback(HDMI_CEC_DEVICE_READY,NULL);
 			} else if(MESSAGE_TYPE_SEND_SUCCESS == event.event_type){
				if( Playback_Device == device_type){
					switch (logical_address){
					case PLAYBACK_DEVICE1_ADDRESS:
						logical_address = PLAYBACK_DEVICE2_ADDRESS;
						break;
					case PLAYBACK_DEVICE2_ADDRESS:
						logical_address = PLAYBACK_DEVICE3_ADDRESS;
						break;
					case RECORD_DEVICE1_ADDRESS:
						logical_address = RECORD_DEVICE2_ADDRESS;
						break;
					case RECORD_DEVICE2_ADDRESS:
						logical_address = RECORD_DEVICE3_ADDRESS;
						break;
					case TUNER_DEVICE1_ADDRESS:
						logical_address = TUNER_DEVICE2_ADDRESS;
						break;
					case TUNER_DEVICE2_ADDRESS:
						logical_address = TUNER_DEVICE3_ADDRESS;
						break;
					case TUNER_DEVICE3_ADDRESS:
						logical_address = TUNER_DEVICE4_ADDRESS;
						break;
					case PLAYBACK_DEVICE3_ADDRESS:
					case RECORD_DEVICE3_ADDRESS:
					case TUNER_DEVICE4_ADDRESS:
					default:
						logical_address = UNREGISTERED_DEVICE_ADDRESS;
						break;
					}
				}
				iret = ioctl(fd_cec,HDMICEC_IOC_SETLOGICALADDRESS,logical_address);
				if(iret < 0){
					printf("Don't set logical address of Hdmi cec device!\n");
					pthread_exit(NULL);
				}
				else
					device_status = READY;
			}
			else
				printf("Unhandle Event type is 0x%x !\n",event.event_type);
			break;
		case READY:
			if(MESSAGE_TYPE_DISCONNECTED == event.event_type){
				device_status = CABLE_PLUGOUT;
			}else if(MESSAGE_TYPE_RECEIVE_SUCCESS == event.event_type){
				memset(&msg,0,sizeof(hdmi_cec_message));
				msg.source_addr = (event.msg[0] & 0xf0) >> 4;
				if(2 == event.msg_len){
					msg.opcode = event.msg[1];
				} else if(event.msg_len > 2){
					msg.opcode = event.msg[1];
					msg.operand_len = event.msg_len - 2;
					msg.operand = &event.msg[2];
				}
				if(client_callback)
					client_callback(HDMI_CEC_RECEIVE_MESSAGE,&msg);
			}
			break;
		case CABLE_PLUGOUT:
			if(MESSAGE_TYPE_CONNECTED == event.event_type){
				device_status = CABLE_PLUGIN;
				ioctl(fd_cec,HDMICEC_IOC_STARTDEVICE,NULL);
			}
		case CABLE_PLUGIN:
			iret = ioctl(fd_cec,HDMICEC_IOC_SETLOGICALADDRESS,logical_address);
			if(iret < 0){
				printf("Don't set logical address of Hdmi cec device!\n");
				pthread_exit(NULL);
			}
			else{
				device_status = ALLOCADDR;
			}
			break;
		case IDLE:
			printf("Receive event when device status!\n");
			pthread_exit(NULL);
			break;
		default:
			printf("Unknow device status!\n");
		}
		pthread_mutex_unlock(&lockdevice);
	}
	pthread_exit(NULL);
}

int hdmi_cec_init(void)
{
	if(false == cec_init_flag){
		fd_cec = open("/dev/mxc_hdmi_cec",O_RDWR | O_NONBLOCK);
		if(fd_cec < 0) {
			printf("Unable to Open HDMI CEC device\n");
			return -1;
		}
		else
			cec_init_flag = true;
		pthread_mutex_init(&lockdevice, NULL);
		device_status = IDLE;
	}
	return 0;
}
int hdmi_cec_deinit(void)
{
	if(fd_cec > 0)
		close(fd_cec);
	fd_cec = -1;
	pthread_mutex_destroy(&lockdevice);
	device_status = IDLE;
	cec_init_flag = false;
	return 0;
}

int hdmi_cec_open(int Device_Type,hdmi_cec_callback callback)
{
	int ret = 0;
	if(false == cec_init_flag){
		printf("Don't initialize hdmi cec!\n");
		return -1;
	}
	pthread_mutex_lock(&lockdevice);
	if(true == cec_open_flag){
		printf("Hdmi cec device is already opened!\n");
		pthread_mutex_unlock(&lockdevice);
		return -1;
	}
	else
		cec_open_flag = true;
	pthread_mutex_unlock(&lockdevice);
	switch (Device_Type){
	case Playback_Device:
		logical_address = PLAYBACK_DEVICE1_ADDRESS;
		break;
	case Record_Device:
		logical_address = RECORD_DEVICE1_ADDRESS;
		break;
	case Tuner_Device:
		logical_address = TUNER_DEVICE1_ADDRESS;
		break;
	default:
		printf("Don't support TV device!\n");
		return -1;
	}
	device_type = Device_Type;

	ret = ioctl(fd_cec,HDMICEC_IOC_STARTDEVICE,NULL);
	if(ret < 0){
		printf("Don't start Hdmi cec device!\n");
		return -1;
	}
	ret = pthread_create(&poll_cec_pid, NULL, &poll_cec_thread, NULL);
	if(0 != ret)
		return -1;
	pthread_mutex_lock(&lockdevice);
	poll_fds[0].fd = fd_cec;
	poll_fds[0].events  = POLLIN;
	poll_fds[0].revents = 0;
	client_callback = callback;
	pthread_mutex_unlock(&lockdevice);
	return 0;
}
int hdmi_cec_close(int Device_Type)
{
	int ret = 0;
	Device_Type = Device_Type;
	if(false == cec_init_flag){
		printf("Don't initialize hdmi cec!\n");
		return -1;
	}
	pthread_mutex_lock(&lockdevice);
	if(false == cec_open_flag){
		pthread_mutex_unlock(&lockdevice);
		return 0;
	}
	cec_open_flag = false;
	ret = ioctl(fd_cec,HDMICEC_IOC_STOPDEVICE,NULL);
	device_status = IDLE;
	poll_fds[0].fd = -1;
	poll_fds[0].events  = POLLIN;
	poll_fds[0].revents = 0;
	logical_address = UNREGISTERED_DEVICE_ADDRESS;
	device_type = 0;
	pthread_mutex_unlock(&lockdevice);
	return ret;
}
int hdmi_cec_send_message(unsigned char dest_addr, unsigned char opcode, int operand_len,unsigned char *operand)
{
	int ret = 0,msg_len = 0;
	unsigned char msg[MAX_CEC_MESSAGE_LEN];
	if(false == cec_init_flag){
		printf("Don't initialize hdmi cec!\n");
		return -1;
	}
	pthread_mutex_lock(&lockdevice);
	if(false == cec_open_flag ||READY != device_status){
		printf("Hdmi cec is not ready!\n");
		pthread_mutex_unlock(&lockdevice);
		return -1;
	}
	memset(msg,0,MAX_CEC_MESSAGE_LEN);
	msg[0] = logical_address << 4 | (dest_addr & 0x0F);
	if(logical_address == dest_addr){/*<Polling> Message*/
		msg_len = 1;
	}else if(0x0 == opcode /*<Feature Abort> Message*/ ||  0 == operand_len){
		msg_len = 2;
		msg[1] = opcode;
	}else if(NULL != operand && 0 != operand_len && operand_len <= (MAX_CEC_MESSAGE_LEN - 2)){
		msg_len = 2 + operand_len;
		msg[1] = opcode;
		memcpy(&msg[2],operand,operand_len);
	}
	ret = write(fd_cec,msg,msg_len);
	if(ret < 0){
		printf("Don't send message by Hdmi cec device!\n");
		ret = -1;
	}
	pthread_mutex_unlock(&lockdevice);
	return ret;
}



