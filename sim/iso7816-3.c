/*
 * Copyright 2008-2009 Freescale Semiconductor, Inc. All Rights Reserved.
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
 * @file iso7816-3.c
 *
 * @brief Library for Freescale IMX SIM interface
 *
 * @ingroup SIM
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdint.h>
#include <linux/mxc_sim_interface.h>

#include "iso7816-3.h"

/* File descriptor */
static int sim_fd;

/* Card present
 * 0 = SIM_PRESENT_REMOVED
 * 1 = SIM_PRESENT_INSERTED
 * 2 = SIM_PRESENT_OPERATIONAL
 */
static int sim_present = SIM_PRESENT_REMOVED;

/* last error occured */
static int sim_errval = SIM_OK;

/* User definable card present state change callback function */
static int (*sim_cardstatecallbackfunction) ();

/* Function: sim_callback_handler
 *
 * Description: signal handler for card present state changes.
 * This function will track card present changes and call the
 * user defined callback function appropriatly.
 *
 * Parameters:
 * int sig      signal number (always SIGIO)
 */

static void sim_callback_handler(int sig)
{
	int errval;
	int present;

	errval = ioctl(sim_fd, SIM_IOCTL_GET_PRESENSE, &present);

	if (errval < 0)
		return;

	if ((present == SIM_PRESENT_REMOVED)
	    && (sim_present != SIM_PRESENT_REMOVED)) {
		sim_present = SIM_PRESENT_REMOVED;
		errval = ioctl(sim_fd, SIM_IOCTL_POWER_OFF, 0);
		if (errval < 0)
			return;
	};

	if ((present == SIM_PRESENT_DETECTED)
	    && (sim_present == SIM_PRESENT_REMOVED)) {
		sim_present = SIM_PRESENT_DETECTED;
		errval = ioctl(sim_fd, SIM_IOCTL_POWER_ON, 0);
		if (errval < 0)
			return;
	};

	if (present == SIM_PRESENT_OPERATIONAL)
		sim_present = SIM_PRESENT_OPERATIONAL;

	if (sim_cardstatecallbackfunction != 0)
		sim_cardstatecallbackfunction();

};

/* Function: RegisterCardStateCallbackFunc
 *
 * Description: Register a user defined callback function to track
 * state changes.
 *
 * Parameters:
 * int(*cardstatecallbackfunc)(void)    pointer to callback function
 *
 * Return Values:
 *  SIM_OK                 Success
 * -SIM_E_INVALIDCALLBACK  pointer to callback function is zero
 */

int RegisterCardStateCallbackFunc(int (*cardstatecallbackfunc) (void))
{
	int errval;

	if (cardstatecallbackfunc) {
		sim_cardstatecallbackfunction = cardstatecallbackfunc;
		errval = SIM_OK;
	} else {
		errval = -SIM_E_INVALIDCALLBACK;
	};

	sim_errval = errval;
	return errval;
};

/* Function:  SendReceiveAPDU
 *
 * Description: Transfer an APDU
 *
 * Parameters:
 * unsigned char * cmd      transmit buffer
 * int   cmdlen   transmit length
 * unsigned char * resp     receive buffer
 * int   resplen  expected receive length
 *
 * Return Value:
 * 0x00006xxx                ISO 7816-3 error codes
 * 0x00009xxx                Application specific codes
 * -SIM_E_NOCARD             No card inserted
 * -SIM_E_ACCESS             Memory violation error
 * -SIM_E_TPDUSHORT          TPDU less than 5 bytes
 * -SIM_E_INVALIDXMTLENGTH   Requested transmit is too long
 * -SIM_E_INVALIDRCVLENGTH   Requested receive is too long
 * -SIM_E_TIMEOUT            Transfer Timeout
 * -SIM_E_NACK               No ACK received
 */

int SendReceiveAPDU(unsigned char *cmd, int cmdlen, unsigned char *resp, int resplen)
{
	int errval;

	sim_xfer_t tpdu = { cmd, cmdlen, resp, resplen,
		SIM_XFER_TYPE_TPDU, 100
	};
	errval = ioctl(sim_fd, SIM_IOCTL_XFER, &tpdu);
	if (!errval)
		errval = (tpdu.sw1 << 8) | tpdu.sw2;
	else
		errval = errno;

	sim_errval = errval;
	return errval;
};

/* Function:  SendReceivePTS
 *
 * Description: Transfer a protocol type selecion string (PTS)
 *
 * Parameters:
 * unsigned chard unsigned char * pts_request   PTS transmit string
 * unsigned char unsigned char * pts_response  PTS reveive buffer
 * int ptslen          PTS length
 *
 * Return Values:
 *  SIM_OK                   Success
 * -SIM_E_NOCARD             No card inserted
 * -SIM_E_ACCESS             Memory violation error
 * -SIM_E_PTSEMPTY           PTS transmit string has zero length
 * -SIM_E_INVALIDXMTLENGTH   PTS transmit string is too long
 * -SIM_E_INVALIDRCVLENGTH   PTS receive buffer is too long
 * -SIM_E_TIMEOUT            Transfer Timeout
 */

int SendReceivePTS(unsigned char *pts_request, unsigned char *pts_response, int ptslen)
{
	int errval;

	sim_xfer_t pts = { pts_request, ptslen, pts_response, ptslen,
		SIM_XFER_TYPE_PTS, 100
	};
	errval = ioctl(sim_fd, SIM_IOCTL_XFER, &pts);
	if (errval)
		errval = errno;

	sim_errval = errval;
	return errval;
};

/* Function:  ReaderStart
 *
 * Description: Initialize the card reader interface
 *
 * Return Value:
 *  SIM_OK                    Success
 * -SIM_E_READERSTART         Error while initializing the card reader
 */

int ReaderStart(void)
{
	int errval;
	int oflags;

	signal(SIGIO, &sim_callback_handler);

	errval = sim_fd = open("/dev/mxc_sim", O_RDWR);
	if (errval >= 0)
		errval = ioctl(sim_fd, SIM_IOCTL_GET_PRESENSE, &sim_present);
	if (errval >= 0)
		errval = fcntl(sim_fd, F_SETOWN, getpid());
	if (errval >= 0)
		errval = oflags = fcntl(sim_fd, F_GETFL);
	if (errval >= 0)
		errval = fcntl(sim_fd, F_SETFL, oflags | FASYNC);
	if (errval < 0)
		errval = -SIM_E_READERSTART;

	sim_errval = errval;
	return errval;
}

/* Function:  ReaderStop
 *
 * Description: Shutdown the card reader
 */

void ReaderStop(void)
{
	if (sim_fd)
		close(sim_fd);
	sim_fd = 0;
	sim_present = SIM_PRESENT_REMOVED;
	sim_errval = SIM_OK;
	sim_cardstatecallbackfunction = 0;
};

/* Function:  GetCardState
 *
 * Description: Check if card is present
 *
 * Return values:
 * SIM_PRESENT_REMOVED         No card has been inserted
 * SIM_PRESENT_DETECTED        Card insertion has been detected
 * SIM_PRESENT_OPERATIONAL     ATR has been received and the card
 * 			       is fully operational
 */

int GetCardState(void)
{
	return sim_present;
};

/* Function:  GetAtr
 *
 * Description: Get ATR received. This will only work when
 * the card state is SIM_PRESENT_OPERATIONAL. The parameter
 * "size" tells the number of bytes the given ATR buffer can
 * be filled with. An ATR can have a maximum length of 32 bytes.
 *
 * Parameters:
 * unsigned char * buf      buffer to write the ATR into
 * int*  size     pointer to maximum number of bytes the supplied buf can hold

 * Return values:
 *  SIM_OK               Success - the ATR size is stored to *size
 * -SIM_E_ACCESS         Error while copying the ATR to user space
 * -SIM_E_BUFFERTOOSMALL The received ATR is bigger then the supplied buffer
 * -SIM_E_NOCARD         No card has yet been inserted
 * -SIM_E_INVALPARAM     Invalid parameters (either "size" or "buf" is zero)
 */

int GetAtr(unsigned char *buf, int *size)
{
	int errval = SIM_OK;
	sim_atr_t atr;

	if ((buf != 0) && (size != 0)) {
		if (sim_present == SIM_PRESENT_OPERATIONAL) {
			errval = ioctl(sim_fd, SIM_IOCTL_GET_ATR, &atr);
			if (errval >= 0) {
				if (atr.size <= *size) {
					*size = atr.size;
					memcpy(buf, atr.t, *size);
				} else {
					errval = -SIM_E_BUFFERTOOSMALL;
				};
			} else {
				errval = errno;
			};
		} else {
			errval = -SIM_E_NOCARD;
		};
	} else {
		errval = -SIM_E_INVALPARAM;
	};

	sim_errval = errval;
	return errval;
};

/* Function:  GetParamAtr
 *
 * Description: Get communication parameters determined from the ATR received.
 * The parameters are only valid if the card is operational.
 *
 * Parameters:
 * int* fi    storage for frequency multiplyer index
 * int* di    storage for frequency devider index
 * int* t     storage for protocol type
 * int* n     storage for extra guard time
 *
 * Return Values:
 *  SIM_OK           Success
 * -SIM_E_NOCARD     No card present
 * -SIM_E_ACCESS     Error while copying the ATR parameters to user space
 */

int GetParamAtr(int *fi, int *di, int *t, int *n)
{
	int errval;
	sim_param_t param;

	errval = ioctl(sim_fd, SIM_IOCTL_GET_PARAM_ATR, &param);
	if (errval >= 0) {
		if (fi)
			*fi = param.FI;
		if (di)
			*di = param.DI;
		if (t)
			*t = param.T;
		if (n)
			*n = param.N;
	} else
		errval = errno;

	sim_errval = errval;
	return errval;
};

/* Function:  GetParam
 *
 * Description: Get the current communication parameters.
 *
 * Parameters:
 * int* fi    storage for frequency multiplyer index
 * int* di    storage for frequency devider index
 * int* t     storage for protocol type
 * int* n     storage for wait time
 *
 * Return Value:
 *  SIM_OK           Success
 * -SIM_E_ACCESS     Error while copying the parameters to user space
 */

int GetParam(int *fi, int *di, int *t, int *n)
{
	int errval;
	sim_param_t param;

	errval = ioctl(sim_fd, SIM_IOCTL_GET_PARAM, &param);
	if (errval >= 0) {
		if (fi)
			*fi = param.FI;
		if (di)
			*di = param.DI;
		if (t)
			*t = param.T;
		if (n)
			*n = param.N;
	} else
		errval = errno;

	sim_errval = errval;
	return errval;
};

/* Function:  SetParam
 *
 * Description: Set communication parameters. Parameters
 * should only be applied if a valid ATR has been received
 * and a PTS sequence took place.
 *
 * Parameters:
 * int fi    frequency multiplyer index
 * int di    frequency devider index
 * int t     protocol type
 * int n     wait time
 *
 * Return Values:
 *  SIM_OK   Success
 * -SIM_E_ACCESS                   Error while copying communication
 *  				   parameters from user space
 * -SIM_E_PARAM_DIVISOR_RANGE      Calculated divisor bigger than 255
 * -SIM_E_PARAM_FBYD_NOTDIVBY8OR12 F/D not divisable by 12 (as required)
 * -SIM_E_PARAM_FBYD_WITHFRACTION  F/D has a remainder
 * -SIM_E_PARAM_DI_INVALID         Frequency multiplyer index not supported
 * -SIM_E_PARAM_FI_INVALID         Frequency divider index not supported
 */

int SetParam(int fi, int di, int t, int n)
{
	int errval;
	sim_param_t param;

	errval = ioctl(sim_fd, SIM_IOCTL_GET_PARAM, &param);
	if (errval >= 0) {
		param.FI = fi;
		param.DI = di;
		param.T = t;
		param.N = n;
		errval = ioctl(sim_fd, SIM_IOCTL_SET_PARAM, &param);
	} else
		errval = errno;

	sim_errval = errval;
	return errval;
};

/* Function:  ColdReset
 *
 * Description: Run the cold reset sequence for the interface;
 * disable CLK, RST low and VCC off, reset all internal states, wait,
 * then VCC on, RST high. This procedure will cause an ATR.
 *
 * Return Values:
 *  SIM_OK             Success
 * -SIM_E_POWERED_OFF  Interface not powered
 */

int ColdReset(void)
{
	sim_present = SIM_PRESENT_REMOVED;
	return ioctl(sim_fd, SIM_IOCTL_COLD_RESET, 0);
};

/* Function:  WarmReset
 *
 * Description: Run the warm reset sequence for the interface:
 * RST low, reset all internal states, wait, then RST high.
 * This procedure should cause an ATR.
 *
 * Return Values:
 *  SIM_OK             Success
 * -SIM_E_POWERED_OFF  Interface not powered
 */

int WarmReset(void)
{
	sim_present = SIM_PRESENT_REMOVED;
	return ioctl(sim_fd, SIM_IOCTL_WARM_RESET, 0);
};

/* Function:  GetError
 *
 * Description: get code for last error occured
 *
 * Return Value:
 * code for last error happend
 */

int GetError(void)
{
	return sim_errval;
};

/* Function:  LockCard
 *
 * Description: physically lock the card.
 *
 * Return Values:
 *  SIM_OK          Success
 * -SIM_E_NOCARD    No card inserted, yet
 */

int LockCard(void)
{
	int errval = ioctl(sim_fd, SIM_IOCTL_CARD_LOCK, 0);
	if (errval < 0)
		errval = errno;

	sim_errval = errval;
	return errval;
};

/* Function:  EjectCard
 *
 * Description: physically unlock and eject the card.
 *
 * Return Values:
 *  SIM_OK          Success
 * -SIM_E_NOCARD    No card inserted, yet
 */

int EjectCard(void)
{
	int errval = ioctl(sim_fd, SIM_IOCTL_CARD_EJECT, 0);
	if (errval < 0)
		errval = errno;

	sim_errval = errval;
	return errval;
};
