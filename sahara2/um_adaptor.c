/*
 * User Space library to access the Security hardware
 * Copyright (C) 2005-2006 written by Freescale Semiconductor
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

/*!
* @file lib/sahara2/um_adaptor.c
*
* @brief The Adaptor component provides a user-mode interface to the device
* driver.
*/

#include <sf_util.h>

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>

#include <sahara.h>
#include <sah_kernel.h>
#include <sahara.h>
#include <adaptor.h>

#include <memory.h>
#include <fcntl.h>

#ifdef DIAG_ADAPTOR
#include <diagnostic.h>
#endif				/* DIAG_ADAPTOR */

/* Most of the Linux IO functions return -1 on error */
#define IO_ERROR    -1

#ifdef DIAG_ADAPTOR
void um_Dump_Chain(const sah_Desc * chain);

void um_Dump_Region(const char *prefix, const unsigned char *data,
		    unsigned length);

static void um_Dump_Link(const char *prefix, const sah_Link * link);

void um_Dump_Words(const char *prefix, const unsigned *data, unsigned length);

#undef LOG_DIAG

#define LOG_DIAG(x) printf("%s\n", x)

#ifndef MAX_DUMP
#define MAX_DUMP 16
#endif

/* This static error message buffer is likely not thread-safe */
static char Diag_msg[200];
#endif

/*!
 * Chain of active user contexts for this process.
 */
static fsl_shw_uco_t *user_chain = NULL;

/*!
 * Flag for whether callback handling has been set up for this process.
 */
static int callback_initialized = 0;

/**** memory routines ****/

static void *my_malloc(void *ref, size_t n)
{
	void *mem;

#ifndef DIAG_MEM_ERRORS
	mem = malloc(n);
#else
	if ((rand() % DIAG_MEM_CONST) == 0) {
		mem = 0;
	} else {
		mem = malloc(n);
	}
#endif

	(void)ref;		/* unused param warning */
	return mem;
}

static sah_Head_Desc *my_alloc_head_desc(void *ref)
{
	sah_Head_Desc *mem;

#ifndef DIAG_MEM_ERRORS
	mem = malloc(sizeof(sah_Head_Desc));
#else
	if ((rand() % DIAG_MEM_CONST) == 0) {
		mem = 0;
	} else {
		mem = malloc(sizeof(sah_Head_Desc));
	}
#endif

	(void)ref;		/* unused param warning */
	return mem;
}

static sah_Desc *my_alloc_desc(void *ref)
{
	sah_Desc *mem;

#ifndef DIAG_MEM_ERRORS
	mem = malloc(sizeof(sah_Desc));
#else
	if ((rand() % DIAG_MEM_CONST) == 0) {
		mem = 0;
	} else {
		mem = malloc(sizeof(sah_Desc));
	}
#endif

	(void)ref;		/* unused param warning */
	return mem;
}

static sah_Link *my_alloc_link(void *ref)
{
	sah_Link *mem;

#ifndef DIAG_MEM_ERRORS
	mem = malloc(sizeof(sah_Link));
#else
	if ((rand() % DIAG_MEM_CONST) == 0) {
		mem = 0;
	} else {
		mem = malloc(sizeof(sah_Link));
	}
#endif

	(void)ref;		/* unused param warning */
	return mem;
}

static void my_free(void *ref, void *ptr)
{
	free(ptr);
	(void)ref;		/* unused param warning */
	return;
}

static void *my_memcpy(void *ref, void *dest, const void *src, size_t n)
{
	(void)ref;		/* unused param warning */
	return memcpy(dest, src, n);
}

static void *my_memset(void *ref, void *ptr, int ch, size_t n)
{
	(void)ref;		/* unused param warning */
	return memset(ptr, ch, n);
}

/*! Standard memory manipulation routines for user-mode API. */
static sah_Mem_Util std_usermode_mem_util = {
	.mu_ref = 0,
	.mu_malloc = my_malloc,
	.mu_alloc_head_desc = my_alloc_head_desc,
	.mu_alloc_desc = my_alloc_desc,
	.mu_alloc_link = my_alloc_link,
	.mu_free = my_free,
	.mu_free_head_desc = (void (*)(void *, sah_Head_Desc *))my_free,
	.mu_free_desc = (void (*)(void *, sah_Desc *))my_free,
	.mu_free_link = (void (*)(void *, sah_Link *))my_free,
	.mu_memcpy = my_memcpy,
	.mu_memset = my_memset
};

static fsl_shw_return_t add_user(fsl_shw_uco_t * uco);
static void remove_user(fsl_shw_uco_t * uco);
static int setup_callback(fsl_shw_uco_t * uco);
static void sah_sighandler(int num);
static fsl_shw_return_t sah_service_request(unsigned int command,
					    void *arg, fsl_shw_uco_t * uco);

/*!
 * @brief    Sends a request to register this user
 *
 * @param[in,out] uco User context.  Part of the structre contains input
 *                                   parameters and part is filled in by the
 *                                   driver.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t sah_register(fsl_shw_uco_t * uco)
{
	fsl_shw_return_t status = FSL_RETURN_ERROR_S;
	unsigned dev_opened = 0;	/* boolean */
	unsigned user_added = 0;	/* boolean */

	/* Link user into process-local chain of contexts */
	status = add_user(uco);
	if (status != FSL_RETURN_OK_S) {
		goto out;
	}
	user_added = 1;

	if (uco->sahara_openfd >= 0) {
		status = FSL_RETURN_ERROR_S;
		goto out;
	}

	/* This code needs to open the device RIGHT HERE */
	uco->sahara_openfd = open(SAHARA_DEVICE, O_WRONLY);
	if (uco->sahara_openfd < 0) {
		status = FSL_RETURN_ERROR_S;
		goto out;
	}
	dev_opened = 1;
	uco->mem_util = &std_usermode_mem_util;

	/* check that uco is valid */
	status = sah_validate_uco(uco);
	if (status != FSL_RETURN_OK_S) {
		goto out;
	}

	/*  Life is good, register this user */
	status = sah_service_request(SAHARA_REGISTER, (void *)uco, uco);

      out:
	if (status != FSL_RETURN_OK_S) {
		if (user_added) {
			remove_user(uco);
		}
		if (dev_opened) {
			close(uco->sahara_openfd);
			uco->sahara_openfd = -1;
		}
	}

	return status;
}

/*!
 * @brief    Sends a request to deregister this user
 *
 * @param[in,out] uco User context.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t sah_deregister(fsl_shw_uco_t * uco)
{
	fsl_shw_return_t status = FSL_RETURN_ERROR_S;

	/* Turn off flags to make sure anything outstanding does not make waves. */
	uco->flags &=
	    ~(FSL_UCO_CALLBACK_SETUP_COMPLETE | FSL_UCO_CALLBACK_MODE);

	remove_user(uco);

	/* check that a valid file descriptor could exist */
	if (uco->sahara_openfd >= 0) {
		status =
		    sah_service_request(SAHARA_DEREGISTER, (void *)uco, uco);
	}

	if (status == FSL_RETURN_OK_S) {
		/* close down the ioctl access */
		close(uco->sahara_openfd);
		uco->sahara_openfd = -1;
	}

	return status;
}

/*!
 * @brief    Sends a request to get results from the result pool
 *
 * @param[in,out] arg    Location containing info for retrieving results
 * @param         uco    User context.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t sah_get_results(sah_results * arg, fsl_shw_uco_t * uco)
{
	fsl_shw_return_t code = sah_service_request(SAHARA_GET_RESULTS,
						    (void *)arg, uco);

	if ((code == FSL_RETURN_OK_S) && (arg->actual != 0)) {
		sah_Postprocess_Results(uco, arg);
	}

	return code;
}

/*!
 * This function writes the Descriptor Chain to the kernel driver.
 *
 * @brief     Writes the Descriptor Chain to the kernel driver.
 *
 * @param    dar  A pointer to a Descriptor Chain of type sah_Desc
 * @param         uco     User context.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t adaptor_Exec_Descriptor_Chain(sah_Head_Desc * dar,
					       fsl_shw_uco_t * uco)
{
	fsl_shw_return_t ret = FSL_RETURN_OK_S;
	uint32_t blocking = (uco->flags & FSL_UCO_BLOCKING_MODE);

	if ((uco->flags & FSL_UCO_CALLBACK_MODE)
	    && !(uco->flags & FSL_UCO_CALLBACK_SETUP_COMPLETE)) {
		if (setup_callback(uco) == 0) {
#ifdef DIAG_ADAPTOR
			LOG_DIAG("callback setup failed");
#endif
			ret = FSL_RETURN_ERROR_S;
		}
	}
#ifdef DIAG_ADAPTOR
	um_Dump_Chain(&dar->desc);
#endif

	if (ret == FSL_RETURN_OK_S) {
		ret = sah_service_request(SAHARA_DAR, (void *)dar, uco);
	}

	if (blocking && (ret == FSL_RETURN_OK_S)) {
		/* chain actually executed, or at least queue */
		ret = dar->result;
	};

	return ret;
}

/*!
 * Service request pass from UM to KM in this function via an ioctl
 * call.
 *
 * @brief    UM to KM command passing
 *
 * @param    command       the command to pass via the ioctl call
 * @param    arg           pointer to pass to kernel space
 * @param    uco           User context.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t sah_service_request(unsigned int command,
				     void *arg, fsl_shw_uco_t * uco)
{
	int linux_return_value;
	fsl_shw_return_t status;

	/* Need to retry the ioctl() in case it was interupted. This
	 * interruption would be due to another thread performing a reset of
	 * the SAHARA HW. Upon interruption, the descriptor chain must be
	 * re-written since the chain still needs to be executed.
	 */
	do {
		linux_return_value = ioctl(uco->sahara_openfd,
					   command, (unsigned long)arg);
	} while ((linux_return_value == IO_ERROR) && (errno == EINTR));

	if (linux_return_value == 0) {
		status = FSL_RETURN_OK_S;
	} else {
#ifdef DIAG_ADAPTOR
		sprintf(Diag_msg, "errno from ioctl() is %d", errno);
		LOG_DIAG(Diag_msg);
#endif
		status = FSL_RETURN_ERROR_S;
	}

#ifdef DIAG_ADAPTOR
	if (status != FSL_RETURN_OK_S) {
		LOG_DIAG("failed to perform service ioctl operation");
	}
#endif				/* DIAG_ADAPTOR */

	return status;
}

/*!
 * Link a newly-registered context to the #user_chain.
 *
 * @param uco    User context to add
 *
 * @return FSL_RETURN_OK_S on success; other error code
 */
static fsl_shw_return_t add_user(fsl_shw_uco_t * uco)
{
	fsl_shw_uco_t *current = user_chain;
	fsl_shw_uco_t *prev = NULL;
	fsl_shw_return_t code = FSL_RETURN_ERROR_S;

	/*
	 * Trundle down the chain searching to see whether the 'new' context is
	 * already on the list.
	 */
	while ((current != uco) && (current != NULL)) {
		prev = current;
		current = current->next;
	}

	if (current != uco) {
		uco->next = user_chain;
		user_chain = uco;
		code = FSL_RETURN_OK_S;
	}

	return code;
}

/*!
 * Unlink a deregistered context from the #user_chain
 *
 * @param uco    User context to remove
 */
static void remove_user(fsl_shw_uco_t * uco)
{
	fsl_shw_uco_t *prev = NULL;
	fsl_shw_uco_t *current = user_chain;

	/* Search chain looking for the entry */
	while ((current != uco) && (current != NULL)) {
		prev = current;
		current = current->next;
	}

	/* Did we find it */
	if (current != NULL) {
		if (prev == NULL) {
			/* It is first entry.  Point head to next in chain */
			user_chain = current->next;
		} else {
			/* Remove it from chain by pointing previous to next */
			prev->next = current->next;
		}
		current->next = NULL;	/* just for safety */
	}

	return;
}

/*!
 * Set up API's internal callback handler on SIGUSR2
 *
 * @param uco   User context
 *
 * @return 0 for failure, 1 for success
 */
static int setup_callback(fsl_shw_uco_t * uco)
{
	int code = 0;

	if (!callback_initialized) {
		/* This is defined by POSIX */
		struct sigaction action;

		action.sa_handler = sah_sighandler;
		action.sa_flags = 0;	/* no special flags needed. */
		sigfillset(&action.sa_mask);	/* suspend all signals during handler */
		if ((code = sigaction(SIGUSR2, &action, NULL)) != 0) {
			fprintf(stderr, "sigaction() failed with code %d\n",
				code);
		} else {
			uco->flags |= FSL_UCO_CALLBACK_SETUP_COMPLETE;
			callback_initialized = 1;
			code = 1;
		}
	} else {
		code = 1;
	}

	return code;
}

/*!
 * User-mode signal handler.
 *
 * Called when SIGUSR1 fires.  This will call the user's callback function
 * if the user still has one registered.
 *
 * @param num    Signal number (ignored)
 */
static void sah_sighandler(int num)
{
	fsl_shw_uco_t *current_user = user_chain;

	/* Something happened.  Callback anybody who has callback on.  */
	while (current_user != NULL) {
		fsl_shw_uco_t *next_user = current_user->next;

		if ((current_user->flags & FSL_UCO_CALLBACK_MODE)
		    && (current_user->callback != NULL)) {
			current_user->callback(current_user);
		}
		current_user = next_user;
	}

	(void)num;		/* unused */
	return;
}

/*!
 * Allocate a slot on the SCC
 *
 * @param   user_ctx
 * @param   key_len
 * @param   ownerid
 * @param   slot
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t do_scc_slot_alloc(fsl_shw_uco_t * user_ctx,
				   uint32_t key_len,
				   uint64_t ownerid, uint32_t * slot)
{
	fsl_shw_return_t ret;
	scc_slot_t slot_info;

	slot_info.key_length = key_len;
	slot_info.ownerid = ownerid;

	slot_info.slot = 400;
	slot_info.code = 500;
	ret = sah_service_request(SAHARA_SCC_ALLOC, &slot_info, user_ctx);

	if (ret == FSL_RETURN_OK_S) {
		*slot = slot_info.slot;
		ret = slot_info.code;
	}

	return ret;
}

/*!
 * Deallocate a slot on the SCC
 *
 * @param   user_ctx
 * @param   ownerid
 * @param   slot
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t do_scc_slot_dealloc(fsl_shw_uco_t * user_ctx, uint64_t ownerid,
				     uint32_t slot)
{
	scc_slot_t slot_info;
	fsl_shw_return_t ret;

	slot_info.ownerid = ownerid;
	slot_info.slot = slot;

	ret = sah_service_request(SAHARA_SCC_DEALLOC, &slot_info, user_ctx);
	if (ret == FSL_RETURN_OK_S) {
		ret = slot_info.code;
	}

	return ret;
}

/*!
 * Populate a slot on the SCC
 *
 * @param   user_ctx
 * @param   ownerid
 * @param   slot
 * @param   key
 * @param   key_size
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t do_scc_slot_load_slot(fsl_shw_uco_t * user_ctx,
				       uint64_t ownerid, uint32_t slot,
				       const uint8_t * key, uint32_t key_size)
{
	scc_slot_t slot_info;
	fsl_shw_return_t ret;

	slot_info.ownerid = ownerid;
	slot_info.slot = slot;
	slot_info.key_length = key_size;
	slot_info.key = (void *)key;

	ret = sah_service_request(SAHARA_SCC_LOAD, &slot_info, user_ctx);
	if (ret == FSL_RETURN_OK_S) {
#ifdef DIAG_ADAPTOR
		LOG_DIAG("SAHARA_SCC_LOAD reported error");
#endif
		ret = slot_info.code;
	}

	return ret;
}

/*!
 * Encrypt a slot on the SCC
 *
 * @param   user_ctx
 * @param   ownerid
 * @param   slot
 * @param   key_length
 * @param   black_data
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t do_scc_slot_encrypt(fsl_shw_uco_t * user_ctx, uint64_t ownerid,
				     uint32_t slot, uint32_t key_length,
				     uint8_t * black_data)
{
	scc_slot_t slot_info;
	fsl_shw_return_t ret;

	slot_info.ownerid = ownerid;
	slot_info.slot = slot;
	slot_info.key = black_data;
	slot_info.key_length = key_length;

	ret = sah_service_request(SAHARA_SCC_SLOT_ENC, &slot_info, user_ctx);
	if (ret == FSL_RETURN_OK_S) {
		ret = slot_info.code;
	}

	return ret;
}

/*!
 * Decrypt a slot on the SCC
 *
 * @param   user_ctx
 * @param   ownerid
 * @param   slot
 * @param   key_length
 * @param   black_data
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t do_scc_slot_decrypt(fsl_shw_uco_t * user_ctx, uint64_t ownerid,
				     uint32_t slot, uint32_t key_length,
				     const uint8_t * black_data)
{
	scc_slot_t slot_info;
	fsl_shw_return_t ret;

	slot_info.ownerid = ownerid;
	slot_info.slot = slot;
	slot_info.key = (uint8_t *) black_data;
	slot_info.key_length = key_length;

	ret = sah_service_request(SAHARA_SCC_SLOT_DEC, &slot_info, user_ctx);
	if (ret == FSL_RETURN_OK_S) {
		ret = slot_info.code;
	}

	return ret;
}

#ifdef DIAG_ADAPTOR
/*!
 * Dump chain of descriptors to the log.
 *
 * @brief Dump descriptor chain
 *
 * @param    chain     Kernel virtual address of start of chain of descriptors
 *
 * @return   void
 */
void um_Dump_Chain(const sah_Desc * chain)
{
	while (chain != NULL) {
		um_Dump_Words("Desc", (unsigned *)chain,
			      6 /*sizeof(*chain)/sizeof(unsigned) */ );
		/* place this definition elsewhere */
		if (chain->ptr1) {
			if (chain->header & SAH_HDR_LLO) {
				um_Dump_Region(" Data1", chain->ptr1,
					       chain->len1);
			} else {
				um_Dump_Link(" Link1", chain->ptr1);
			}
		}
		if (chain->ptr2) {
			if (chain->header & SAH_HDR_LLO) {
				um_Dump_Region(" Data2", chain->ptr2,
					       chain->len2);
			} else {
				um_Dump_Link(" Link2", chain->ptr2);
			}
		}

		chain = (chain->next ? chain->next : 0);
	}
}

/*!
 * Dump chain of links to the log.
 *
 * @brief Dump chain of links
 *
 * @param    prefix    Text to put in front of dumped data
 * @param    link      Kernel virtual address of start of chain of links
 *
 * @return   void
 */
static void um_Dump_Link(const char *prefix, const sah_Link * link)
{
	while (link != NULL) {
		um_Dump_Words(prefix, (unsigned *)link,
			      3 /* # words in h/w link */ );
		if (link->flags & SAH_STORED_KEY_INFO) {
			sprintf(Diag_msg, "  SCC: Slot %d", link->slot);
			LOG_DIAG(Diag_msg);
		} else if (link->data != NULL) {
			um_Dump_Region("  Data", link->data, link->len);
		}

		link = (link->next ? link->next : 0);
	}
}

/*!
 * Dump given region of data to the log.
 *
 * @brief Dump data
 *
 * @param    prefix    Text to put in front of dumped data
 * @param    data      Kernel virtual address of start of region to dump
 * @param    length    Amount of data to dump
 *
 * @return   void
 */
void um_Dump_Region(const char *prefix, const unsigned char *data,
		    unsigned length)
{
	unsigned count;
	char *output = Diag_msg;
	unsigned data_len;

	/* Build up the output string with multiple calls to sprintf() */
	output += sprintf(Diag_msg, "%s (%08X,%u):", prefix, (uint32_t) data,
			  length);

	/* Restrict amount of data to dump */
	if (length > MAX_DUMP) {
		data_len = MAX_DUMP;
	} else {
		data_len = length;
	}

	for (count = 0; count < data_len; count++) {
		if (count % 4 == 0) {
			*output++ = ' ';
		}
		output += sprintf(output, "%02X", *data++);
	}

	LOG_DIAG(Diag_msg);
}

/*!
 * Dump given words of data to the log.
 *
 * @brief Dump data
 *
 * @param    prefix      Text to put in front of dumped data
 * @param    data        Kernel virtual address of start of region to dump
 * @param    word_count  Amount of data to dump
 *
 * @return   void
 */
void um_Dump_Words(const char *prefix, const unsigned *data,
		   unsigned word_count)
{
	char *output = Diag_msg;

	/* Build up the output string with multiple calls to sprintf() */
	output +=
	    sprintf(output, "%s (%08X,%uw): ", prefix, (uint32_t) data,
		    word_count);

	while (word_count--) {
		output += sprintf(output, "%08X ", *data++);
	}

	LOG_DIAG(Diag_msg);
}
#endif				/* DIAG_ADAPTOR */
