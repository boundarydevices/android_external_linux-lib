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
 * @file lib/rng/fsl_shw_user.c
 *
 * This file implements User Context, Get Results, and Platform Capabilities
 * functions of the FSL SHW API in USER MODE for talking to a SHW device
 * driver.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

#ifdef FSL_DEBUG
#include <stdio.h>
#include <errno.h>
#include <string.h>
#endif

#include "shw_driver.h"

/*!
 * Chain of active user contexts for this process.
 */
static fsl_shw_uco_t *user_chain = NULL;

/*!
 * User-space copy of capabilities, as read from kernel driver (and modified
 * with local API version?).
 */
struct cap {
	/*! Whether data has been read from kernel space  */
	unsigned populated;
	union {
		uint32_t buffer[256];
		fsl_shw_pco_t pco;
	};
};

static struct cap cap = {
	0 /* populated */ ,
	{}
};

static int setup_callback(fsl_shw_uco_t * uco);
static void sah_sighandler(int num);

 /*!
  * Sanity checks the user context object fields to ensure that they make some
  * sense before passing the uco as a parameter.
  *
  * @brief Verify the user context object
  *
  * @param  uco  user context object
  *
  * @return    A return code of type #fsl_shw_return_t.
  */
fsl_shw_return_t validate_uco(fsl_shw_uco_t * uco)
{
	fsl_shw_return_t status = FSL_RETURN_OK_S;

	/* check if file is opened */
	if (uco->openfd < 0) {
#ifdef FSL_DEBUG
		fprintf(stderr, "SHW: No open file descriptor."
			"  Is context registered?\n");
#endif
		status = FSL_RETURN_NO_RESOURCE_S;
	} else {
		/* check flag combination: the only invalid setting of the
		 * blocking and callback flags is blocking with callback. So check
		 * for that
		 */
		if ((uco->
		     flags & (FSL_UCO_BLOCKING_MODE | FSL_UCO_CALLBACK_MODE)) ==
		    (FSL_UCO_BLOCKING_MODE | FSL_UCO_CALLBACK_MODE)) {
#ifdef FSL_DEBUG
			fprintf(stderr,
				"SHW: invalid flags in user context: 0x%x\n",
				uco->flags);
#endif
			status = FSL_RETURN_BAD_FLAG_S;
		} else {
			/* must have pool of at least 1, even for blocking mode */
			if (uco->pool_size == 0) {
				status = FSL_RETURN_ERROR_S;
			} else {
				/* if callback flag is set, it better have a callback
				 * routine */
				if (uco->flags & FSL_UCO_CALLBACK_MODE) {
					if (!
					    (uco->
					     flags &
					     FSL_UCO_CALLBACK_SETUP_COMPLETE)) {
						if (setup_callback(uco)) {
							status =
							    FSL_RETURN_OK_S;
						}
					}

					if (uco->callback == NULL) {
#ifdef FSL_DEBUG
						fprintf(stderr,
							"SHW: Callback flag set in user"
							" context, but callback function is NULL\n");
#endif
						status =
						    FSL_RETURN_INTERNAL_ERROR_S;
					}
				}
			}
		}
	}

	return status;
}

/*!
 * Link a newly-registered context to the beginning of the #user_chain.
 *
 * @param uco    User context to add
 */
inline static void add_user(fsl_shw_uco_t * uco)
{
	uco->next = user_chain;
	user_chain = uco;

	return;
}

/*!
 * Unlink a deregistered context from the #user_chain
 *
 * @param uco    User context to remove
 */
inline static void remove_user(fsl_shw_uco_t * uco)
{
	fsl_shw_uco_t *prev = NULL;
	fsl_shw_uco_t *current = user_chain;

	/* Search chain looking for the entry */
	while ((current != uco) && (current != NULL)) {
		current = current->next;
		prev = current;
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
 * Create an association between the the user and the provider of the API.
 *
 * @param  user_ctx   The user context which will be used for this association.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t fsl_shw_register_user(fsl_shw_uco_t * user_ctx)
{
	int code;
	fsl_shw_return_t ret = FSL_RETURN_ERROR_S;

	code = open("/dev/fsl_shw", O_RDWR);

	if (code < 0) {
#ifdef FSL_DEBUG
		fprintf(stderr, "SHW: open() failed with (%d) %s\n", errno,
			strerror(errno));
#endif
	} else {
		user_ctx->openfd = code;	/* 'good' code is a file descriptor */
		code =
		    ioctl(code, SHW_IOCTL_REQUEST + SHW_USER_REQ_REGISTER_USER,
			  user_ctx);
		if (code == 0) {
			add_user(user_ctx);
			ret = FSL_RETURN_OK_S;
		} else {
			close(user_ctx->openfd);
			user_ctx->openfd = -1;
#ifdef FSL_DEBUG
			fprintf(stderr,
				"SHW: Failed user registration ioctl\n");
#endif
		}
	}

	return ret;
}

/*!
 * Destroy the association between the the user and the provider of the API.
 *
 * @param  user_ctx   The user context which is no longer needed.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t fsl_shw_deregister_user(fsl_shw_uco_t * user_ctx)
{
	fsl_shw_return_t ret = FSL_RETURN_ERROR_S;

	ret = validate_uco(user_ctx);
	if (ret == FSL_RETURN_OK_S) {
		int code = close(user_ctx->openfd);

		if (code < 0) {
			ret = FSL_RETURN_INTERNAL_ERROR_S;
		}
		user_ctx->openfd = -1;
		remove_user(user_ctx);
	}

	return ret;
}

/* REQ-S2LRD-PINTFC-API-GEN-006 */

/*!
 * Retrieve results from earlier operations.
 *
 * @param         user_ctx     The user's context.
 * @param         result_size  The number of array elements of @a results.
 * @param[in,out] results      Pointer to first of the (array of) locations to
 *                             store results.
 * @param[out]    result_count Pointer to store the number of results which
 *                             were returned.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t fsl_shw_get_results(fsl_shw_uco_t * user_ctx,
				     unsigned result_size,
				     fsl_shw_result_t results[],
				     unsigned *result_count)
{
	fsl_shw_return_t status = FSL_RETURN_INTERNAL_ERROR_S;

	/* perform a sanity check on the uco */
	status = validate_uco(user_ctx);

	/* if uco appears ok, build structure and pass to get results */
	if (status == FSL_RETURN_OK_S) {
		struct results_req req;

		/* if requested is zero, it's done before it started */
		if (result_size > 0) {
			int code;

			init_req(&req.hdr, user_ctx);
			req.requested = result_size;
			req.results = results;
			/* get the results */
			code = ioctl(user_ctx->openfd,
				     SHW_IOCTL_REQUEST +
				     SHW_USER_REQ_GET_RESULTS, &req);

			if (code == 0) {
				*result_count = req.actual;
				status = FSL_RETURN_OK_S;
			}
		} else {
			*result_count = 0;	/* no place to store results */
		}
	}

	return status;
}

/* REQ-S2LRD-PINTFC-API-GEN-003 */
/*!
 * Determine the hardware security capabilities of this platform.
 *
 * Though a user context object is passed into this function, it will always
 * act in a non-blocking manner.
 *
 * @param  user_ctx   The user context which will be used for the query.
 *
 * @return  A pointer to the capabilities object.
 */
fsl_shw_pco_t *fsl_shw_get_capabilities(fsl_shw_uco_t * user_ctx)
{

	fsl_shw_return_t status = validate_uco(user_ctx);
	fsl_shw_pco_t *retval = NULL;

	if (status == FSL_RETURN_OK_S) {
		if (cap.populated) {
			retval = &cap.pco;
		} else {
			register int code;
			struct capabilities_req req;

			init_req(&req.hdr, user_ctx);
			req.size = sizeof(cap.buffer);
			req.capabilities = &cap.pco;
			code = ioctl(user_ctx->openfd,
				     SHW_IOCTL_REQUEST +
				     SHW_USER_REQ_GET_CAPABILITIES, &req);

			if ((code == 0) && (req.hdr.code == FSL_RETURN_OK_S)) {
				retval = &cap.pco;
				cap.populated = 1;
			}
		}
	};

	return retval;
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
	/*!
	 * Flag for whether callback handling has been set up for this process.
	 */
	static int callback_initialized = 0;
	int code = 0;		/* assume failure */

	if (!callback_initialized) {
		/* This is defined by POSIX */
		struct sigaction action;

		action.sa_handler = sah_sighandler;
		action.sa_flags = 0;	/* no special flags needed. */
		sigfillset(&action.sa_mask);	/* suspend all signals during handler */
		if (sigaction(SIGUSR2, &action, NULL) != 0) {
#ifdef FSL_DEBUG
			fprintf(stderr,
				"FSL API: sigaction() failed with error (%d) %s\n",
				errno, strerror(errno));
#endif
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
 * Called when SIGUSR2 fires.  This will call the user's callback function
 * if the user still has one registered.
 *
 * @param num    Signal number (ignored)
 */
static void sah_sighandler(int num)
{
	fsl_shw_uco_t *current_user = user_chain;

#ifdef FSL_DEBUG
	fprintf(stderr, "SHW: Signal received\n");
#endif

	/* Something happened.  Callback anybody who has callback on.  */
	while (current_user != NULL) {
		fsl_shw_uco_t *next_user = current_user->next;

		if ((current_user->flags & FSL_UCO_CALLBACK_MODE)
		    && (current_user->callback != NULL)) {
#ifdef FSL_DEBUG
			fprintf(stderr, "SHW: calling back user %p\n",
				current_user);
#endif
			current_user->callback(current_user);
		}
		current_user = next_user;
	}

	(void)num;		/* unused */
	return;
}
