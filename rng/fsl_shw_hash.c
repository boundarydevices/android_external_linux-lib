/*
 * User Space library to access the Security hardware
 * Copyright (C) 2005-2008 written by Freescale Semiconductor
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


/**
 * @file fsl_shw_hash.c
 *
 * This file implements Cryptographic Hashing functions of the FSL SHW API
 * for Sahara.  This does not include HMAC.
 */

#include "shw_driver.h"


/* REQ-S2LRD-PINTFC-API-BASIC-HASH-005 */
/**
 * Hash a stream of data with a cryptographic hash algorithm.
 *
 * The flags in the @a hash_ctx control the operation of this function.
 *
 * Hashing functions work on 64 octets of message at a time.  Therefore, when
 * any partial hashing of a long message is performed, the message @a length of
 * each segment must be a multiple of 64.  When ready to
 * #FSL_HASH_FLAGS_FINALIZE the hash, the @a length may be any value.
 *
 * With the #FSL_HASH_FLAGS_INIT and #FSL_HASH_FLAGS_FINALIZE flags on, a
 * one-shot complete hash, including padding, will be performed.  The @a length
 * may be any value.
 *
 * The first octets of a data stream can be hashed by setting the
 * #FSL_HASH_FLAGS_INIT and #FSL_HASH_FLAGS_SAVE flags.  The @a length must be
 * a multiple of 64.
 *
 * The flag #FSL_HASH_FLAGS_LOAD is used to load a context previously saved by
 * #FSL_HASH_FLAGS_SAVE.  The two in combination will allow a (multiple-of-64
 * octets) 'middle sequence' of the data stream to be hashed with the
 * beginning.  The @a length must again be a multiple of 64.
 *
 * Since the flag #FSL_HASH_FLAGS_LOAD is used to load a context previously
 * saved by #FSL_HASH_FLAGS_SAVE, the #FSL_HASH_FLAGS_LOAD and
 * #FSL_HASH_FLAGS_FINALIZE flags, used together, can be used to finish the
 * stream.  The @a length may be any value.
 *
 * If the user program wants to do the padding for the hash, it can leave off
 * the #FSL_HASH_FLAGS_FINALIZE flag.  The @a length must then be a multiple of
 * 64 octets.
 *
 * @param      user_ctx  A user context from #fsl_shw_register_user().
 * @param[in,out] hash_ctx Hashing algorithm and state of the cipher.
 * @param      msg       Pointer to the data to be hashed.
 * @param      length    Length, in octets, of the @a msg.
 * @param[out] result    If not null, pointer to where to store the hash
 *                       digest.
 * @param      result_len Number of octets to store in @a result.
 *
 * @return    A return code of type #fsl_shw_return_t.
 */
fsl_shw_return_t fsl_shw_hash(
                                fsl_shw_uco_t* user_ctx,
                                fsl_shw_hco_t* hash_ctx,
                                const uint8_t* msg,
                                uint32_t length,
                                uint8_t* result,
                                uint32_t result_len)
{
    fsl_shw_return_t ret = FSL_RETURN_ERROR_S;


    /* Unused */
    (void)user_ctx;
    (void)hash_ctx;
    (void)msg;
    (void)length;
    (void)result;
    (void)result_len;

    return ret;
}
