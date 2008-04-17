/*
 * Copyright 2004-2008 Freescale Semiconductor, Inc. All Rights Reserved.
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
 * @file vpu_debug.h
 *
 * @brief VPU debug definition
 *
 * @ingroup VPU
 */

#ifndef __VPU_DEBUG_H
#define __VPU_DEBUG_H

#define	DEBUG_LEVEL	0
#define dprintf(level, fmt, arg...)     if (DEBUG_LEVEL >= level) \
        printf("<VPU-lib> " fmt , ## arg)

#endif
