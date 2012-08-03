/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for generic mget defines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_MGET_H
#define _MGET_MGET_H

#ifndef MGET_VERSION
	#define MGET_VERSION "0.1"
#endif

#if defined(__GNUC__) && __GNUC__ >= 3
	#define UNUSED __attribute__ ((unused))
	#define UNUSED_RESULT __attribute__ ((warn_unused_result))
	#define PURE __attribute__ ((pure))
	#define CONST __attribute__ ((const))
	#define NORETURN __attribute__ ((noreturn))
	#define NONNULL(...) __attribute__ ((nonnull(__VA_ARGS__)))
	#define PRINTF_FORMAT(a,b) __attribute__ ((format (printf, a, b)))
	#define DEPRECATED __attribute__ ((deprecated))
	#define MALLOC __attribute__ ((malloc))
	#define ALLOC_SIZE(a) __attribute__ ((alloc_size(a)))
	#define ALLOC_SIZE2(a,b) __attribute__ ((alloc_size(a,b)))
#else
	#define UNUSED
	#define UNUSED_RESULT
	#define PURE
	#define CONST
	#define NORETURN
	#define NONNULL
	#define PRINTF_FORMAT(a,b)
	#define DEPRECATED
	#define MALLOC
	#define ALLOC_SIZE(a)
	#define ALLOC_SIZE2(a,b)
#endif

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
	// define restrict for non c99 compilers
	#if !defined(restrict)
		#define restrict
	#endif
#endif

#if ENABLE_NLS != 0
	#include <libintl.h>
	#define _(STRING) gettext(STRING)
#else
	#define _(STRING) STRING
#endif

#endif /* _MGET_MGET_H */
