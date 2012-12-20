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

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#	define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#	define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if GCC_VERSION_AT_LEAST(2,5)
#	define CONST __attribute__ ((const))
#	define NORETURN __attribute__ ((noreturn))
#else
#	define CONST
#	define NORETURN
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#	define PRINTF_FORMAT(a, b) __attribute__ ((format (printf, a, b)))
#define UNUSED __attribute__ ((unused))
#else
#	define PRINT_FORMAT(a, b)
#define UNUSED
#endif
#define UNUSED __attribute__ ((unused))

#if GCC_VERSION_AT_LEAST(2,96)
#	define PURE __attribute__ ((pure))
#else
#	define PURE
#endif

#if GCC_VERSION_AT_LEAST(3,0)
#	define MALLOC __attribute__ ((malloc))
#	define unlikely(expr) __builtin_expect(!!(expr), 0)
#	define likely(expr) __builtin_expect(!!(expr), 1)
#else
#	define MALLOC
#	define unlikely(expr) expr
#	define likely(expr) expr
#endif

#if GCC_VERSION_AT_LEAST(3,1)
#	define ALWAYS_INLINE __attribute__ ((always_inline))
#	define DEPRECATED __attribute__ ((deprecated))
#else
#	define ALWAYS_INLINE
#	define DEPRECATED
#endif

// nonnull is dangerous to use with current gcc <= 4.7.1.
// see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308
// we have to use e.g. the clang analyzer if we want NONNULL.
// but even clang is not perfect - don't use nonnull in production
#if defined(__clang__)
#	if GCC_VERSION_AT_LEAST(3,3)
#		define NONNULL_ALL __attribute__ ((nonnull))
#		define NONNULL(a) __attribute__ ((nonnull a))
#	else
#		define NONNULL_ALL
#		define NONNULL(a)
#	endif
#else
//#	define NONNULL_ALL
#		define NONNULL_ALL __attribute__ ((nonnull))
#	define NONNULL(a) __attribute__ ((nonnull a))
// #	define NONNULL(a)
#endif

#if GCC_VERSION_AT_LEAST(3,4)
#	define UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#	define UNUSED_RESULT
#endif

#if defined(__clang__)
#	define ALLOC_SIZE(a)
#	define ALLOC_SIZE2(a, b)
#elif GCC_VERSION_AT_LEAST(4,3)
#	define ALLOC_SIZE(a) __attribute__ ((__alloc_size__(a)))
#	define ALLOC_SIZE2(a, b) __attribute__ ((__alloc_size__(a, b)))
#else
#	define ALLOC_SIZE(a)
#	define ALLOC_SIZE2(a, b)
#endif

#if ENABLE_NLS != 0
	#include <libintl.h>
	#define _(STRING) gettext(STRING)
#else
	#define _(STRING) STRING
	#define ngettext(STRING1,STRING2,N) STRING2
#endif

//#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901
//#define restrict
//#endif

#endif /* _MGET_MGET_H */
