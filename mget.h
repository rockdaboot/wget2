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
	#define MGET_VERSION "0.1.2"
#endif

#if __GNUC__ >= 3
	#define UNUSED __attribute__ ((__unused__))
	#define UNUSED_RESULT __attribute__ ((__warn_unused_result__))
	#define PURE __attribute__ ((__pure__))
	#define CONST __attribute__ ((__const__))
	#define NORETURN __attribute__ ((__noreturn__))

// nonnull is dangerous to use with current gcc <= 4.7.1
// see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308
// we have to use e.g. the clang analyzer if we want NONNULL
#if defined(__clang__)
	#define NONNULL(...) __attribute__ ((__nonnull__(__VA_ARGS__)))
	#define NONNULL_ALL __attribute__ ((__nonnull__))
#else
	#define NONNULL(...) __attribute__ ((__nonnull__(__VA_ARGS__)))
	#define NONNULL_ALL __attribute__ ((__nonnull__))
#endif
	#define PRINTF_FORMAT(a,b) __attribute__ ((__format__ (__printf__, a, b)))
	#define DEPRECATED __attribute__ ((__deprecated__))
	#define MALLOC __attribute__ ((__malloc__))
#if defined(__clang__)
	#define ALLOC_SIZE(...)
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
	#define ALLOC_SIZE(...) __attribute__ ((__alloc_size__(__VA_ARGS__)))
#else
	#define ALLOC_SIZE(...)
#endif
	#define unlikely(expr) __builtin_expect(!!(expr), 0)
	#define likely(expr) __builtin_expect(!!(expr), 1)
#else
	#define UNUSED
	#define UNUSED_RESULT
	#define PURE
	#define CONST
	#define NORETURN
	#define NONNULL(a)
	#define NONNULL_ALL
	#define PRINTF_FORMAT(a,b)
	#define DEPRECATED
	#define MALLOC
	#define ALLOC_SIZE(a)
	#define unlikely(expr) expr
	#define likely(expr) expr
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
