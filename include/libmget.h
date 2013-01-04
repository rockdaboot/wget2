/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for libmget library routines
 *
 * Changelog
 * 28.12.2012  Tim Ruehsen  created (moved mget.h and list.h and into here)
 *
 */

#ifndef _MGET_LIBMGET_H
#define _MGET_LIBMGET_H

#include <stddef.h>

/*
 * Attribute defines
 * Using G_GNU_ as prefix to let gtk-doc recognize the attributes.
 */

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#	define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#	define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if GCC_VERSION_AT_LEAST(2,5)
#	define G_GNUC_MGET_CONST __attribute__ ((const))
#	define G_GNUC_MGET_NORETURN __attribute__ ((noreturn))
#else
#	define G_GNUC_MGET_CONST
#	define G_GNUC_MGET_NORETURN
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#	define G_GNUC_MGET_PRINTF_FORMAT(a, b) __attribute__ ((format (printf, a, b)))
#define G_GNUC_MGET_UNUSED __attribute__ ((unused))
#else
#	define G_GNUC_MGET_PRINT_FORMAT(a, b)
#define G_GNUC_MGET_UNUSED
#endif

#if GCC_VERSION_AT_LEAST(2,96)
#	define G_GNUC_MGET_PURE __attribute__ ((pure))
#else
#	define G_GNUC_MGET_PURE
#endif

#if GCC_VERSION_AT_LEAST(3,0)
#	define G_GNUC_MGET_MALLOC __attribute__ ((malloc))
#	define unlikely(expr) __builtin_expect(!!(expr), 0)
#	define likely(expr) __builtin_expect(!!(expr), 1)
#else
#	define G_GNUC_MGET_MALLOC
#	define unlikely(expr) expr
#	define likely(expr) expr
#endif

#if GCC_VERSION_AT_LEAST(3,1)
#	define G_GNUC_MGET_ALWAYS_INLINE __attribute__ ((always_inline))
#	define G_GNUC_MGET_DEPRECATED __attribute__ ((deprecated))
#else
#	define G_GNUC_MGET_ALWAYS_INLINE
#	define G_GNUC_MGET_DEPRECATED
#endif

// nonnull is dangerous to use with current gcc <= 4.7.1.
// see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308
// we have to use e.g. the clang analyzer if we want NONNULL.
// but even clang is not perfect - don't use nonnull in production
#if defined(__clang__)
#	if GCC_VERSION_AT_LEAST(3,3)
#		define G_GNUC_MGET_NONNULL_ALL __attribute__ ((nonnull))
#		define G_GNUC_MGET_NONNULL(a) __attribute__ ((nonnull a))
#	else
#		define G_GNUC_MGET_NONNULL_ALL
#		define G_GNUC_MGET_NONNULL(a)
#	endif
#elif GCC_VERSION_AT_LEAST(3,3)
#	define G_GNUC_MGET_NONNULL_ALL __attribute__ ((nonnull))
#	define G_GNUC_MGET_NONNULL(a) __attribute__ ((nonnull a))
#else
#	define G_GNUC_MGET_NONNULL_ALL
#	define G_GNUC_MGET_NONNULL(a)
#endif

#if GCC_VERSION_AT_LEAST(3,4)
#	define G_GNUC_MGET_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#	define G_GNUC_MGET_UNUSED_RESULT
#endif

#if defined(__clang__)
#	define G_GNUC_MGET_ALLOC_SIZE(a)
#	define G_GNUC_MGET_ALLOC_SIZE2(a, b)
#elif GCC_VERSION_AT_LEAST(4,3)
#	define G_GNUC_MGET_ALLOC_SIZE(a) __attribute__ ((__alloc_size__(a)))
#	define G_GNUC_MGET_ALLOC_SIZE2(a, b) __attribute__ ((__alloc_size__(a, b)))
#else
#	define G_GNUC_MGET_ALLOC_SIZE(a)
#	define G_GNUC_MGET_ALLOC_SIZE2(a, b)
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

#undef GCC_VERSION_AT_LEAST

/*
 * Double linked list
 */

/**
 * MGET_LIST:
 *
 * Type for double linked lists and list entries.
 */
typedef struct _MGET_LISTNODE MGET_LIST;

void *
	mget_list_append(MGET_LIST **list, const void *data, size_t size) G_GNUC_MGET_NONNULL_ALL;
void *
	mget_list_prepend(MGET_LIST **list, const void *data, size_t size) G_GNUC_MGET_NONNULL_ALL;
void *
	mget_list_getfirst(const MGET_LIST *list) G_GNUC_MGET_CONST;
void *
	mget_list_getlast(const MGET_LIST *list) G_GNUC_MGET_CONST;
void
	mget_list_remove(MGET_LIST **list, void *elem) G_GNUC_MGET_NONNULL_ALL;
void
	mget_list_free(MGET_LIST **list) G_GNUC_MGET_NONNULL_ALL;
int
	mget_list_browse(const MGET_LIST *list, int (*browse)(void *context, void *elem), void *context) G_GNUC_MGET_NONNULL((2));

#endif /* _MGET_LIBMGET_H */
