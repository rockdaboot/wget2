/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen
 *
 */

#ifndef _LIBMGET_PRIVATE_H
#define _LIBMGET_PRIVATE_H

#include <stdlib.h> // needed for free()

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

// allow us to use mget_* functions without it's mget_ prefix within the library code
// #define _MGET_PREFIX mget_
//#define _MGET_CONCAT(a,b) a ## b
//#define _MGET_CONCAT2(a,b) _MGET_CONCAT(a,b)
// #define _GET_ADDPREFIX(a) _MGET_CONCAT2(_MGET_PREFIX,a)
// #define xmalloc _MGET_ADDPREFIX(xmalloc)

#define xmalloc mget_malloc
#define xcalloc mget_calloc
#define xrealloc mget_realloc

#define info_printf mget_info_printf
#define error_printf mget_error_printf
#define error_printf_exit mget_error_printf_exit
#define debug_printf mget_debug_printf

// _MGET_LOGGER is shared between log.c and logger.c, but must no be exposed to the public
struct _MGET_LOGGER {
	FILE *fp;
	const char *fname;
	void (*func)(const char *buf, size_t bufsize);

	void (*vprintf)(const MGET_LOGGER *logger, const char *fmt, va_list args);
	void (*write)(const MGET_LOGGER *logger, const char *buf, size_t bufsize);
};

#endif /* _MGET_INTERN_H */
