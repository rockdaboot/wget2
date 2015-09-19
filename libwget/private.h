/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen
 *
 */

#ifndef _LIBWGET_PRIVATE_H
#define _LIBWGET_PRIVATE_H

#include <stdlib.h> // needed for free()

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

// allow us to use wget_* functions without it's wget_ prefix within the library code
// #define _WGET_PREFIX wget_
//#define _WGET_CONCAT(a,b) a ## b
//#define _WGET_CONCAT2(a,b) _WGET_CONCAT(a,b)
// #define _GET_ADDPREFIX(a) _WGET_CONCAT2(_WGET_PREFIX,a)
// #define xmalloc _WGET_ADDPREFIX(xmalloc)

#define xmalloc wget_malloc
#define xcalloc wget_calloc
#define xrealloc wget_realloc

#define info_printf wget_info_printf
#define error_printf wget_error_printf
#define error_printf_exit wget_error_printf_exit
#define debug_printf wget_debug_printf
#define debug_write wget_debug_write

// _WGET_LOGGER is shared between log.c and logger.c, but must not be exposed to the public
struct _wget_logger_st {
	FILE *fp;
	const char *fname;
	void (*func)(const char *buf, size_t bufsize);

	void (*vprintf)(const wget_logger_t *logger, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(2,0);
	void (*write)(const wget_logger_t *logger, const char *buf, size_t bufsize);
};

#endif /* _LIBWGET_PRIVATE_H */
