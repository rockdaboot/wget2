/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Wget header file
 *
 * Changelog
 * 11.01.2013  Tim Ruehsen  created
 *
 */

#ifndef _WGET_WGET_H
#define _WGET_WGET_H

#include <stddef.h>
#include <stdlib.h> // needed for free()

#include <wget.h>

// gnulib convenience header for libintl.h, turn of annoying warnings
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#include <gettext.h>
#pragma GCC diagnostic pop

#ifdef ENABLE_NLS
#	define _(STRING) gettext(STRING)
#else
#	define _(STRING) STRING
#endif

// use the helper routines provided by libwget
#define info_printf wget_info_printf
#define error_printf  wget_error_printf
#define error_printf_exit  wget_error_printf_exit
#define debug_printf wget_debug_printf
#define debug_write wget_debug_write

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

// Number of threads in the program
extern int nthreads;

typedef enum exit_status_t {
	WG_EXIT_STATUS_NO_ERROR   = 0,
	WG_EXIT_STATUS_GENERIC    = 1,
	WG_EXIT_STATUS_PARSE_INIT = 2,
	WG_EXIT_STATUS_IO         = 3,
	WG_EXIT_STATUS_NETWORK    = 4,
	WG_EXIT_STATUS_TLS        = 5,
	WG_EXIT_STATUS_AUTH       = 6,
	WG_EXIT_STATUS_PROTOCOL   = 7,
	WG_EXIT_STATUS_REMOTE     = 8,
} exit_status_t;

void set_exit_status(exit_status_t status);
const char * G_GNUC_WGET_NONNULL_ALL get_local_filename(wget_iri_t *iri);

#endif /* _WGET_WGET_H */
