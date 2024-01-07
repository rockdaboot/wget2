/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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

#ifndef SRC_WGET_MAIN_H
#define SRC_WGET_MAIN_H

#include <stddef.h>
#include <stdlib.h> // needed for free()

#include <wget.h>

// gnulib convenience header for libintl.h, turn of annoying warnings
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wvla"
#endif // __GNUC__
#include <gettext.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__

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
#define xfree(a) do { if (a) { wget_free((void *)(a)); a=NULL; } } while (0)

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

#endif /* SRC_WGET_MAIN_H */
