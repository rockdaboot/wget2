/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * along with Libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen
 *
 */

#ifndef LIBWGET_PRIVATE_H
#define LIBWGET_PRIVATE_H

#include <stdio.h> // needed for FILE
#include <stdlib.h> // needed for free()
#include <stdarg.h> // needed for va_list

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

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { wget_free((void *)(a)); a=NULL; } } while (0)

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

// allow us to use wget_* functions without it's wget_ prefix within the library code
// #define _WGET_PREFIX wget_
//#define _WGET_CONCAT(a,b) a ## b
//#define _WGET_CONCAT2(a,b) _WGET_CONCAT(a,b)
// #define _GET_ADDPREFIX(a) _WGET_CONCAT2(_WGET_PREFIX,a)
// #define xmalloc _WGET_ADDPREFIX(xmalloc)

#define info_printf wget_info_printf
#define error_printf wget_error_printf
#define error_printf_exit wget_error_printf_exit
#define debug_printf wget_debug_printf
#define debug_write wget_debug_write



#ifdef __cplusplus
    #define INITIALIZER(f) \
        static void f(void); \
        struct f##_t_ { f##_t_(void) { f(); } }; static f##_t_ f##_; \
        static void f(void)
#elif defined(_MSC_VER)
#define ___old_read read
#undef read
#pragma section(".CRT$XCU",read)
#define read ___old_read
    #define INITIALIZER2_(f,p) \
        static void f(void); \
        __declspec(allocate(".CRT$XCU")) void (*f##__constructor__)(void) = f; \
        __pragma(comment(linker,"/include:" p #f "__constructor__")) \
        static void f(void)
    #ifdef _WIN64
        #define INITIALIZER(f) INITIALIZER2_(f,"")
    #else
        #define INITIALIZER(f) INITIALIZER2_(f,"_")
    #endif
#pragma data_seg()
#else
    #define INITIALIZER(f) \
        static void f(void) __attribute__((constructor)); \
        static void f(void)
#endif


#endif /* LIBWGET_PRIVATE_H */
