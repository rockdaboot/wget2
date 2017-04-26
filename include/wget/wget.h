/*
 * Copyright(c) 2012-2015 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for libwget library routines
 *
 * Changelog
 * 28.12.2012  Tim Ruehsen  created (moved wget.h and list.h and into here)
 *
 */

#ifndef _LIBWGET_LIBWGET_H
#define _LIBWGET_LIBWGET_H

#include <stddef.h>
#ifdef HAVE_PTHREAD_H
#	include <pthread.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#ifdef WITH_LIBNGHTTP2
#	include <nghttp2/nghttp2.h>
#endif

#ifdef WGETVER_FILE
#   include WGETVER_FILE
#else //not WGETVER_FILE
#   include "wgetver.h"
#endif //WGETVER_FILE

// see https://www.gnu.org/software/gnulib/manual/html_node/Exported-Symbols-of-Shared-Libraries.html
#if defined BUILDING_LIBWGET && HAVE_VISIBILITY
#	define WGETAPI __attribute__ ((__visibility__("default")))
#elif defined BUILDING_LIBWGET && defined _MSC_VER && !defined LIBWGET_STATIC
#	define WGETAPI __declspec(dllexport)
#elif defined _MSC_VER && !defined LIBWGET_STATIC
#	define WGETAPI __declspec(dllimport)
#else
#	define WGETAPI
#endif

/*
 * Attribute defines specific for clang (especially for improving clang analyzer)
 * Using G_GNU_ as prefix to let gtk-doc recognize the attributes.
 */

/*
 * Attribute defines for GCC and compatible compilers
 * Using G_GNU_ as prefix to let gtk-doc recognize the attributes.
 */

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#	define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#	define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if GCC_VERSION_AT_LEAST(2,5) || defined(__clang__)
#	define G_GNUC_WGET_CONST __attribute__ ((const))
#	define G_GNUC_WGET_NORETURN __attribute__ ((noreturn))
#else
#	define G_GNUC_WGET_CONST
#	define G_GNUC_WGET_NORETURN
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#	define G_GNUC_WGET_PRINTF_FORMAT(a, b) __attribute__ ((format (printf, a, b)))
#	define G_GNUC_WGET_UNUSED __attribute__ ((unused))
#else
#	define G_GNUC_WGET_PRINTF_FORMAT(a, b)
#	define G_GNUC_WGET_UNUSED
#endif

#if GCC_VERSION_AT_LEAST(2,96) || defined(__clang__)
#	define G_GNUC_WGET_PURE __attribute__ ((pure))
#else
#	define G_GNUC_WGET_PURE
#endif

#if GCC_VERSION_AT_LEAST(3,0)
#	define G_GNUC_WGET_MALLOC __attribute__ ((malloc))
#	define unlikely(expr) __builtin_expect(!!(expr), 0)
#	define likely(expr) __builtin_expect(!!(expr), 1)
#else
#	define G_GNUC_WGET_MALLOC
#	define unlikely(expr) expr
#	define likely(expr) expr
#endif

#if GCC_VERSION_AT_LEAST(3,1) || defined(__clang__)
#	define G_GNUC_WGET_ALWAYS_INLINE __attribute__ ((always_inline))
#   define G_GNUC_WGET_FLATTEN __attribute__ ((flatten))
#   define G_GNUC_WGET_DEPRECATED __attribute__ ((deprecated))
#else
#	define G_GNUC_WGET_ALWAYS_INLINE
#	define G_GNUC_WGET_FLATTEN
#	define G_GNUC_WGET_DEPRECATED
#endif

// nonnull is dangerous to use with current gcc <= 4.7.1.
// see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308
// we have to use e.g. the clang analyzer if we want NONNULL.
// but even clang is not perfect - don't use nonnull in production
#if defined(__clang__)
#	if GCC_VERSION_AT_LEAST(3,3)
#		define G_GNUC_WGET_NONNULL_ALL __attribute__ ((nonnull))
#		define G_GNUC_WGET_NONNULL(a) __attribute__ ((nonnull a))
#	else
#		define G_GNUC_WGET_NONNULL_ALL
#		define G_GNUC_WGET_NONNULL(a)
#	endif
#elif GCC_VERSION_AT_LEAST(3,3)
#	define G_GNUC_WGET_NONNULL_ALL __attribute__ ((nonnull))
#	define G_GNUC_WGET_NONNULL(a) __attribute__ ((nonnull a))
#else
#	define G_GNUC_WGET_NONNULL_ALL
#	define G_GNUC_WGET_NONNULL(a)
#endif

#if GCC_VERSION_AT_LEAST(3,4)
#	define G_GNUC_WGET_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#	define G_GNUC_WGET_UNUSED_RESULT
#endif

#if GCC_VERSION_AT_LEAST(4,0)
#	define G_GNUC_WGET_NULL_TERMINATED __attribute__((__sentinel__))
#else
#	define G_GNUC_WGET_NULL_TERMINATED
#endif

#if defined(__clang__)
#	define G_GNUC_WGET_ALLOC_SIZE(a)
#	define G_GNUC_WGET_ALLOC_SIZE2(a, b)
#elif GCC_VERSION_AT_LEAST(4,3)
#	define G_GNUC_WGET_ALLOC_SIZE(a) __attribute__ ((__alloc_size__(a)))
#	define G_GNUC_WGET_ALLOC_SIZE2(a, b) __attribute__ ((__alloc_size__(a, b)))
#else
#	define G_GNUC_WGET_ALLOC_SIZE(a)
#	define G_GNUC_WGET_ALLOC_SIZE2(a, b)
#endif

// Let C++ include C headers
#ifdef  __cplusplus
#	define WGET_BEGIN_DECLS  extern "C" {
#	define WGET_END_DECLS    }
#else
#	define WGET_BEGIN_DECLS
#	define WGET_END_DECLS
#endif

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

//#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901
//#	define restrict
//#endif

#undef GCC_VERSION_AT_LEAST

// we can prefix the exposed functions as we want
#ifndef _WGET_PREFIX
#	define _WGET_PREFIX wget_
#endif

WGET_BEGIN_DECLS

/*
 * Library initialization functions
 */

// Why not using enum ? Might result in different values if one entry is inserted.
// And that might break the ABI.
#define WGET_DEBUG_STREAM 1000
#define WGET_DEBUG_FUNC   1001
#define WGET_DEBUG_FILE   1002
#define WGET_ERROR_STREAM 1003
#define WGET_ERROR_FUNC   1004
#define WGET_ERROR_FILE   1005
#define WGET_INFO_STREAM  1006
#define WGET_INFO_FUNC    1007
#define WGET_INFO_FILE    1008
#define WGET_DNS_CACHING  1009
#define WGET_COOKIE_SUFFIXES 1010
#define WGET_COOKIES_ENABLED 1011
#define WGET_COOKIE_FILE 1012
#define WGET_COOKIE_DB 1013
#define WGET_COOKIE_KEEPSESSIONCOOKIES 1014
#define WGET_BIND_ADDRESS 1015
#define WGET_NET_FAMILY_EXCLUSIVE 1016
#define WGET_NET_FAMILY_PREFERRED 1017
#define WGET_TCP_FASTFORWARD  1018

#define WGET_HTTP_URL                 2000
#define WGET_HTTP_URL_ENCODING        2001
#define WGET_HTTP_URI                 2002
#define WGET_HTTP_COOKIE_STORE        2003
#define WGET_HTTP_HEADER_ADD          2004
//#define WGET_HTTP_HEADER_DEL        2005
//#define WGET_HTTP_HEADER_SET        2006
//#define WGET_HTTP_BIND_ADDRESS      2007
#define WGET_HTTP_CONNECTION_PTR      2008
#define WGET_HTTP_RESPONSE_KEEPHEADER 2009
#define WGET_HTTP_MAX_REDIRECTIONS    2010
#define WGET_HTTP_BODY_SAVEAS_STREAM  2011
#define WGET_HTTP_BODY_SAVEAS_FILE    2012
#define WGET_HTTP_BODY_SAVEAS_FD      2013
#define WGET_HTTP_BODY_SAVEAS_FUNC    2014
#define WGET_HTTP_HEADER_FUNC         2015
#define WGET_HTTP_SCHEME              2016
#define WGET_HTTP_BODY                2017
#define WGET_HTTP_BODY_SAVEAS         2018
#define WGET_HTTP_USER_DATA           2019

// definition of error conditions
#define WGET_E_SUCCESS 0 /* OK */
#define WGET_E_UNKNOWN -1 /* general error if nothing else appropriate */
#define WGET_E_INVALID -2 /* invalid value to function */
#define WGET_E_TIMEOUT -3 /* timeout condition */
#define WGET_E_CONNECT -4 /* connect failure */
#define WGET_E_HANDSHAKE -5 /* general TLS handshake failure */
#define WGET_E_CERTIFICATE -6 /* general TLS certificate failure */
#define WGET_E_TLS_DISABLED -7 /* TLS was not enabled at compile time */

typedef void (*wget_global_get_func_t)(const char *, size_t);

WGETAPI void
	wget_global_init(int key, ...) G_GNUC_WGET_NULL_TERMINATED;
WGETAPI void
	wget_global_deinit(void);
WGETAPI const void *
	wget_global_get_ptr(int key);
WGETAPI int
	wget_global_get_int(int key);
WGETAPI wget_global_get_func_t
	wget_global_get_func(int key);

/*
 * Utility functions
 */

/**
 * WGET_UTILITY:
 *
 * General utility functions
 */

// <mode> values for wget_ready_to_transfer()
#define WGET_IO_READABLE 1
#define WGET_IO_WRITABLE 2

typedef int (*wget_update_load_t)(void *, FILE *fp);
typedef int (*wget_update_save_t)(void *, FILE *fp);

WGETAPI int
	wget_ready_2_read(int fd, int timeout);
WGETAPI int
	wget_ready_2_write(int fd, int timeout);
WGETAPI int
	wget_ready_2_transfer(int fd, int timeout, short mode);
WGETAPI int
	wget_strcmp(const char *s1, const char *s2) G_GNUC_WGET_PURE;
WGETAPI int
	wget_strcasecmp(const char *s1, const char *s2) G_GNUC_WGET_PURE;
WGETAPI int
	wget_strcasecmp_ascii(const char *s1, const char *s2) G_GNUC_WGET_PURE;
WGETAPI int
	wget_strncasecmp_ascii(const char *s1, const char *s2, size_t n) G_GNUC_WGET_PURE;
WGETAPI char *
	wget_strtolower(char *s);
WGETAPI int
	wget_strncmp(const char *s1, const char *s2, size_t n) G_GNUC_WGET_PURE;
WGETAPI int
	wget_strncasecmp(const char *s1, const char *s2, size_t n) G_GNUC_WGET_PURE;
WGETAPI void
	wget_memtohex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_millisleep(int ms);
WGETAPI long long
	wget_get_timemillis(void);
WGETAPI int
	wget_percent_unescape(char *src);
WGETAPI int
	wget_match_tail(const char *s, const char *tail) G_GNUC_WGET_PURE;
WGETAPI int
	wget_match_tail_nocase(const char *s, const char *tail) G_GNUC_WGET_PURE;
WGETAPI char *
	wget_strnglob(const char *str, size_t n, int flags) G_GNUC_WGET_PURE;
WGETAPI char *
	wget_human_readable(char *buf, size_t bufsize, uint64_t n) G_GNUC_WGET_CONST;
WGETAPI int
	wget_get_screen_size(int *width, int *height);
WGETAPI ssize_t
	wget_fdgetline(char **buf, size_t *bufsize, int fd) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_getline(char **buf, size_t *bufsize, FILE *fp) G_GNUC_WGET_NONNULL_ALL;
WGETAPI FILE *
	wget_vpopenf(const char *type, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((1,2));
WGETAPI FILE *
	wget_popenf(const char *type, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(2,3) G_GNUC_WGET_NONNULL((1,2));
WGETAPI FILE *
	wget_popen2f(FILE **fpin, FILE **fpout, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(3,4) G_GNUC_WGET_NONNULL((3));
WGETAPI pid_t
	wget_fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv);
WGETAPI pid_t
	wget_popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv);
WGETAPI char *
	wget_read_file(const char *fname, size_t *size);
WGETAPI int
	wget_update_file(const char *fname, wget_update_load_t load_func, wget_update_save_t save_func, void *context);
WGETAPI int
	wget_truncate(const char *path, off_t length) G_GNUC_WGET_NONNULL((1));
WGETAPI const char
	*wget_local_charset_encoding(void);
WGETAPI int
	wget_memiconv(const char *src_encoding, const void *src, size_t srclen, const char *dst_encoding, char **out, size_t *outlen);
WGETAPI char *
	wget_striconv(const char *src, const char *src_encoding, const char *dst_encoding) G_GNUC_WGET_MALLOC;
WGETAPI int
	wget_str_needs_encoding(const char *s) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_PURE;
WGETAPI int
	wget_str_is_valid_utf8(const char *utf8) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_PURE;
WGETAPI char *
	wget_str_to_utf8(const char *src, const char *encoding) G_GNUC_WGET_MALLOC;
WGETAPI char *
	wget_utf8_to_str(const char *src, const char *encoding) G_GNUC_WGET_MALLOC;
WGETAPI const char *
	wget_str_to_ascii(const char *src);

/**
 * WGET_COMPATIBILITY:
 *
 * General compatibility functions
 */

#ifndef HAVE_STRLCPY
WGETAPI size_t
	strlcpy(char *restrict dst, const char *restrict src, size_t size) G_GNUC_WGET_NONNULL_ALL;
#endif

/**
 * \ingroup libwget-list
 *
 * Type for double linked lists and list entries.
 */
typedef struct _wget_list_st wget_list_t;
typedef int (*wget_list_browse_t)(void *context, void *elem);

WGETAPI void *
	wget_list_append(wget_list_t **list, const void *data, size_t size) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void *
	wget_list_prepend(wget_list_t **list, const void *data, size_t size) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void *
	wget_list_getfirst(const wget_list_t *list) G_GNUC_WGET_CONST;
WGETAPI void *
	wget_list_getlast(const wget_list_t *list) G_GNUC_WGET_PURE;
WGETAPI void *
	wget_list_getnext(const void *elem) G_GNUC_WGET_PURE;
WGETAPI void
	wget_list_remove(wget_list_t **list, void *elem) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_list_free(wget_list_t **list) G_GNUC_WGET_NONNULL_ALL;
WGETAPI int
	wget_list_browse(const wget_list_t *list, wget_list_browse_t browse, void *context) G_GNUC_WGET_NONNULL((2));

/*
 * Memory allocation routines
 */

// I try to never leave freed pointers hanging around
#define wget_xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

typedef void (*wget_oom_callback_t)(void);

WGETAPI void *
	wget_malloc(size_t size) G_GNUC_WGET_MALLOC G_GNUC_WGET_ALLOC_SIZE(1);
WGETAPI void *
	wget_calloc(size_t nmemb, size_t size) G_GNUC_WGET_MALLOC G_GNUC_WGET_ALLOC_SIZE2(1,2);
WGETAPI void *
	wget_realloc(void *ptr, size_t size) G_GNUC_WGET_ALLOC_SIZE(2);
WGETAPI void
	wget_set_oomfunc(wget_oom_callback_t);

/*
 * String/Memory routines, slightly different than standard functions
 */

WGETAPI void *
	wget_memdup(const void *m, size_t n) G_GNUC_WGET_ALLOC_SIZE(2);
WGETAPI char *
	wget_strdup(const char *s) G_GNUC_WGET_MALLOC;
WGETAPI char *
	wget_strmemdup(const void *m, size_t n) G_GNUC_WGET_ALLOC_SIZE(2);
WGETAPI void
	wget_strmemcpy(char *s, size_t ssize, const void *m, size_t n) G_GNUC_WGET_NONNULL_ALL;

/*
 * Base64 routines
 */

static inline size_t wget_base64_get_decoded_length(size_t len)
{
	return ((len + 3) / 4) * 3 + 1;
}

static inline size_t wget_base64_get_encoded_length(size_t len)
{
	return ((len + 2) / 3) * 4 + 1;
}

WGETAPI int
	wget_base64_is_string(const char *src) G_GNUC_WGET_PURE;
WGETAPI size_t
	wget_base64_decode(char *restrict dst, const char *restrict src, size_t n) G_GNUC_WGET_NONNULL_ALL;
WGETAPI size_t
	wget_base64_encode(char *restrict dst, const char *restrict src, size_t n) G_GNUC_WGET_NONNULL_ALL;
WGETAPI char *
	wget_base64_decode_alloc(const char *restrict src, size_t n) G_GNUC_WGET_NONNULL_ALL;
WGETAPI char *
	wget_base64_encode_alloc(const char *restrict src, size_t n) G_GNUC_WGET_NONNULL_ALL;
WGETAPI char *
	wget_base64_encode_vprintf_alloc(const char *restrict fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(1,0) G_GNUC_WGET_NONNULL_ALL;
WGETAPI char *
	wget_base64_encode_printf_alloc(const char *restrict fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(1,2) G_GNUC_WGET_NONNULL_ALL;

/*
 * Buffer routines
 */

typedef struct {
	char *
		data; // pointer to internal memory
	size_t
		length; // number of bytes in 'data'
	size_t
		size; // capacity of 'data' (terminating 0 byte doesn't count here)
	unsigned int
		release_data : 1, // 'data' has been malloc'ed and must be freed
		release_buf : 1; // buffer_t structure has been malloc'ed and must be freed
} wget_buffer_t;

WGETAPI wget_buffer_t *
	wget_buffer_init(wget_buffer_t *buf, char *data, size_t size);
WGETAPI wget_buffer_t *
	wget_buffer_alloc(size_t size) G_GNUC_WGET_MALLOC G_GNUC_WGET_ALLOC_SIZE(1);
WGETAPI void
	wget_buffer_ensure_capacity(wget_buffer_t *buf, size_t size) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_buffer_deinit(wget_buffer_t *buf);
WGETAPI void
	wget_buffer_free(wget_buffer_t **buf);
WGETAPI void
	wget_buffer_free_data(wget_buffer_t *buf);
WGETAPI void
	wget_buffer_realloc(wget_buffer_t *buf, size_t size) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_ALLOC_SIZE(2);
WGETAPI void
	wget_buffer_reset(wget_buffer_t *buf);
WGETAPI size_t
	wget_buffer_memcpy(wget_buffer_t *buf, const void *data, size_t length) G_GNUC_WGET_NONNULL((1,2));
WGETAPI size_t
	wget_buffer_memcat(wget_buffer_t *buf, const void *data, size_t length) G_GNUC_WGET_NONNULL((1,2));
WGETAPI size_t
	wget_buffer_strcpy(wget_buffer_t *buf, const char *s) G_GNUC_WGET_NONNULL((1,2));
WGETAPI size_t
	wget_buffer_strcat(wget_buffer_t *buf, const char *s) G_GNUC_WGET_NONNULL((1,2));
WGETAPI size_t
	wget_buffer_bufcpy(wget_buffer_t *buf, wget_buffer_t *src) G_GNUC_WGET_NONNULL((1,2));
WGETAPI size_t
	wget_buffer_bufcat(wget_buffer_t *buf, wget_buffer_t *src) G_GNUC_WGET_NONNULL((1,2));
WGETAPI size_t
	wget_buffer_memset(wget_buffer_t *buf, char c, size_t length) G_GNUC_WGET_NONNULL((1));
WGETAPI size_t
	wget_buffer_memset_append(wget_buffer_t *buf, char c, size_t length) G_GNUC_WGET_NONNULL((1));
WGETAPI char *
	wget_buffer_trim(wget_buffer_t *buf) G_GNUC_WGET_NONNULL((1));
WGETAPI size_t
	wget_buffer_vprintf_append(wget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_WGET_NONNULL((1,2)) G_GNUC_WGET_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_buffer_printf_append(wget_buffer_t *buf, const char *fmt, ...) G_GNUC_WGET_NONNULL((1,2)) G_GNUC_WGET_PRINTF_FORMAT(2,3);
WGETAPI size_t
	wget_buffer_vprintf(wget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_WGET_NONNULL((1,2)) G_GNUC_WGET_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_buffer_printf(wget_buffer_t *buf, const char *fmt, ...) G_GNUC_WGET_NONNULL((1,2)) G_GNUC_WGET_PRINTF_FORMAT(2,3);

/*
 * Printf-style routines
 */

WGETAPI size_t
	wget_vasprintf(char **strp, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_asprintf(char **strp, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(2,3);
WGETAPI char *
	wget_vaprintf(const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(1,0);
WGETAPI char *
	wget_aprintf(const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(1,2);

/*
 * Logger routines
 */

typedef struct _wget_logger_st wget_logger_t;
typedef void (*wget_logger_func_t)(const char *buf , size_t len) G_GNUC_WGET_NONNULL_ALL;

WGETAPI void
	wget_logger_set_func(wget_logger_t *logger, wget_logger_func_t);
WGETAPI void
	wget_logger_set_stream(wget_logger_t *logger, FILE *fp);
WGETAPI void
	wget_logger_set_file(wget_logger_t *logger, const char *fname);
WGETAPI wget_logger_func_t
	wget_logger_get_func(wget_logger_t *logger) G_GNUC_WGET_PURE;
WGETAPI FILE *
	wget_logger_get_stream(wget_logger_t *logger) G_GNUC_WGET_PURE;
WGETAPI const char *
	wget_logger_get_file(wget_logger_t *logger) G_GNUC_WGET_PURE;
WGETAPI int
	wget_logger_is_active(wget_logger_t *logger) G_GNUC_WGET_PURE;

/*
 * Logging routines
 */

#define WGET_LOGGER_INFO   1
#define WGET_LOGGER_ERROR  2
#define WGET_LOGGER_DEBUG  3

WGETAPI void
	wget_info_vprintf(const char *fmt, va_list args) G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT(1,0);
WGETAPI void
	wget_info_printf(const char *fmt, ...) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_PRINTF_FORMAT(1,2);
WGETAPI void
	wget_error_vprintf(const char *fmt, va_list args) G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT(1,0);
WGETAPI void
	wget_error_printf(const char *fmt, ...) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_PRINTF_FORMAT(1,2);
WGETAPI void
	wget_error_printf_exit(const char *fmt, ...) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_NORETURN G_GNUC_WGET_PRINTF_FORMAT(1,2);
WGETAPI void
	wget_debug_vprintf(const char *fmt, va_list args) G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT(1,0);
WGETAPI void
	wget_debug_printf(const char *fmt, ...) G_GNUC_WGET_NONNULL((1)) G_GNUC_WGET_PRINTF_FORMAT(1,2);
WGETAPI void
	wget_debug_write(const char *buf, size_t len) G_GNUC_WGET_NONNULL_ALL;
WGETAPI wget_logger_t *
	wget_get_logger(int id) G_GNUC_WGET_CONST;

/*
 * Vector datatype routines
 */

typedef struct _wget_vector_st wget_vector_t;
typedef int (*wget_vector_compare_t)(const void *elem1, const void *elem2);
typedef int (*wget_vector_find_t)(void *elem);
typedef int (*wget_vector_browse_t)(void *ctx, void *elem);
typedef int (*wget_vector_destructor_t)(void *elem);

WGETAPI wget_vector_t *
	wget_vector_create(int max, int off, wget_vector_compare_t cmp) G_GNUC_WGET_MALLOC;
WGETAPI int
	wget_vector_find(const wget_vector_t *v, const void *elem) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_findext(const wget_vector_t *v, int start, int direction, wget_vector_find_t find) G_GNUC_WGET_NONNULL((4));
WGETAPI int
	wget_vector_contains(const wget_vector_t *v, const void *elem) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_insert(wget_vector_t *v, const void *elem, size_t size, int pos) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_insert_noalloc(wget_vector_t *v, const void *elem, int pos) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_insert_sorted(wget_vector_t *v, const void *elem, size_t size) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_insert_sorted_noalloc(wget_vector_t *v, const void *elem) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_add(wget_vector_t *v, const void *elem, size_t size) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_add_noalloc(wget_vector_t *v, const void *elem) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_add_str(wget_vector_t *v, const char *s) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_add_vprintf(wget_vector_t *v, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_add_printf(wget_vector_t *v, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(2,3) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_replace(wget_vector_t *v, const void *elem, size_t size, int pos) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_replace_noalloc(wget_vector_t *v, const void *elem, int pos) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_vector_move(wget_vector_t *v, int old_pos, int new_pos);
WGETAPI int
	wget_vector_swap(wget_vector_t *v, int pos1, int pos2);
WGETAPI int
	wget_vector_remove(wget_vector_t *v, int pos);
WGETAPI int
	wget_vector_remove_nofree(wget_vector_t *v, int pos);
WGETAPI int
	wget_vector_size(const wget_vector_t *v) G_GNUC_WGET_PURE;
WGETAPI int
	wget_vector_browse(const wget_vector_t *v, wget_vector_browse_t browse, void *ctx) G_GNUC_WGET_NONNULL((2));
WGETAPI void
	wget_vector_free(wget_vector_t **v);
WGETAPI void
	wget_vector_clear(wget_vector_t *v);
WGETAPI void
	wget_vector_clear_nofree(wget_vector_t *v);
WGETAPI void *
	wget_vector_get(const wget_vector_t *v, int pos) G_GNUC_WGET_PURE;
WGETAPI void
	wget_vector_setcmpfunc(wget_vector_t *v, wget_vector_compare_t cmp) G_GNUC_WGET_NONNULL((2));
WGETAPI void
	wget_vector_set_destructor(wget_vector_t *v, wget_vector_destructor_t destructor);
WGETAPI void
	wget_vector_sort(wget_vector_t *v);

/*
 * Hashmap datatype routines
 */

typedef struct _wget_hashmap_st wget_hashmap_t;
typedef int (*wget_hashmap_compare_t)(const void *key1, const void *key2);
typedef unsigned int (*wget_hashmap_hash_t)(const void *value);
typedef int (*wget_hashmap_browse_t)(void *ctx, const void *key, void *value);
typedef void (*wget_hashmap_key_destructor_t)(void *key);
typedef void (*wget_hashmap_value_destructor_t)(void *value);

WGETAPI wget_hashmap_t
	*wget_hashmap_create(int max, int off, wget_hashmap_hash_t hash, wget_hashmap_compare_t cmp) G_GNUC_WGET_MALLOC;
WGETAPI int
	wget_hashmap_put(wget_hashmap_t *h, const void *key, size_t keysize, const void *value, size_t valuesize);
WGETAPI int
	wget_hashmap_put_noalloc(wget_hashmap_t *h, const void *key, const void *value);
//WGETAPI int
//	wget_hashmap_put_ident(WGET_HASHMAP *h, const void *key, size_t keysize);
//WGETAPI int
//	wget_hashmap_put_ident_noalloc(WGET_HASHMAP *h, const void *key);
WGETAPI int
	wget_hashmap_size(const wget_hashmap_t *h) G_GNUC_WGET_PURE;
WGETAPI int
	wget_hashmap_browse(const wget_hashmap_t *h, wget_hashmap_browse_t browse, void *ctx) G_GNUC_WGET_NONNULL((2));
WGETAPI void
	wget_hashmap_free(wget_hashmap_t **h);
WGETAPI void
	wget_hashmap_clear(wget_hashmap_t *h);
WGETAPI void *
	wget_hashmap_get(const wget_hashmap_t *h, const void *key);
WGETAPI int
	wget_hashmap_get_null(const wget_hashmap_t *h, const void *key, void **value);
WGETAPI int
	wget_hashmap_contains(const wget_hashmap_t *h, const void *key);
WGETAPI int
	wget_hashmap_remove(wget_hashmap_t *h, const void *key);
WGETAPI int
	wget_hashmap_remove_nofree(wget_hashmap_t *h, const void *key);
WGETAPI void
	wget_hashmap_setcmpfunc(wget_hashmap_t *h, wget_hashmap_compare_t cmp);
WGETAPI void
	wget_hashmap_sethashfunc(wget_hashmap_t *h, wget_hashmap_hash_t hash);
WGETAPI void
	wget_hashmap_set_key_destructor(wget_hashmap_t *h, wget_hashmap_key_destructor_t destructor);
WGETAPI void
	wget_hashmap_set_value_destructor(wget_hashmap_t *h, wget_hashmap_value_destructor_t destructor);
WGETAPI void
	wget_hashmap_setloadfactor(wget_hashmap_t *h, float factor);

/*
 * Stringmap datatype routines
 */

typedef wget_hashmap_t wget_stringmap_t;
typedef int (*wget_stringmap_compare_t)(const char *key1, const char *key2);
typedef unsigned int (*wget_stringmap_hash_t)(const char *value);
typedef int (*wget_stringmap_browse_t)(void *ctx, const char *key, void *value);
//typedef void (*wget_stringmap_key_destructor_t)(char *key);
typedef void (*wget_stringmap_value_destructor_t)(void *value);

WGETAPI wget_stringmap_t *
	wget_stringmap_create(int max) G_GNUC_WGET_MALLOC;
WGETAPI wget_stringmap_t *
	wget_stringmap_create_nocase(int max) G_GNUC_WGET_MALLOC;
WGETAPI int
	wget_stringmap_put(wget_stringmap_t *h, const char *key, const void *value, size_t valuesize);
WGETAPI int
	wget_stringmap_put_noalloc(wget_stringmap_t *h, const char *key, const void *value);
//WGETAPI int
//	wget_stringmap_put_ident(WGET_STRINGMAP *h, const char *key);
//WGETAPI int
//	wget_stringmap_put_ident_noalloc(WGET_STRINGMAP *h, const char *key);
WGETAPI int
	wget_stringmap_size(const wget_stringmap_t *h) G_GNUC_WGET_PURE;
WGETAPI int
	wget_stringmap_browse(const wget_stringmap_t *h, wget_stringmap_browse_t browse, void *ctx) G_GNUC_WGET_NONNULL((2));
WGETAPI void
	wget_stringmap_free(wget_stringmap_t **h);
WGETAPI void
	wget_stringmap_clear(wget_stringmap_t *h);
WGETAPI void *
	wget_stringmap_get(const wget_stringmap_t *h, const char *key);
WGETAPI int
	wget_stringmap_get_null(const wget_stringmap_t *h, const char *key, void **value);
WGETAPI int
	wget_stringmap_contains(const wget_stringmap_t *h, const char *key);
WGETAPI int
	wget_stringmap_remove(wget_stringmap_t *h, const char *key);
WGETAPI int
	wget_stringmap_remove_nofree(wget_stringmap_t *h, const char *key);
WGETAPI void
	wget_stringmap_setcmpfunc(wget_stringmap_t *h, wget_stringmap_compare_t cmp);
WGETAPI void
	wget_stringmap_sethashfunc(wget_stringmap_t *h, wget_stringmap_hash_t hash);
WGETAPI void
	wget_stringmap_setloadfactor(wget_stringmap_t *h, float factor);
WGETAPI void
	wget_stringmap_set_value_destructor(wget_hashmap_t *h, wget_stringmap_value_destructor_t destructor);

/*
 * Thread wrapper routines
 */

#if USE_POSIX_THREADS || USE_PTH_THREADS
# define WGET_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
# define WGET_THREAD_COND_INITIALIZER PTHREAD_COND_INITIALIZER
typedef pthread_t wget_thread_t;
typedef pthread_mutex_t wget_thread_mutex_t;
typedef pthread_cond_t wget_thread_cond_t;
#else
# define WGET_THREAD_MUTEX_INITIALIZER 0
# define WGET_THREAD_COND_INITIALIZER 0
typedef unsigned long int wget_thread_t;
typedef int wget_thread_mutex_t;
typedef int wget_thread_cond_t;
#endif

WGETAPI int
	wget_thread_start(wget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags);
WGETAPI int
	wget_thread_mutex_init(wget_thread_mutex_t *mutex);
WGETAPI void
	wget_thread_mutex_lock(wget_thread_mutex_t *);
WGETAPI void
	wget_thread_mutex_unlock(wget_thread_mutex_t *);
WGETAPI int
	wget_thread_kill(wget_thread_t thread, int sig);
WGETAPI int
	wget_thread_cancel(wget_thread_t thread);
WGETAPI int
	wget_thread_join(wget_thread_t thread);
WGETAPI int
	wget_thread_cond_init(wget_thread_cond_t *cond);
WGETAPI int
	wget_thread_cond_signal(wget_thread_cond_t *cond);
WGETAPI int
	wget_thread_cond_wait(wget_thread_cond_t *cond, wget_thread_mutex_t *mutex, long long ms);
WGETAPI wget_thread_t
	wget_thread_self(void) G_GNUC_WGET_CONST;
WGETAPI bool
	wget_thread_support(void) G_GNUC_WGET_CONST;

/*
 * Decompressor routines
 */

typedef struct _wget_decompressor_st wget_decompressor_t;
typedef int (*wget_decompressor_sink_t)(void *context, const char *data, size_t length);
typedef int (*wget_decompressor_error_handler_t)(wget_decompressor_t *dc, int err);

enum {
	wget_content_encoding_identity,
	wget_content_encoding_gzip,
	wget_content_encoding_deflate,
	wget_content_encoding_lzma,
	wget_content_encoding_bzip2,
	wget_content_encoding_brotli,
};

WGETAPI wget_decompressor_t *
	wget_decompress_open(int encoding, wget_decompressor_sink_t data_sink, void *context);
WGETAPI void
	wget_decompress_close(wget_decompressor_t *dc);
WGETAPI int
	wget_decompress(wget_decompressor_t *dc, char *src, size_t srclen);
WGETAPI void
	wget_decompress_set_error_handler(wget_decompressor_t *dc, wget_decompressor_error_handler_t error_handler);
WGETAPI void *
	wget_decompress_get_context(wget_decompressor_t *dc);

/*
 * URI/IRI routines
 */

// TODO: i have to move this away from libwget.h
WGETAPI extern const char * const
	wget_iri_schemes[];

#define WGET_IRI_SCHEME_HTTP    (wget_iri_schemes[0])
#define WGET_IRI_SCHEME_HTTPS   (wget_iri_schemes[1])
#define WGET_IRI_SCHEME_FTP     (wget_iri_schemes[2])
#define WGET_IRI_SCHEME_DEFAULT WGET_IRI_SCHEME_HTTP

typedef struct wget_iri_st {
	const char *
		uri;      // pointer to original URI string, unescaped and converted to UTF-8
	const char *
		display;
	const char *
		scheme;
	const char *
		userinfo;
	const char *
		password;
	const char *
		host; // unescaped, toASCII converted, lowercase host (or IP address) part
	const char *
		port;
	const char *
		resolv_port;
	const char *
		path; // unescaped path part or NULL
	const char *
		query; // unescaped query part or NULL
	const char *
		fragment; // unescaped fragment part or NULL
	const char *
		connection_part; // helper, e.g. http://www.example.com:8080
	size_t
		dirlen; // length of directory part in 'path' (needed/initialized with --no-parent)
	unsigned int
		host_allocated : 1; // if set, free host in iri_free()
	unsigned int
		path_allocated : 1; // if set, free path in iri_free()
	unsigned int
		query_allocated : 1; // if set, free query in iri_free()
	unsigned int
		fragment_allocated : 1; // if set, free fragment in iri_free()
	unsigned int
		is_ip_address : 1; // if set, the hostname part is a literal IPv4 or IPv6 address
} wget_iri_t;

WGETAPI void
	wget_iri_test(void);
WGETAPI void
	wget_iri_free(wget_iri_t **iri);
WGETAPI void
	wget_iri_free_content(wget_iri_t *iri);
WGETAPI void
	wget_iri_set_defaultpage(const char *page);
WGETAPI int
	wget_iri_supported(const wget_iri_t *iri) G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL_ALL;
WGETAPI int
	wget_iri_isgendelim(char c) G_GNUC_WGET_CONST;
WGETAPI int
	wget_iri_issubdelim(char c) G_GNUC_WGET_CONST;
WGETAPI int
	wget_iri_isreserved(char c) G_GNUC_WGET_CONST;
WGETAPI int
	wget_iri_isunreserved(char c) G_GNUC_WGET_CONST;
WGETAPI int
	wget_iri_isunreserved_path(char c) G_GNUC_WGET_CONST;
WGETAPI int
	wget_iri_compare(wget_iri_t *iri1, wget_iri_t *iri2) G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL_ALL;
WGETAPI char *
	wget_iri_unescape_inline(char *src) G_GNUC_WGET_NONNULL_ALL;
WGETAPI wget_iri_t *
	wget_iri_parse(const char *uri, const char *encoding);
WGETAPI wget_iri_t *
	wget_iri_parse_base(wget_iri_t *base, const char *url, const char *encoding);
WGETAPI wget_iri_t *
	wget_iri_clone(wget_iri_t *iri);
WGETAPI const char *
	wget_iri_get_connection_part(wget_iri_t *iri);
WGETAPI const char *
	wget_iri_relative_to_abs(wget_iri_t *base, const char *val, size_t len, wget_buffer_t *buf);
WGETAPI const char *
	wget_iri_escape(const char *src, wget_buffer_t *buf);
WGETAPI const char *
	wget_iri_escape_path(const char *src, wget_buffer_t *buf) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_iri_escape_query(const char *src, wget_buffer_t *buf) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_iri_get_escaped_host(const wget_iri_t *iri, wget_buffer_t *buf) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_iri_get_escaped_resource(const wget_iri_t *iri, wget_buffer_t *buf) G_GNUC_WGET_NONNULL_ALL;
WGETAPI char *
	wget_iri_get_path(const wget_iri_t *iri, wget_buffer_t *buf, const char *encoding) G_GNUC_WGET_NONNULL((1,2));
WGETAPI char *
	wget_iri_get_query_as_filename(const wget_iri_t *iri, wget_buffer_t *buf, const char *encoding) G_GNUC_WGET_NONNULL((1,2));
WGETAPI char *
	wget_iri_get_filename(const wget_iri_t *iri, wget_buffer_t *buf, const char *encoding) G_GNUC_WGET_NONNULL((1,2));
WGETAPI const char *
	wget_iri_set_scheme(wget_iri_t *iri, const char *scheme);

/*
 * Cookie routines
 */

// typedef for cookie database
typedef struct wget_cookie_db_st wget_cookie_db_t;

// typedef for cookie
typedef struct wget_cookie_st wget_cookie_t;

WGETAPI wget_cookie_t *
	wget_cookie_init(wget_cookie_t *cookie);
WGETAPI void
	wget_cookie_deinit(wget_cookie_t *cookie);
WGETAPI void
	wget_cookie_free(wget_cookie_t **cookie);
WGETAPI char *
	wget_cookie_to_setcookie(wget_cookie_t *cookie);
WGETAPI const char *
	wget_cookie_parse_setcookie(const char *s, wget_cookie_t **cookie) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_cookie_normalize_cookies(const wget_iri_t *iri, const wget_vector_t *cookies);
WGETAPI int
	wget_cookie_store_cookie(wget_cookie_db_t *cookie_db, wget_cookie_t *cookie);
WGETAPI void
	wget_cookie_store_cookies(wget_cookie_db_t *cookie_db, wget_vector_t *cookies);
WGETAPI int
	wget_cookie_normalize(const wget_iri_t *iri, wget_cookie_t *cookie);
WGETAPI int
	wget_cookie_check_psl(const wget_cookie_db_t *cookie_db, const wget_cookie_t *cookie);
WGETAPI wget_cookie_db_t *
	wget_cookie_db_init(wget_cookie_db_t *cookie_db);
WGETAPI void
	wget_cookie_db_deinit(wget_cookie_db_t *cookie_db);
WGETAPI void
	wget_cookie_db_free(wget_cookie_db_t **cookie_db);
WGETAPI void
	wget_cookie_set_keep_session_cookies(wget_cookie_db_t *cookie_db, int keep);
WGETAPI int
	wget_cookie_db_save(wget_cookie_db_t *cookie_db, const char *fname);
WGETAPI int
	wget_cookie_db_load(wget_cookie_db_t *cookie_db, const char *fname);
WGETAPI int
	wget_cookie_db_load_psl(wget_cookie_db_t *cookie_db, const char *fname);
WGETAPI char *
	wget_cookie_create_request_header(wget_cookie_db_t *cookie_db, const wget_iri_t *iri);

/*
 * HTTP Strict Transport Security (HSTS) routines
 */

// structure for HTTP Strict Transport Security (HSTS) entries
typedef struct _wget_hsts_st wget_hsts_t;
typedef struct _wget_hsts_db_st wget_hsts_db_t;

WGETAPI wget_hsts_t *
	wget_hsts_init(wget_hsts_t *hsts);
WGETAPI void
	wget_hsts_deinit(wget_hsts_t *hsts);
WGETAPI void
	wget_hsts_free(wget_hsts_t *hsts);
WGETAPI wget_hsts_t *
	wget_hsts_new(const char *host, int port, time_t maxage, int include_subdomains);
WGETAPI int
	wget_hsts_host_match(const wget_hsts_db_t *hsts_db, const char *host, int port);
WGETAPI wget_hsts_db_t *
	wget_hsts_db_init(wget_hsts_db_t *hsts_db);
WGETAPI void
	wget_hsts_db_deinit(wget_hsts_db_t *hsts_db);
WGETAPI void
	wget_hsts_db_free(wget_hsts_db_t **hsts_db);
WGETAPI void
	wget_hsts_db_add(wget_hsts_db_t *hsts_db, wget_hsts_t *hsts);
WGETAPI int
	wget_hsts_db_save(wget_hsts_db_t *hsts_db, const char *fname);
WGETAPI int
	wget_hsts_db_load(wget_hsts_db_t *hsts_db, const char *fname);

/*
 * HTTP Public Key Pinning (HPKP)
 */
typedef struct _wget_hpkp_db_st wget_hpkp_db_t;
typedef struct _wget_hpkp_st wget_hpkp_t;
//typedef struct _wget_hpkp_pin_st wget_hpkp_pin_t;

/* FIXME this doesn't work */
/**
 * \addtogroup libwget-hpkp
 * Return values
 * @{
 */
#define WGET_HPKP_OK			 0
#define WGET_HPKP_ERROR			-1
#define WGET_HPKP_ENTRY_EXPIRED		-2
#define WGET_HPKP_WAS_DELETED		-3
#define WGET_HPKP_NOT_ENOUGH_PINS	-4
#define WGET_HPKP_ENTRY_EXISTS		-5
#define WGET_HPKP_ERROR_FILE_OPEN	-6
/* @} */

WGETAPI wget_hpkp_t *
	wget_hpkp_new(void);
WGETAPI void
	wget_hpkp_free(wget_hpkp_t *hpkp);
WGETAPI void
	wget_hpkp_pin_add(wget_hpkp_t *hpkp, const char *pin_type, const char *pin_b64);
WGETAPI void
	wget_hpkp_set_host(wget_hpkp_t *hpkp, const char *host);
WGETAPI void
	wget_hpkp_set_maxage(wget_hpkp_t *hpkp, time_t maxage);
WGETAPI void
	wget_hpkp_set_include_subdomains(wget_hpkp_t *hpkp, int include_subdomains);
WGETAPI wget_hpkp_db_t *
	wget_hpkp_db_init(wget_hpkp_db_t *hpkp_db);
WGETAPI void
	wget_hpkp_db_deinit(wget_hpkp_db_t *hpkp_db);
WGETAPI void
	wget_hpkp_db_free(wget_hpkp_db_t **hpkp_db);
WGETAPI int
	wget_hpkp_db_check_pubkey(wget_hpkp_db_t *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize);
WGETAPI void
	wget_hpkp_db_add(wget_hpkp_db_t *hpkp_db, wget_hpkp_t **hpkp);
WGETAPI int
	wget_hpkp_db_load(wget_hpkp_db_t *hpkp_db, const char *fname);
WGETAPI int
	wget_hpkp_db_save(wget_hpkp_db_t *hpkp_db, const char *fname);

/*
 * TLS session resumption
 */

// structure for TLS resumption cache entries
typedef struct _wget_tls_session_st wget_tls_session_t;
typedef struct _wget_tls_session_db_st wget_tls_session_db_t;

WGETAPI wget_tls_session_t *
	wget_tls_session_init(wget_tls_session_t *tls_session);
WGETAPI void
	wget_tls_session_deinit(wget_tls_session_t *tls_session);
WGETAPI void
	wget_tls_session_free(wget_tls_session_t *tls_session);
WGETAPI wget_tls_session_t *
	wget_tls_session_new(const char *host, time_t maxage, const void *data, size_t data_size);
WGETAPI int
	wget_tls_session_get(const wget_tls_session_db_t *tls_session_db, const char *host, void **data, size_t *size);
WGETAPI wget_tls_session_db_t *
	wget_tls_session_db_init(wget_tls_session_db_t *tls_session_db);
WGETAPI void
	wget_tls_session_db_deinit(wget_tls_session_db_t *tls_session_db);
WGETAPI void
	wget_tls_session_db_free(wget_tls_session_db_t **tls_session_db);
WGETAPI void
	wget_tls_session_db_add(wget_tls_session_db_t *tls_session_db, wget_tls_session_t *tls_session);
WGETAPI int
	wget_tls_session_db_save(wget_tls_session_db_t *tls_session_db, const char *fname);
WGETAPI int
	wget_tls_session_db_load(wget_tls_session_db_t *tls_session_db, const char *fname);
WGETAPI int
	wget_tls_session_db_changed(wget_tls_session_db_t *tls_session_db) G_GNUC_WGET_PURE;

/*
 * Online Certificate Status Protocol (OCSP) routines
 */

// structure for Online Certificate Status Protocol (OCSP) entries
typedef struct _wget_ocsp_st wget_ocsp_t;
typedef struct _wget_ocsp_db_st wget_ocsp_db_t;

WGETAPI wget_ocsp_t *
	wget_ocsp_init(wget_ocsp_t *ocsp);
WGETAPI void
	wget_ocsp_deinit(wget_ocsp_t *ocsp);
WGETAPI void
	wget_ocsp_free(wget_ocsp_t *ocsp);
WGETAPI wget_ocsp_t *
	wget_ocsp_new(const char *fingerprint, time_t maxage, int valid);
WGETAPI int
	wget_ocsp_fingerprint_in_cache(const wget_ocsp_db_t *ocsp_db, const char *fingerprint, int *valid);
WGETAPI int
	wget_ocsp_hostname_is_valid(const wget_ocsp_db_t *ocsp_db, const char *fingerprint);
WGETAPI wget_ocsp_db_t *
	wget_ocsp_db_init(wget_ocsp_db_t *ocsp_db);
WGETAPI void
	wget_ocsp_db_deinit(wget_ocsp_db_t *ocsp_db);
WGETAPI void
	wget_ocsp_db_free(wget_ocsp_db_t **ocsp_db);
WGETAPI void
	wget_ocsp_db_add_fingerprint(wget_ocsp_db_t *ocsp_db, wget_ocsp_t *ocsp);
WGETAPI void
	wget_ocsp_db_add_host(wget_ocsp_db_t *ocsp_db, wget_ocsp_t *ocsp);
WGETAPI int
	wget_ocsp_db_save(wget_ocsp_db_t *ocsp_db, const char *fname);
WGETAPI int
	wget_ocsp_db_load(wget_ocsp_db_t *ocsp_db, const char *fname);

/*
 * .netrc routines
 */

// structure for .netrc entries
typedef struct _wget_netrc_db_st wget_netrc_db_t;
typedef struct {
	const char *
		host;
	const char *
		login;
	const char *
		password;
} wget_netrc_t;

WGETAPI wget_netrc_t *
	wget_netrc_init(wget_netrc_t *netrc);
WGETAPI void
	wget_netrc_deinit(wget_netrc_t *netrc);
WGETAPI void
	wget_netrc_free(wget_netrc_t *netrc);
WGETAPI wget_netrc_t *
	wget_netrc_new(const char *machine, const char *login, const char *password);
WGETAPI wget_netrc_db_t *
	wget_netrc_db_init(wget_netrc_db_t *netrc_db);
WGETAPI void
	wget_netrc_db_deinit(wget_netrc_db_t *netrc_db);
WGETAPI void
	wget_netrc_db_free(wget_netrc_db_t **netrc_db);
WGETAPI void
	wget_netrc_db_add(wget_netrc_db_t *netrc_db, wget_netrc_t *netrc);
WGETAPI wget_netrc_t *
	wget_netrc_get(const wget_netrc_db_t *netrc_db, const char *host);
WGETAPI int
	wget_netrc_db_load(wget_netrc_db_t *netrc_db, const char *fname);

/*
 * CSS parsing routines
 */

typedef struct {
	size_t
		len;
	size_t
		pos;
	const char *
		url;
	const char *
		abs_url;
} WGET_PARSED_URL;

typedef void (*wget_css_parse_uri_cb_t)(void *user_ctx, const char *url, size_t len, size_t pos);
typedef void (*wget_css_parse_encoding_cb_t)(void *user_ctx, const char *url, size_t len);

WGETAPI void
	wget_css_parse_buffer(
		const char *buf,
		size_t len,
		wget_css_parse_uri_cb_t callback_uri,
		wget_css_parse_encoding_cb_t callback_encoding,
		void *user_ctx) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_css_parse_file(
		const char *fname,
		wget_css_parse_uri_cb_t callback_uri,
		wget_css_parse_encoding_cb_t callback_encoding,
		void *user_ctx) G_GNUC_WGET_NONNULL((1));
WGETAPI wget_vector_t *
	wget_css_get_urls(
		const char *css,
		size_t len,
		wget_iri_t *base,
		const char **encoding) G_GNUC_WGET_NONNULL((1));
WGETAPI wget_vector_t *
	wget_css_get_urls_from_localfile(
		const char *fname,
		wget_iri_t *base,
		const char **encoding) G_GNUC_WGET_NONNULL((1));

typedef struct {
	const char
		*p;
	size_t
		len;
} wget_string_t;

typedef struct {
	wget_string_t
		url;
	char
		attr[16];
	char
		dir[16];
	unsigned char
		link_inline : 1; // 1 = rel was 'stylesheet' or 'shortcut icon'
} WGET_HTML_PARSED_URL;

typedef struct {
	wget_vector_t
		*uris;
	const char *
		encoding;
	wget_string_t
		base;
	unsigned char
		follow : 1;
} WGET_HTML_PARSED_RESULT;

typedef struct {
	const char *
		name;
	const char *
		attribute;
} wget_html_tag_t;

WGETAPI WGET_HTML_PARSED_RESULT *
	wget_html_get_urls_inline(const char *html, wget_vector_t *additional_tags, wget_vector_t *ignore_tags);
WGETAPI void
	wget_html_free_urls_inline(WGET_HTML_PARSED_RESULT **res);
WGETAPI void
	wget_sitemap_get_urls_inline(const char *sitemap, wget_vector_t **urls, wget_vector_t **sitemap_urls);
WGETAPI void
	wget_atom_get_urls_inline(const char *atom, wget_vector_t **urls);
WGETAPI void
	wget_rss_get_urls_inline(const char *rss, wget_vector_t **urls);

/*
 * XML and HTML parsing routines
 */

#define XML_FLG_BEGIN      (1<<0) // <
#define XML_FLG_CLOSE      (1<<1) // >
#define XML_FLG_END        (1<<2) // </elem>
#define XML_FLG_ATTRIBUTE  (1<<3) // attr="value"
#define XML_FLG_CONTENT    (1<<4)
#define XML_FLG_COMMENT    (1<<5) // <!-- ... -->
//#define XML_FLG_CDATA      (1<<6) // <![CDATA[...]]>, now same handling as 'special'
#define XML_FLG_PROCESSING (1<<7) // e.g. <? ... ?>
#define XML_FLG_SPECIAL    (1<<8) // e.g. <!DOCTYPE ...>

#define XML_HINT_REMOVE_EMPTY_CONTENT (1<<0) // merge spaces, remove empty content
#define XML_HINT_HTML                 (1<<1) // parse HTML instead of XML

#define HTML_HINT_REMOVE_EMPTY_CONTENT XML_HINT_REMOVE_EMPTY_CONTENT

typedef void (*wget_xml_callback_t)(void *, int, const char *, const char *, const char *, size_t, size_t);

WGETAPI void
	wget_xml_parse_buffer(
		const char *buf,
		wget_xml_callback_t callback,
		void *user_ctx,
		int hints) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_xml_parse_file(
		const char *fname,
		wget_xml_callback_t callback,
		void *user_ctx,
		int hints) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_html_parse_buffer(
		const char *buf,
		wget_xml_callback_t callback,
		void *user_ctx,
		int hints) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_html_parse_file(
		const char *fname,
		wget_xml_callback_t callback,
		void *user_ctx,
		int hints) G_GNUC_WGET_NONNULL((1));

/*
 * TCP network routines
 */

#define WGET_NET_FAMILY_ANY  0
#define WGET_NET_FAMILY_IPV4 1
#define WGET_NET_FAMILY_IPV6 2

#define WGET_PROTOCOL_HTTP_1_1  0
#define WGET_PROTOCOL_HTTP_2_0  1

typedef struct wget_tcp_st wget_tcp_t;

WGETAPI int
	wget_net_init(void);
WGETAPI int
	wget_net_deinit(void);
WGETAPI wget_tcp_t *
	wget_tcp_init(void);
WGETAPI void
	wget_tcp_deinit(wget_tcp_t **tcp);
WGETAPI void
	wget_dns_cache_free(void);
WGETAPI void
	wget_tcp_close(wget_tcp_t *tcp);
WGETAPI void
	wget_tcp_set_timeout(wget_tcp_t *tcp, int timeout);
WGETAPI int
	wget_tcp_get_timeout(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI void
	wget_tcp_set_connect_timeout(wget_tcp_t *tcp, int timeout);
WGETAPI void
	wget_tcp_set_dns_timeout(wget_tcp_t *tcp, int timeout);
WGETAPI void
	wget_tcp_set_dns_caching(wget_tcp_t *tcp, int caching);
WGETAPI void
	wget_tcp_set_tcp_fastopen(wget_tcp_t *tcp, int tcp_fastopen);
WGETAPI void
	wget_tcp_set_tls_false_start(wget_tcp_t *tcp, int false_start);
WGETAPI void
	wget_tcp_set_ssl(wget_tcp_t *tcp, int ssl);
WGETAPI int
	wget_tcp_get_ssl(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI void
	wget_tcp_set_ssl_hostname(wget_tcp_t *tcp, const char *hostname);
WGETAPI const char *
	wget_tcp_get_ssl_hostname(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI void
	wget_tcp_set_ssl_ca_file(wget_tcp_t *tcp, const char *cafile);
WGETAPI void
	wget_tcp_set_ssl_key_file(wget_tcp_t *tcp, const char *certfile, const char *keyfile);
WGETAPI int
	wget_tcp_get_dns_caching(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI int
	wget_tcp_get_tcp_fastopen(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI int
	wget_tcp_get_tls_false_start(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI int
	wget_tcp_get_family(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI int
	wget_tcp_get_preferred_family(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI int
	wget_tcp_get_protocol(wget_tcp_t *tcp) G_GNUC_WGET_PURE;
WGETAPI int
	wget_tcp_get_local_port(wget_tcp_t *tcp);
WGETAPI void
	wget_tcp_set_debug(wget_tcp_t *tcp, int debug);
WGETAPI void
	wget_tcp_set_family(wget_tcp_t *tcp, int family);
WGETAPI void
	wget_tcp_set_preferred_family(wget_tcp_t *tcp, int family);
WGETAPI void
	wget_tcp_set_protocol(wget_tcp_t *tcp, int protocol);
WGETAPI void
	wget_tcp_set_bind_address(wget_tcp_t *tcp, const char *bind_address);
WGETAPI struct addrinfo *
	wget_tcp_resolve(wget_tcp_t *tcp, const char *restrict name, const char *restrict port) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_tcp_connect(wget_tcp_t *tcp, const char *host, const char *port) G_GNUC_WGET_NONNULL((1));
WGETAPI int
	wget_tcp_listen(wget_tcp_t *tcp, const char *host, const char *port, int backlog) G_GNUC_WGET_NONNULL((1));
WGETAPI wget_tcp_t
	*wget_tcp_accept(wget_tcp_t *parent_tcp) G_GNUC_WGET_NONNULL((1));
WGETAPI int
	wget_tcp_tls_start(wget_tcp_t *tcp) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_tcp_tls_stop(wget_tcp_t *tcp) G_GNUC_WGET_NONNULL((1));
WGETAPI ssize_t
	wget_tcp_vprintf(wget_tcp_t *tcp, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_tcp_printf(wget_tcp_t *tcp, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(2,3) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_tcp_write(wget_tcp_t *tcp, const char *buf, size_t count) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_tcp_read(wget_tcp_t *tcp, char *buf, size_t count) G_GNUC_WGET_NONNULL_ALL;
WGETAPI int
	wget_tcp_ready_2_transfer(wget_tcp_t *tcp, int flags) G_GNUC_WGET_NONNULL_ALL;

WGETAPI int
	wget_ip_is_family(const char *host, int family) G_GNUC_WGET_PURE;

/*
 * SSL routines
 */

#define WGET_SSL_X509_FMT_PEM 0
#define WGET_SSL_X509_FMT_DER 1

#define WGET_SSL_SECURE_PROTOCOL   1
#define WGET_SSL_CA_DIRECTORY      2
#define WGET_SSL_CA_FILE           3
#define WGET_SSL_CERT_FILE         4
#define WGET_SSL_KEY_FILE          5
#define WGET_SSL_CA_TYPE           6
#define WGET_SSL_CERT_TYPE         7
#define WGET_SSL_KEY_TYPE          8
#define WGET_SSL_CHECK_CERTIFICATE 9
#define WGET_SSL_CHECK_HOSTNAME    10
#define WGET_SSL_PRINT_INFO        11
#define WGET_SSL_DIRECT_OPTIONS    12
#define WGET_SSL_CRL_FILE          13
#define WGET_SSL_OCSP_STAPLING     14
#define WGET_SSL_OCSP_SERVER       15
#define WGET_SSL_OCSP              16
#define WGET_SSL_OCSP_CACHE        17
#define WGET_SSL_ALPN              18
#define WGET_SSL_SESSION_CACHE     19
#define WGET_SSL_HPKP_CACHE     20

WGETAPI void
	wget_ssl_init(void);
WGETAPI void
	wget_ssl_deinit(void);
WGETAPI void
	wget_ssl_set_config_string(int key, const char *value);
WGETAPI void
	wget_ssl_set_config_int(int key, int value);
//WGETAPI void *
//	wget_ssl_open(int sockfd, const char *hostname, int connect_timeout) G_GNUC_WGET_NONNULL((2));
WGETAPI int
	wget_ssl_open(wget_tcp_t *tcp);
WGETAPI void
	wget_ssl_close(void **session);
WGETAPI void
	wget_ssl_set_check_certificate(char value);
WGETAPI void
	wget_ssl_server_init(void);
WGETAPI void
	wget_ssl_server_deinit(void);
WGETAPI int
	wget_ssl_server_open(wget_tcp_t *tcp);
WGETAPI void
	wget_ssl_server_close(void **session);
WGETAPI ssize_t
	wget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout) G_GNUC_WGET_NONNULL_ALL;

/*
 * HTTP routines
 */

typedef struct {
	const char *
		name;
	const char *
		value;
} wget_http_header_param_t;

typedef struct {
	const char *
		uri;
	const char *
		type;
	int
		pri;
	enum {
		link_rel_describedby,
		link_rel_duplicate
	} rel;
} wget_http_link_t;

typedef struct {
	const char *
		algorithm;
	const char *
		encoded_digest;
} wget_http_digest_t;

typedef struct {
	const char *
		auth_scheme;
	wget_stringmap_t *
		params;
} wget_http_challenge_t;

enum {
	transfer_encoding_identity,
	transfer_encoding_chunked
};

typedef struct wget_http_response_t wget_http_response_t;
typedef int (*wget_http_header_callback_t)(wget_http_response_t *, void *);
typedef int (*wget_http_body_callback_t)(wget_http_response_t *, void *, const char *, size_t);

// keep the request as simple as possible
typedef struct {
	wget_vector_t *
		headers;
	const char *
		scheme;
	const char *
		body;
	wget_http_header_callback_t
		header_callback; // called after HTTP header has been received
	wget_http_body_callback_t
		body_callback; // called for each body data packet received
	void *
		user_data;
	void *
		header_user_data; // meant to be used in header callback function
	void *
		body_user_data; // meant to be used in body callback function
	wget_buffer_t
		esc_resource; // URI escaped resource
	wget_buffer_t
		esc_host; // URI escaped host
	size_t
		body_length;
	int32_t
		stream_id; // HTTP2 stream id
	char
		esc_resource_buf[256];
	char
		esc_host_buf[64];
	char
		method[8]; // we just need HEAD, GET and POST
	unsigned char
		response_keepheader : 1;
} wget_http_request_t;

// just parse the header lines that we need
struct wget_http_response_t {
	wget_http_request_t *
		req;
	wget_vector_t *
		links;
	wget_vector_t *
		digests;
	wget_vector_t *
		cookies;
	wget_vector_t *
		challenges;
	wget_hpkp_t *
		hpkp;
	const char *
		content_type;
	const char *
		content_type_encoding;
	const char *
		content_filename;
	const char *
		location;
	const char *
		etag;
	wget_buffer_t *
		header;
	wget_buffer_t *
		body;
	size_t
		content_length;
	time_t
		last_modified;
	time_t
		hsts_maxage;
	char
		reason[32];
	int
		icy_metaint;
	short
		major;
	short
		minor;
	short
		code; // request only status code
	char
		transfer_encoding,
		content_encoding,
		content_length_valid,
		keep_alive;
	char
		hsts_include_subdomains;
	unsigned char
		hsts : 1; // if hsts_maxage and hsts_include_subdomains are valid
	size_t
		cur_downloaded;
};

typedef struct {
	wget_tcp_t *
		tcp;
	const char *
		esc_host;
	const char *
		port;
	const char *
		scheme;
	wget_buffer_t *
		buf;
#ifdef WITH_LIBNGHTTP2
	nghttp2_session *
		http2_session;
#endif
	wget_vector_t
		*pending_requests; // List of unresponsed requests (HTTP1 only)
	wget_vector_t
		*received_http2_responses; // List of received (but yet unprocessed) responses (HTTP2 only)
	int
		pending_http2_requests; // Number of unresponsed requests (HTTP2 only)
	char
		protocol; // WGET_PROTOCOL_HTTP_1_1 or WGET_PROTOCOL_HTTP_2_0
	unsigned char
		print_response_headers : 1,
		abort_indicator : 1,
		proxied : 1;
} wget_http_connection_t;

WGETAPI int
	wget_http_isseparator(char c) G_GNUC_WGET_CONST;
WGETAPI int
	wget_http_istoken(char c) G_GNUC_WGET_CONST;

WGETAPI const char *
	wget_http_parse_token(const char *s, const char **token) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_quoted_string(const char *s, const char **qstring) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_param(const char *s, const char **param, const char **value) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_name(const char *s, const char **name) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_parse_name_fixed(const char *s, const char **name, size_t *namelen) G_GNUC_WGET_NONNULL_ALL;
WGETAPI time_t
	wget_http_parse_full_date(const char *s) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_link(const char *s, wget_http_link_t *link) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_digest(const char *s, wget_http_digest_t *digest) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_challenge(const char *s, wget_http_challenge_t *challenge) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_challenges(const char *s, wget_vector_t *challenges) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_location(const char *s, const char **location) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_transfer_encoding(const char *s, char *transfer_encoding) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_content_type(const char *s, const char **content_type, const char **charset) G_GNUC_WGET_NONNULL((1));
WGETAPI const char *
	wget_http_parse_content_encoding(const char *s, char *content_encoding) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_content_disposition(const char *s, const char **filename) G_GNUC_WGET_NONNULL((1));
WGETAPI const char *
	wget_http_parse_strict_transport_security(const char *s, time_t *maxage, char *include_subdomains) G_GNUC_WGET_NONNULL((1));
WGETAPI const char *
	wget_http_parse_public_key_pins(const char *s, wget_hpkp_t *hpkp) G_GNUC_WGET_NONNULL((1));
WGETAPI const char *
	wget_http_parse_connection(const char *s, char *keep_alive) G_GNUC_WGET_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_setcookie(const char *s, wget_cookie_t **cookie) G_GNUC_WGET_NONNULL((1));
WGETAPI const char *
	wget_http_parse_etag(const char *s, const char **etag) G_GNUC_WGET_NONNULL((1));

WGETAPI char *
	wget_http_print_date(time_t t, char *buf, size_t bufsize) G_GNUC_WGET_NONNULL_ALL;

WGETAPI void
	wget_http_add_param(wget_vector_t **params, wget_http_header_param_t *param) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_add_header_vprintf(wget_http_request_t *req, const char *name, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(3,0) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_add_header_printf(wget_http_request_t *req, const char *name, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(3,4) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_add_header(wget_http_request_t *req, const char *name, const char *value) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_add_header_param(wget_http_request_t *req, wget_http_header_param_t *param) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_add_credentials(wget_http_request_t *req, wget_http_challenge_t *challenge, const char *username, const char *password) G_GNUC_WGET_NONNULL((1));
WGETAPI int
	wget_http_set_http_proxy(const char *proxy, const char *encoding);
WGETAPI int
	wget_http_set_https_proxy(const char *proxy, const char *encoding);
WGETAPI int
	wget_http_set_no_proxy(const char *no_proxy, const char *encoding);
WGETAPI int
	wget_http_match_no_proxy(wget_vector_t *no_proxies, const char *host);
WGETAPI void
	wget_http_abort_connection(wget_http_connection_t *conn);

WGETAPI int
	wget_http_free_param(wget_http_header_param_t *param);
WGETAPI void
	wget_http_free_cookie(wget_cookie_t *cookie);
WGETAPI void
	wget_http_free_digest(wget_http_digest_t *digest);
WGETAPI void
	wget_http_free_challenge(wget_http_challenge_t *challenge);
WGETAPI void
	wget_http_free_link(wget_http_link_t *link);

WGETAPI void
	wget_http_free_cookies(wget_vector_t **cookies);
WGETAPI void
	wget_http_free_hpkp_entries(wget_hpkp_t **hpkp);
WGETAPI void
	wget_http_free_digests(wget_vector_t **digests);
WGETAPI void
	wget_http_free_challenges(wget_vector_t **challenges);
WGETAPI void
	wget_http_free_links(wget_vector_t **links);
//WGETAPI void
//	wget_http_free_header(HTTP_HEADER **header);
WGETAPI void
	wget_http_free_request(wget_http_request_t **req);
WGETAPI void
	wget_http_free_response(wget_http_response_t **resp);

WGETAPI wget_http_response_t *
	wget_http_read_header(const wget_iri_t *iri) G_GNUC_WGET_NONNULL_ALL;
WGETAPI wget_http_response_t *
	wget_http_get_header(wget_iri_t *iri) G_GNUC_WGET_NONNULL_ALL;
WGETAPI wget_http_response_t *
	wget_http_parse_response_header(char *buf) G_GNUC_WGET_NONNULL_ALL;
WGETAPI wget_http_response_t *
	wget_http_get_response_cb(wget_http_connection_t *conn) G_GNUC_WGET_NONNULL((1));
//WGETAPI HTTP_RESPONSE *
//	http_get_response_mem(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL_ALL;
WGETAPI wget_http_response_t *
	wget_http_get_response(wget_http_connection_t *conn) G_GNUC_WGET_NONNULL((1));

WGETAPI int
	wget_http_open(wget_http_connection_t **_conn, const wget_iri_t *iri);
WGETAPI wget_http_request_t *
	wget_http_create_request(const wget_iri_t *iri, const char *method) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_close(wget_http_connection_t **conn) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_http_request_set_header_cb(wget_http_request_t *req, wget_http_header_callback_t cb, void *user_data) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_http_request_set_body_cb(wget_http_request_t *req, wget_http_body_callback_t cb, void *user_data) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_http_request_set_int(wget_http_request_t *req, int key, int value) G_GNUC_WGET_NONNULL((1));
WGETAPI int
	wget_http_request_get_int(wget_http_request_t *req, int key) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_http_request_set_ptr(wget_http_request_t *req, int key, void *value) G_GNUC_WGET_NONNULL((1));
WGETAPI void *
	wget_http_request_get_ptr(wget_http_request_t *req, int key) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_http_request_set_body(wget_http_request_t *req, const char *mimetype, char *body, size_t length) G_GNUC_WGET_NONNULL((1));
WGETAPI int
	wget_http_send_request(wget_http_connection_t *conn, wget_http_request_t *req) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_http_request_to_buffer(wget_http_request_t *req, wget_buffer_t *buf, int proxied) G_GNUC_WGET_NONNULL_ALL;

/*
 * Highlevel HTTP routines
 */

WGETAPI wget_http_response_t *
	wget_http_get(int first_key, ...) G_GNUC_WGET_NULL_TERMINATED;
WGETAPI wget_vector_t
	*wget_get_css_urls(const char *data);

/*
 * MD5 routines
 */

WGETAPI void
	wget_md5_printf_hex(char *digest_hex, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(2,3) G_GNUC_WGET_NONNULL_ALL;


/*
 * random routines
 */

int wget_random(void);
void wget_srandom(unsigned int seed);

/**
 * \ingroup libwget-hash
 * \brief Type for hash / digest routines
 */
typedef struct _wget_hash_hd_st wget_hash_hd_t;

/**
 * \ingroup libwget-hash
 * \brief Enumeration of different hash digest algorithms
 */
typedef enum {
	WGET_DIGTYPE_UNKNOWN, /**< Indicates 'Unknown hash algorithm', returned by wget_hash_get_algorithm() */
	WGET_DIGTYPE_MD5,     /**< Type 'MD5' digest */
	WGET_DIGTYPE_SHA1,    /**< Type SHA1 digest */
	WGET_DIGTYPE_RMD160,  /**< Type RMD160 digest */
	WGET_DIGTYPE_MD2,     /**< Type 'MD2' digest */
	WGET_DIGTYPE_SHA256,  /**< Type 'SHA256' digest */
	WGET_DIGTYPE_SHA384,  /**< Type 'SHA384' digest */
	WGET_DIGTYPE_SHA512,  /**< Type 'SHA512' digest */
	WGET_DIGTYPE_SHA224   /**< Type 'SHA224' digest */
} wget_digest_algorithm_t;

WGETAPI wget_digest_algorithm_t
	wget_hash_get_algorithm(const char *hashname);
WGETAPI int
	wget_hash_fast(wget_digest_algorithm_t algorithm, const void *text, size_t textlen, void *digest);
WGETAPI int
	wget_hash_get_len(wget_digest_algorithm_t algorithm) G_GNUC_WGET_CONST;
WGETAPI int
	wget_hash_init(wget_hash_hd_t *dig, wget_digest_algorithm_t algorithm);
WGETAPI int
	wget_hash(wget_hash_hd_t *handle, const void *text, size_t textlen);
WGETAPI void
	wget_hash_deinit(wget_hash_hd_t *handle, void *digest);

/*
 * Hash file routines
 */

WGETAPI int
	wget_hash_file_fd(const char *hashname, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) G_GNUC_WGET_NONNULL_ALL;
WGETAPI int
	wget_hash_file_offset(const char *hashname, const char *fname, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) G_GNUC_WGET_NONNULL_ALL;
WGETAPI int
	wget_hash_file(const char *hashname, const char *fname, char *digest_hex, size_t digest_hex_size) G_GNUC_WGET_NONNULL_ALL;

/*
 * Metalink types and routines
 */

typedef struct {
	wget_iri_t
		*iri;
	int
		priority;
	char
		location[8]; // location of the mirror, e.g. 'de', 'fr' or 'jp'
} wget_metalink_mirror_t;

typedef struct {
	char
		type[16], // type of hash, e.g. 'MD5' or 'SHA-256'
		hash_hex[128+1]; // hash value as HEX string
} wget_metalink_hash_t;

// Metalink piece, for checksumming after download
typedef struct {
	wget_metalink_hash_t
		hash;
	off_t
		position;
	off_t
		length;
} wget_metalink_piece_t;

typedef struct {
	const char
		*name;
	wget_vector_t
		*mirrors,
		*hashes, // checksums of complete file
		*pieces; // checksums of smaller pieces of the file
	off_t
		size; // total size of the file
} wget_metalink_t;

WGETAPI wget_metalink_t
	*wget_metalink_parse(const char *xml) G_GNUC_WGET_NONNULL((1));
WGETAPI void
	wget_metalink_free(wget_metalink_t **metalink);
WGETAPI void
	wget_metalink_sort_mirrors(wget_metalink_t *metalink);

/*
 * Robots types and routines
 */

typedef struct {
	const char *
		path;
	size_t
		len;
} ROBOTS_PATH;

typedef struct ROBOTS {
	wget_vector_t
		*paths;
	wget_vector_t
		*sitemaps;
} ROBOTS;

WGETAPI ROBOTS *
	wget_robots_parse(const char *data, const char *client);
WGETAPI void
	wget_robots_free(ROBOTS **robots);

/*
 * Progress bar routines
 */

typedef struct _wget_bar_st wget_bar_t;

WGETAPI wget_bar_t *
	wget_bar_init(wget_bar_t *bar, int nslots);
WGETAPI void
	wget_bar_deinit(wget_bar_t *bar);
WGETAPI void
	wget_bar_free(wget_bar_t **bar);
WGETAPI void
	wget_bar_print(wget_bar_t *bar, int slot, const char *s);
WGETAPI ssize_t
	wget_bar_vprintf(wget_bar_t *bar, int slot, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(3,0) G_GNUC_WGET_NONNULL_ALL;
WGETAPI ssize_t
	wget_bar_printf(wget_bar_t *bar, int slot, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(3,4) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_bar_slot_begin(wget_bar_t *bar, int slot, const char *filename, ssize_t filesize) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_bar_slot_downloaded(wget_bar_t *bar, int slot, size_t nbytes);
WGETAPI void
	wget_bar_slot_deregister(wget_bar_t *bar, int slot) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_bar_update(wget_bar_t *bar) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_bar_set_slots(wget_bar_t *bar, int nslots) G_GNUC_WGET_NONNULL_ALL;
WGETAPI void
	wget_bar_screen_resized(void);
WGETAPI void
	wget_bar_write_line(wget_bar_t *bar, const char *buf, size_t len) G_GNUC_WGET_NONNULL_ALL;

/*
 * Console routines
 */

// console color definitions
typedef enum {
	WGET_CONSOLE_COLOR_RESET = 0,
	WGET_CONSOLE_COLOR_WHITE = 1,
	WGET_CONSOLE_COLOR_BLUE = 2,
	WGET_CONSOLE_COLOR_GREEN = 3,
	WGET_CONSOLE_COLOR_RED = 4,
	WGET_CONSOLE_COLOR_MAGENTA = 5
} wget_console_color_t;

WGETAPI int
	wget_console_init(void);
WGETAPI int
	wget_console_deinit(void);
WGETAPI void
	wget_console_set_fg_color(wget_console_color_t colorid);
WGETAPI void
	wget_console_reset_fg_color(void);

WGET_END_DECLS

#endif /* _LIBWGET_LIBWGET_H */
