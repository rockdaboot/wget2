/*
 * Copyright(c) 2012,2013,2014,1015 Tim Ruehsen
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for libmget library routines
 *
 * Changelog
 * 28.12.2012  Tim Ruehsen  created (moved mget.h and list.h and into here)
 *
 */

#ifndef _LIBMGET_LIBMGET_H
#define _LIBMGET_LIBMGET_H

#include <stddef.h>
#ifdef HAVE_LIBPTHREAD
#	include <pthread.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef HAVE_INTTYPES_H
#	include <inttypes.h>
#endif
#ifdef WITH_LIBNGHTTP2
	#include <nghttp2/nghttp2.h>
#endif

// transitional defines, remove when migration to libmget is done
#define xmalloc mget_malloc
#define xcalloc mget_calloc
#define xrealloc mget_realloc

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

#if GCC_VERSION_AT_LEAST(2,5)
#	define G_GNUC_MGET_CONST __attribute__ ((const))
#	define G_GNUC_MGET_NORETURN __attribute__ ((noreturn))
#else
#	define G_GNUC_MGET_CONST
#	define G_GNUC_MGET_NORETURN
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#	define G_GNUC_MGET_PRINTF_FORMAT(a, b) __attribute__ ((format (printf, a, b)))
#	define G_GNUC_MGET_UNUSED __attribute__ ((unused))
#else
#	define G_GNUC_MGET_PRINT_FORMAT(a, b)
#	define G_GNUC_MGET_UNUSED
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

#if GCC_VERSION_AT_LEAST(4,0)
#	define G_GNUC_MGET_NULL_TERMINATED __attribute__((__sentinel__))
#else
#	define G_GNUC_MGET_NULL_TERMINATED
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

// Let C++ include C headers
#ifdef  __cplusplus
#	define MGET_BEGIN_DECLS  extern "C" {
#	define MGET_END_DECLS    }
#else
#	define MGET_BEGIN_DECLS
#	define MGET_END_DECLS
#endif

// Include libintl.h before we redefine gettext stuff
#ifdef HAVE_LIBINTL_H
#	include <libintl.h>
#endif

#if ENABLE_NLS != 0
#	undef gettext
#	define _(STRING) gettext(STRING)
#else
#	undef ngettext
#	define _(STRING) STRING
#	define ngettext(STRING1,STRING2,N) STRING2
#endif

//#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901
//#	define restrict
//#endif

#undef GCC_VERSION_AT_LEAST

// we can prefix the exposed functions as we want
#ifndef _MGET_PREFIX
#	define _MGET_PREFIX mget_
#endif

MGET_BEGIN_DECLS

/*
 * Library initialization functions
 */

// Why not using enum ? Might result in different values if one entry is inserted.
// And that might break the ABI.
#define MGET_DEBUG_STREAM 1000
#define MGET_DEBUG_FUNC   1001
#define MGET_DEBUG_FILE   1002
#define MGET_ERROR_STREAM 1003
#define MGET_ERROR_FUNC   1004
#define MGET_ERROR_FILE   1005
#define MGET_INFO_STREAM  1006
#define MGET_INFO_FUNC    1007
#define MGET_INFO_FILE    1008
#define MGET_DNS_CACHING  1009
#define MGET_COOKIE_SUFFIXES 1010
#define MGET_COOKIES_ENABLED 1011
#define MGET_COOKIE_FILE 1012
#define MGET_COOKIE_DB 1013
#define MGET_COOKIE_KEEPSESSIONCOOKIES 1014
#define MGET_BIND_ADDRESS 1015
#define MGET_NET_FAMILY_EXCLUSIVE 1016
#define MGET_NET_FAMILY_PREFERRED 1017
#define MGET_TCP_FASTFORWARD  1018

#define MGET_HTTP_URL          2000
#define MGET_HTTP_URL_ENCODING 2001
#define MGET_HTTP_URI          2002
#define MGET_HTTP_COOKIE_STORE 2003
#define MGET_HTTP_HEADER_ADD   2004
//#define MGET_HTTP_HEADER_DEL   2005
//#define MGET_HTTP_HEADER_SET   2006
//#define MGET_HTTP_BIND_ADDRESS 2007
#define MGET_HTTP_CONNECTION_PTR 2008
#define MGET_HTTP_RESPONSE_KEEPHEADER 2009
#define MGET_HTTP_MAX_REDIRECTIONS 2010
#define MGET_HTTP_BODY_SAVEAS_STREAM 2011
#define MGET_HTTP_BODY_SAVEAS_FILE 2012
#define MGET_HTTP_BODY_SAVEAS_FD 2013
#define MGET_HTTP_BODY_SAVEAS_FUNC 2014
#define MGET_HTTP_HEADER_FUNC 2015

// definition of error conditions
#define MGET_E_SUCCESS 0 /* OK */
#define MGET_E_UNKNOWN -1 /* general error if nothing else appropriate */
#define MGET_E_INVALID -2 /* invalid value to function */
#define MGET_E_TIMEOUT -3 /* timeout condition */
#define MGET_E_CONNECT -4 /* connect failure */
#define MGET_E_HANDSHAKE -5 /* general TLS handshake failure */
#define MGET_E_CERTIFICATE -6 /* general TLS certificate failure */

void
	mget_global_init(int key, ...) G_GNUC_MGET_NULL_TERMINATED;
void
	mget_global_deinit(void);
const void *
	mget_global_get_ptr(int key);
int
	mget_global_get_int(int key);

/*
 * Utility functions
 */

/**
 * MGET_UTILITY:
 *
 * General utility functions
 */

// <mode> values for mget_ready_to_transfer()
#define MGET_IO_READABLE 1
#define MGET_IO_WRITABLE 2

int
	mget_ready_2_read(int fd, int timeout);
int
	mget_ready_2_write(int fd, int timeout);
int
	mget_ready_2_transfer(int fd, int timeout, short mode);
int
	mget_strcmp(const char *s1, const char *s2) G_GNUC_MGET_PURE;
int
	mget_strcasecmp(const char *s1, const char *s2) G_GNUC_MGET_PURE;
int
	mget_strcasecmp_ascii(const char *s1, const char *s2) G_GNUC_MGET_PURE;
int
	mget_strncasecmp_ascii(const char *s1, const char *s2, size_t n) G_GNUC_MGET_PURE;
char *
	mget_strtolower(char *s);
int
	mget_strncmp(const char *s1, const char *s2, size_t n) G_GNUC_MGET_PURE;
int
	mget_strncasecmp(const char *s1, const char *s2, size_t n) G_GNUC_MGET_PURE;
void
   mget_memtohex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size) G_GNUC_MGET_NONNULL_ALL;
void
	mget_millisleep(int ms);
int
	mget_percent_unescape(char *src);
int
	mget_match_tail(const char *s, const char *tail) G_GNUC_MGET_PURE;
int
	mget_match_tail_nocase(const char *s, const char *tail) G_GNUC_MGET_PURE;
ssize_t
	mget_fdgetline(char **buf, size_t *bufsize, int fd) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_getline(char **buf, size_t *bufsize, FILE *fp) G_GNUC_MGET_NONNULL_ALL;
FILE *
	mget_vpopenf(const char *type, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL((1,2));
FILE *
	mget_popenf(const char *type, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL((1,2));
FILE *
	mget_popen2f(FILE **fpin, FILE **fpout, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL((3));
pid_t
	mget_fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv);
pid_t
	mget_popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv);
/*
size_t
	mget_vbsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, va_list) G_GNUC_MGET_PRINTF_FORMAT(3,0);
size_t
	mget_bsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4);
*/
char *
	mget_read_file(const char *fname, size_t *size);
const char
	*mget_local_charset_encoding(void);
char *
	mget_charset_transcode(const char *src, const char *src_encoding, const char *dst_encoding) G_GNUC_MGET_MALLOC;
int
	mget_str_needs_encoding(const char *s) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_PURE;
int
	mget_str_is_valid_utf8(const char *utf8) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_PURE;
char *
	mget_str_to_utf8(const char *src, const char *encoding) G_GNUC_MGET_MALLOC;
char *
	mget_utf8_to_str(const char *src, const char *encoding) G_GNUC_MGET_MALLOC;
const char *
	mget_str_to_ascii(const char *src);

/**
 * MGET_COMPATIBILITY:
 *
 * General compatibility functions
 */

#ifndef HAVE_STRNDUP
char *
	strndup(const char *s, size_t n) G_GNUC_MGET_MALLOC G_GNUC_MGET_NONNULL_ALL;
#endif

#ifndef HAVE_STRDUP
#	define strdup(s) strndup((s), strlen(s))
#endif

#ifndef HAVE_STRLCPY
size_t
	strlcpy(char *restrict dst, const char *restrict src, size_t size) G_GNUC_MGET_NONNULL_ALL;
#endif

#ifndef HAVE_DPRINTF
int
	vdprintf(int fd, const char *restrict fmt, va_list) G_GNUC_MGET_PRINTF_FORMAT(2,0);
int
	dprintf(int fd, const char *restrict fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3);
#endif /* HAVE_DPRINTF */

/*
 * Double linked list
 */

/**
 * MGET_LIST:
 *
 * Type for double linked lists and list entries.
 */
typedef struct _mget_list_st mget_list_t;

void *
	mget_list_append(mget_list_t **list, const void *data, size_t size) G_GNUC_MGET_NONNULL_ALL;
void *
	mget_list_prepend(mget_list_t **list, const void *data, size_t size) G_GNUC_MGET_NONNULL_ALL;
void *
	mget_list_getfirst(const mget_list_t *list) G_GNUC_MGET_CONST;
void *
	mget_list_getlast(const mget_list_t *list) G_GNUC_MGET_PURE;
void
	mget_list_remove(mget_list_t **list, void *elem) G_GNUC_MGET_NONNULL_ALL;
void
	mget_list_free(mget_list_t **list) G_GNUC_MGET_NONNULL_ALL;
int
	mget_list_browse(const mget_list_t *list, int (*browse)(void *context, void *elem), void *context) G_GNUC_MGET_NONNULL((2));

/*
 * Memory allocation routines
 */

// I try to never leave freed pointers hanging around
#define mget_xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

void *
	mget_malloc(size_t size) G_GNUC_MGET_MALLOC G_GNUC_MGET_ALLOC_SIZE(1);
void *
	mget_calloc(size_t nmemb, size_t size) G_GNUC_MGET_MALLOC G_GNUC_MGET_ALLOC_SIZE2(1,2);
void *
	mget_realloc(void *ptr, size_t size) G_GNUC_MGET_ALLOC_SIZE(2);
void
	mget_set_oomfunc(void (*oom_callback)(void));

/*
 * String/Memory routines, slightly different than standard functions
 */

void *
	mget_memdup(const void *s, size_t n) G_GNUC_MGET_ALLOC_SIZE(2);
char *
	mget_strdup(const char *s) G_GNUC_MGET_MALLOC;
char *
	mget_strmemdup(const void *s, size_t n) G_GNUC_MGET_ALLOC_SIZE(2);
void
	mget_strmemcpy(char *s, size_t ssize, const void *m, size_t n) G_GNUC_MGET_NONNULL_ALL;

/*
 * Base64 routines
 */

int
	mget_base64_is_string(const char *src) G_GNUC_MGET_PURE;
size_t
	mget_base64_decode(char *restrict dst, const char *restrict src, int n) G_GNUC_MGET_NONNULL_ALL;
size_t
	mget_base64_encode(char *restrict dst, const char *restrict src, int n) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_base64_decode_alloc(const char *restrict src, int n) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_base64_encode_alloc(const char *restrict src, int n) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_base64_encode_vprintf_alloc(const char *restrict fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(1,0) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_base64_encode_printf_alloc(const char *restrict fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(1,2) G_GNUC_MGET_NONNULL_ALL;

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
		release_data : 1; // 'data' has been malloc'ed and must be freed
	unsigned int
		release_buf : 1; // buffer_t structure has been malloc'ed and must be freed
} mget_buffer_t;

mget_buffer_t *
	mget_buffer_init(mget_buffer_t *buf, char *data, size_t size);
mget_buffer_t *
	mget_buffer_alloc(size_t size) G_GNUC_MGET_MALLOC G_GNUC_MGET_ALLOC_SIZE(1);
void
	mget_buffer_ensure_capacity(mget_buffer_t *buf, size_t size) G_GNUC_MGET_NONNULL((1));
void
	mget_buffer_deinit(mget_buffer_t *buf);
void
	mget_buffer_free(mget_buffer_t **buf);
void
	mget_buffer_free_data(mget_buffer_t *buf);
void
	mget_buffer_realloc(mget_buffer_t *buf, size_t size) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_ALLOC_SIZE(2);
void
	mget_buffer_reset(mget_buffer_t *buf);
size_t
	mget_buffer_memcpy(mget_buffer_t *buf, const void *data, size_t length) G_GNUC_MGET_NONNULL((1,2));
size_t
	mget_buffer_memcat(mget_buffer_t *buf, const void *data, size_t length) G_GNUC_MGET_NONNULL((1,2));
size_t
	mget_buffer_strcpy(mget_buffer_t *buf, const char *s) G_GNUC_MGET_NONNULL((1,2));
size_t
	mget_buffer_strcat(mget_buffer_t *buf, const char *s) G_GNUC_MGET_NONNULL((1,2));
size_t
	mget_buffer_bufcpy(mget_buffer_t *buf, mget_buffer_t *src) G_GNUC_MGET_NONNULL((1,2));
size_t
	mget_buffer_bufcat(mget_buffer_t *buf, mget_buffer_t *src) G_GNUC_MGET_NONNULL((1,2));
size_t
	mget_buffer_memset(mget_buffer_t *buf, char c, size_t length) G_GNUC_MGET_NONNULL((1));
size_t
	mget_buffer_memset_append(mget_buffer_t *buf, char c, size_t length) G_GNUC_MGET_NONNULL((1));
char *
	mget_buffer_trim(mget_buffer_t *buf) G_GNUC_MGET_NONNULL((1));
size_t
	mget_buffer_vprintf_append(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0);
size_t
	mget_buffer_printf_append(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3);
size_t
	mget_buffer_vprintf(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0);
size_t
	mget_buffer_printf(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3);
size_t
	mget_buffer_vprintf_append2(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0);
size_t
	mget_buffer_printf_append2(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3);
size_t
	mget_buffer_vprintf2(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0);
size_t
	mget_buffer_printf2(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3);

/*
 * Logger routines
 */

typedef struct _mget_logger_st mget_logger_t;
typedef void (*mget_logger_func_t)(const char *buf , size_t len) G_GNUC_MGET_NONNULL_ALL;

void
	mget_logger_set_func(mget_logger_t *logger, mget_logger_func_t);
//	mget_logger_set_func(mget_logger_t *logger, void (*func)(const char *buf G_GNUC_MGET_NONNULL, size_t len));
void
	mget_logger_set_stream(mget_logger_t *logger, FILE *fp);
void
	mget_logger_set_file(mget_logger_t *logger, const char *fname);
void
	(*mget_logger_get_func(mget_logger_t *logger))(const char *, size_t) G_GNUC_MGET_PURE;
FILE *
	mget_logger_get_stream(mget_logger_t *logger) G_GNUC_MGET_PURE;
const char *
	mget_logger_get_file(mget_logger_t *logger) G_GNUC_MGET_PURE;

/*
 * Logging routines
 */

#define MGET_LOGGER_INFO   1
#define MGET_LOGGER_ERROR  2
#define MGET_LOGGER_DEBUG  3

void
	mget_info_vprintf(const char *fmt, va_list args) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,0);
void
	mget_info_printf(const char *fmt, ...) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_error_vprintf(const char *fmt, va_list args) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,0);
void
	mget_error_printf(const char *fmt, ...) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_error_printf_exit(const char *fmt, ...) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_NORETURN G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_debug_vprintf(const char *fmt, va_list args) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,0);
void
	mget_debug_printf(const char *fmt, ...) G_GNUC_MGET_NONNULL((1)) G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_debug_write(const char *buf, size_t len) G_GNUC_MGET_NONNULL_ALL;
mget_logger_t *
	mget_get_logger(int id) G_GNUC_MGET_CONST;

/*
 * Vector datatype routines
 */

typedef struct _mget_vector_st mget_vector_t;

mget_vector_t *
	mget_vector_create(int max, int off, int (*cmp)(const void *, const void *)) G_GNUC_MGET_MALLOC;
int
	mget_vector_find(const mget_vector_t *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_findext(const mget_vector_t *v, int start, int direction, int (*find)(void *)) G_GNUC_MGET_NONNULL((4));
int
	mget_vector_contains(const mget_vector_t *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert(mget_vector_t *v, const void *elem, size_t size, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert_noalloc(mget_vector_t *v, const void *elem, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert_sorted(mget_vector_t *v, const void *elem, size_t size) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert_sorted_noalloc(mget_vector_t *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add(mget_vector_t *v, const void *elem, size_t size) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_noalloc(mget_vector_t *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_str(mget_vector_t *v, const char *s) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_vprintf(mget_vector_t *v, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_printf(mget_vector_t *v, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_replace(mget_vector_t *v, const void *elem, size_t size, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_replace_noalloc(mget_vector_t *v, const void *elem, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_move(mget_vector_t *v, int old_pos, int new_pos);
int
	mget_vector_swap(mget_vector_t *v, int pos1, int pos2);
int
	mget_vector_remove(mget_vector_t *v, int pos);
int
	mget_vector_remove_nofree(mget_vector_t *v, int pos);
int
	mget_vector_size(const mget_vector_t *v) G_GNUC_MGET_PURE;
int
	mget_vector_browse(const mget_vector_t *v, int (*browse)(void *ctx, void *elem), void *ctx) G_GNUC_MGET_NONNULL((2));
void
	mget_vector_free(mget_vector_t **v);
void
	mget_vector_clear(mget_vector_t *v);
void
	mget_vector_clear_nofree(mget_vector_t *v);
void *
	mget_vector_get(const mget_vector_t *v, int pos) G_GNUC_MGET_PURE;
void
	mget_vector_setcmpfunc(mget_vector_t *v, int (*cmp)(const void *elem1, const void *elem2)) G_GNUC_MGET_NONNULL((2));
void
	mget_vector_set_destructor(mget_vector_t *v, void (*destructor)(void *elem));
void
	mget_vector_sort(mget_vector_t *v);

/*
 * Hashmap datatype routines
 */

typedef struct _mget_hashmap_st mget_hashmap_t;

mget_hashmap_t
	*mget_hashmap_create(int max, int off, unsigned int (*hash)(const void *), int (*cmp)(const void *, const void *)) G_GNUC_MGET_MALLOC;
int
	mget_hashmap_put(mget_hashmap_t *h, const void *key, size_t keysize, const void *value, size_t valuesize);
int
	mget_hashmap_put_noalloc(mget_hashmap_t *h, const void *key, const void *value);
//int
//	mget_hashmap_put_ident(MGET_HASHMAP *h, const void *key, size_t keysize);
//int
//	mget_hashmap_put_ident_noalloc(MGET_HASHMAP *h, const void *key);
int
	mget_hashmap_size(const mget_hashmap_t *h) G_GNUC_MGET_PURE;
int
	mget_hashmap_browse(const mget_hashmap_t *h, int (*browse)(void *ctx, const void *key, void *value), void *ctx) G_GNUC_MGET_NONNULL((2));
void
	mget_hashmap_free(mget_hashmap_t **h);
void
	mget_hashmap_clear(mget_hashmap_t *h);
void *
	mget_hashmap_get(const mget_hashmap_t *h, const void *key);
int
	mget_hashmap_get_null(const mget_hashmap_t *h, const void *key, void **value);
int
	mget_hashmap_contains(const mget_hashmap_t *h, const void *key);
int
	mget_hashmap_remove(mget_hashmap_t *h, const void *key);
int
	mget_hashmap_remove_nofree(mget_hashmap_t *h, const void *key);
void
	mget_hashmap_setcmpfunc(mget_hashmap_t *h, int (*cmp)(const void *key1, const void *key2));
void
	mget_hashmap_sethashfunc(mget_hashmap_t *h, unsigned int (*hash)(const void *key));
void
	mget_hashmap_set_key_destructor(mget_hashmap_t *h, void (*destructor)(void *key));
void
	mget_hashmap_set_value_destructor(mget_hashmap_t *h, void (*destructor)(void *value));
void
	mget_hashmap_setloadfactor(mget_hashmap_t *h, float factor);

/*
 * Hashmap datatype routines
 */

typedef mget_hashmap_t mget_stringmap_t;

mget_stringmap_t *
	mget_stringmap_create(int max) G_GNUC_MGET_MALLOC;
mget_stringmap_t *
	mget_stringmap_create_nocase(int max) G_GNUC_MGET_MALLOC;
int
	mget_stringmap_put(mget_stringmap_t *h, const char *key, const void *value, size_t valuesize);
int
	mget_stringmap_put_noalloc(mget_stringmap_t *h, const char *key, const void *value);
//int
//	mget_stringmap_put_ident(MGET_STRINGMAP *h, const char *key);
//int
//	mget_stringmap_put_ident_noalloc(MGET_STRINGMAP *h, const char *key);
int
	mget_stringmap_size(const mget_stringmap_t *h) G_GNUC_MGET_PURE;
int
	mget_stringmap_browse(const mget_stringmap_t *h, int (*browse)(void *ctx, const char *key, void *value), void *ctx) G_GNUC_MGET_NONNULL((2));
void
	mget_stringmap_free(mget_stringmap_t **h);
void
	mget_stringmap_clear(mget_stringmap_t *h);
void *
	mget_stringmap_get(const mget_stringmap_t *h, const char *key);
int
	mget_stringmap_get_null(const mget_stringmap_t *h, const char *key, void **value);
int
	mget_stringmap_contains(const mget_stringmap_t *h, const char *key);
int
	mget_stringmap_remove(mget_stringmap_t *h, const char *key);
int
	mget_stringmap_remove_nofree(mget_stringmap_t *h, const char *key);
void
	mget_stringmap_setcmpfunc(mget_stringmap_t *h, int (*cmp)(const char *key1, const char *key2));
void
	mget_stringmap_sethashfunc(mget_stringmap_t *h, unsigned int (*hash)(const char *key));
void
	mget_stringmap_setloadfactor(mget_stringmap_t *h, float factor);
void
	mget_stringmap_set_value_destructor(mget_hashmap_t *h, void (*destructor)(void *value));

/*
 * Thread wrapper routines
 */

#ifdef PTHREAD_MUTEX_INITIALIZER
#define MGET_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define MGET_THREAD_COND_INITIALIZER PTHREAD_COND_INITIALIZER
typedef pthread_t mget_thread_t;
typedef pthread_mutex_t mget_thread_mutex_t;
typedef pthread_cond_t mget_thread_cond_t;
#else
#define MGET_THREAD_MUTEX_INITIALIZER 0
typedef unsigned long int mget_thread_t;
typedef int mget_thread_mutex_t;
typedef int mget_thread_cond_t;
#endif

int
	mget_thread_start(mget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags);
int
	mget_thread_mutex_init(mget_thread_mutex_t *mutex);
void
	mget_thread_mutex_lock(mget_thread_mutex_t *);
void
	mget_thread_mutex_unlock(mget_thread_mutex_t *);
int
	mget_thread_kill(mget_thread_t thread, int sig);
int
	mget_thread_join(mget_thread_t thread);
int
	mget_thread_cond_init(mget_thread_cond_t *cond);
int
	mget_thread_cond_signal(mget_thread_cond_t *cond);
int
	mget_thread_cond_wait(mget_thread_cond_t *cond, mget_thread_mutex_t *mutex);
mget_thread_t
	mget_thread_self(void) G_GNUC_MGET_CONST;

/*
 * Decompressor routines
 */

typedef struct _mget_decompressor_st mget_decompressor_t;

enum {
	mget_content_encoding_identity,
	mget_content_encoding_gzip,
	mget_content_encoding_deflate,
	mget_content_encoding_lzma,
	mget_content_encoding_bzip2
};

mget_decompressor_t *
	mget_decompress_open(int encoding,
						 int (*put_data)(void *context, const char *data, size_t length),
						 void *context);
void
	mget_decompress_close(mget_decompressor_t *dc);
int
	mget_decompress(mget_decompressor_t *dc, char *src, size_t srclen);

/*
 * URI/IRI routines
 */

// TODO: i have to move this away from libmget.h
extern const char * const
	mget_iri_schemes[];

#define MGET_IRI_SCHEME_HTTP    (mget_iri_schemes[0])
#define MGET_IRI_SCHEME_HTTPS   (mget_iri_schemes[1])
#define MGET_IRI_SCHEME_FTP     (mget_iri_schemes[2])
#define MGET_IRI_SCHEME_DEFAULT MGET_IRI_SCHEME_HTTP

typedef struct mget_iri_st {
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
	char
		host_allocated; // if set, free host in iri_free()
} mget_iri_t;

void
	mget_iri_test(void);
void
	mget_iri_free(mget_iri_t **iri);
void
	mget_iri_free_content(mget_iri_t *iri);
void
	mget_iri_set_defaultpage(const char *page);
int
	mget_iri_supported(const mget_iri_t *iri) G_GNUC_MGET_PURE G_GNUC_MGET_NONNULL_ALL;
int
	mget_iri_isgendelim(char c) G_GNUC_MGET_CONST;
int
	mget_iri_issubdelim(char c) G_GNUC_MGET_CONST;
int
	mget_iri_isreserved(char c) G_GNUC_MGET_CONST;
int
	mget_iri_isunreserved(char c) G_GNUC_MGET_PURE;
int
	mget_iri_isunreserved_path(char c) G_GNUC_MGET_PURE;
int
	mget_iri_compare(mget_iri_t *iri1, mget_iri_t *iri2) G_GNUC_MGET_PURE G_GNUC_MGET_NONNULL_ALL;
mget_iri_t *
	mget_iri_parse(const char *uri, const char *encoding);
mget_iri_t *
	mget_iri_parse_base(mget_iri_t *base, const char *url, const char *encoding);
mget_iri_t *
	mget_iri_clone(mget_iri_t *iri);
const char *
	mget_iri_get_connection_part(mget_iri_t *iri);
const char *
	mget_iri_relative_to_abs(mget_iri_t *base, const char *val, size_t len, mget_buffer_t *buf);
const char *
	mget_iri_escape(const char *src, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_escape_path(const char *src, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_escape_query(const char *src, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_host(const mget_iri_t *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_resource(const mget_iri_t *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_iri_get_path(const mget_iri_t *iri, mget_buffer_t *buf, const char *encoding) G_GNUC_MGET_NONNULL((1,2));
char *
	mget_iri_get_query_as_filename(const mget_iri_t *iri, mget_buffer_t *buf, const char *encoding) G_GNUC_MGET_NONNULL((1,2));
char *
	mget_iri_get_filename(const mget_iri_t *iri, mget_buffer_t *buf, const char *encoding) G_GNUC_MGET_NONNULL((1,2));

/*
 * Cookie routines
 */

// typedef and structure for cookie database
typedef struct mget_cookie_db_st mget_cookie_db_t;

// structure for cookie store
//typedef struct mget_cookie_db_st mget_cookie_db_t;

typedef struct mget_cookie_st {
	const char *
		name;
	const char *
		value;
	const char *
		domain;
	const char *
		path;
	time_t
		expires; // time of expiration (format YYYYMMDDHHMMSS)
	time_t
		maxage; // like expires, but precedes it if set
	time_t
		last_access;
	time_t
		creation;
	unsigned int
		domain_dot : 1; // for compatibility with Netscape cookie format
	unsigned int
		normalized : 1;
	unsigned int
		persistent : 1;
	unsigned int
		host_only : 1;
	unsigned int
		secure_only : 1; // cookie should be used over secure connections only (TLS/HTTPS)
	unsigned int
		http_only : 1; // just use the cookie via HTTP/HTTPS protocol
} mget_cookie_t;

mget_cookie_t *
	mget_cookie_init(mget_cookie_t *cookie);
void
	mget_cookie_deinit(mget_cookie_t *cookie);
void
	mget_cookie_free(mget_cookie_t **cookie);
void
	mget_cookie_normalize_cookies(const mget_iri_t *iri, const mget_vector_t *cookies);
int
	mget_cookie_store_cookie(mget_cookie_db_t *cookie_db, mget_cookie_t *cookie);
void
	mget_cookie_store_cookies(mget_cookie_db_t *cookie_db, mget_vector_t *cookies);
int
	mget_cookie_normalize(const mget_iri_t *iri, mget_cookie_t *cookie);
int
	mget_cookie_check_psl(const mget_cookie_db_t *cookie_db, const mget_cookie_t *cookie);
mget_cookie_db_t *
	mget_cookie_db_init(mget_cookie_db_t *cookie_db);
void
	mget_cookie_db_deinit(mget_cookie_db_t *cookie_db);
void
	mget_cookie_db_free(mget_cookie_db_t **cookie_db);
int
	mget_cookie_db_save(mget_cookie_db_t *cookie_db, const char *fname, int keep_session_cookies);
int
	mget_cookie_db_load(mget_cookie_db_t *cookie_db, const char *fname, int keep_session_cookies);
int
	mget_cookie_db_load_psl(mget_cookie_db_t *cookie_db, const char *fname);
char *
	mget_cookie_create_request_header(mget_cookie_db_t *cookie_db, const mget_iri_t *iri);

/*
 * HTTP Strict Transport Security (HSTS) routines
 */

// structure for HTTP Strict Transport Security (HSTS) entries
typedef struct _mget_hsts_st mget_hsts_t;
typedef struct _mget_hsts_db_st mget_hsts_db_t;

mget_hsts_t *
	mget_hsts_init(mget_hsts_t *hsts);
void
	mget_hsts_deinit(mget_hsts_t *hsts);
void
	mget_hsts_free(mget_hsts_t *hsts);
mget_hsts_t *
	mget_hsts_new(const char *host, int port, time_t maxage, int include_subdomains);
int
	mget_hsts_host_match(const mget_hsts_db_t *hsts_db, const char *host, int port);

mget_hsts_db_t *
	mget_hsts_db_init(mget_hsts_db_t *hsts_db);
void
	mget_hsts_db_deinit(mget_hsts_db_t *hsts_db);
void
	mget_hsts_db_free(mget_hsts_db_t **hsts_db);
void
	mget_hsts_db_add(mget_hsts_db_t *hsts_db, mget_hsts_t *hsts);
int
	mget_hsts_db_save(mget_hsts_db_t *hsts_db, const char *fname);
int
	mget_hsts_db_load(mget_hsts_db_t *hsts_db, const char *fname);

/*
 * Online Certificate Status Protocol (OCSP) routines
 */

// structure for Online Certificate Status Protocol (OCSP) entries
typedef struct _mget_ocsp_st mget_ocsp_t;
typedef struct _mget_ocsp_db_st mget_ocsp_db_t;

mget_ocsp_t *
	mget_ocsp_init(mget_ocsp_t *ocsp);
void
	mget_ocsp_deinit(mget_ocsp_t *ocsp);
void
	mget_ocsp_free(mget_ocsp_t *ocsp);
mget_ocsp_t *
	mget_ocsp_new(const char *fingerprint, time_t maxage, int valid);
int
	mget_ocsp_fingerprint_in_cache(const mget_ocsp_db_t *ocsp_db, const char *fingerprint, int *valid);
int
	mget_ocsp_hostname_is_valid(const mget_ocsp_db_t *ocsp_db, const char *fingerprint);

mget_ocsp_db_t *
	mget_ocsp_db_init(mget_ocsp_db_t *ocsp_db);
void
	mget_ocsp_db_deinit(mget_ocsp_db_t *ocsp_db);
void
	mget_ocsp_db_free(mget_ocsp_db_t **ocsp_db);
void
	mget_ocsp_db_add_fingerprint(mget_ocsp_db_t *ocsp_db, mget_ocsp_t *ocsp);
void
	mget_ocsp_db_add_host(mget_ocsp_db_t *ocsp_db, mget_ocsp_t *ocsp);
int
	mget_ocsp_db_save(mget_ocsp_db_t *ocsp_db, const char *fname);
int
	mget_ocsp_db_load(mget_ocsp_db_t *ocsp_db, const char *fname);

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
} MGET_PARSED_URL;

void
	mget_css_parse_buffer(
		const char *buf,
		void(*callback_uri)(void *user_ctx, const char *url, size_t len, size_t pos),
		void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
		void *user_ctx) G_GNUC_MGET_NONNULL((1));
void
	mget_css_parse_file(
		const char *fname,
		void(*callback_uri)(void *user_ctx, const char *url, size_t len, size_t pos),
		void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
		void *user_ctx) G_GNUC_MGET_NONNULL((1));
mget_vector_t *
	mget_css_get_urls(
		const char *css,
		mget_iri_t *base,
		const char **encoding) G_GNUC_MGET_NONNULL((1));
mget_vector_t *
	mget_css_get_urls_from_localfile(
		const char *fname,
		mget_iri_t *base,
		const char **encoding) G_GNUC_MGET_NONNULL((1));

typedef struct {
	const char
		*p;
	size_t
		len;
} mget_string_t;

typedef struct {
	mget_string_t
		url;
	char
		attr[16];
	char
		dir[16];
} MGET_HTML_PARSED_URL;

typedef struct {
	mget_vector_t
		*uris;
	const char *
		encoding;
	mget_string_t
		base;
	char
		follow;
} MGET_HTML_PARSED_RESULT;

typedef struct {
	const char *
		name;
	const char *
		attribute;
} mget_html_tag_t;

MGET_HTML_PARSED_RESULT *
	mget_html_get_urls_inline(const char *html, mget_vector_t *additional_tags, mget_vector_t *ignore_tags);
void
	mget_html_free_urls_inline(MGET_HTML_PARSED_RESULT **res);

void
	mget_sitemap_get_urls_inline(const char *sitemap, mget_vector_t **urls, mget_vector_t **sitemap_urls);

void
	mget_atom_get_urls_inline(const char *atom, mget_vector_t **urls);

void
	mget_rss_get_urls_inline(const char *rss, mget_vector_t **urls);

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

typedef void mget_xml_callback_t(void *, int, const char *, const char *, const char *, size_t, size_t);

void
	mget_xml_parse_buffer(
		const char *buf,
		mget_xml_callback_t *callback,
//		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1)),
	mget_xml_parse_file(
		const char *fname,
		mget_xml_callback_t *callback,
//		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1)),
	mget_html_parse_buffer(
		const char *buf,
		mget_xml_callback_t *callback,
//		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1)),
	mget_html_parse_file(
		const char *fname,
		mget_xml_callback_t *callback,
//		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1));

/*
 * TCP network routines
 */

#define MGET_NET_FAMILY_ANY  0
#define MGET_NET_FAMILY_IPV4 1
#define MGET_NET_FAMILY_IPV6 2

#define MGET_PROTOCOL_HTTP_1_1  0
#define MGET_PROTOCOL_HTTP_2_0  1

typedef struct mget_tcp_st mget_tcp_t;

mget_tcp_t *
	mget_tcp_init(void);
void
	mget_tcp_deinit(mget_tcp_t **tcp);
void
	mget_dns_cache_free(void);
void
	mget_tcp_close(mget_tcp_t *tcp);
void
	mget_tcp_set_timeout(mget_tcp_t *tcp, int timeout);
int
	mget_tcp_get_timeout(mget_tcp_t *tcp) G_GNUC_MGET_PURE;
void
	mget_tcp_set_connect_timeout(mget_tcp_t *tcp, int timeout);
void
	mget_tcp_set_dns_timeout(mget_tcp_t *tcp, int timeout);
void
	mget_tcp_set_dns_caching(mget_tcp_t *tcp, int caching);
void
	mget_tcp_set_tcp_fastopen(mget_tcp_t *tcp, int tcp_fastopen);
void
	mget_tcp_set_ssl(mget_tcp_t *tcp, int ssl);
int
	mget_tcp_get_ssl(mget_tcp_t *tcp) G_GNUC_MGET_PURE;
void
	mget_tcp_set_ssl_hostname(mget_tcp_t *tcp, const char *hostname);
const char *
	mget_tcp_get_ssl_hostname(mget_tcp_t *tcp) G_GNUC_MGET_PURE;
void
	mget_tcp_set_ssl_ca_file(mget_tcp_t *tcp, const char *cafile);
void
	mget_tcp_set_ssl_key_file(mget_tcp_t *tcp, const char *certfile, const char *keyfile);
int
	mget_tcp_get_dns_caching(mget_tcp_t *tcp) G_GNUC_MGET_PURE;
int
	mget_tcp_get_family(mget_tcp_t *tcp) G_GNUC_MGET_PURE;
int
	mget_tcp_get_preferred_family(mget_tcp_t *tcp) G_GNUC_MGET_PURE;
int
	mget_tcp_get_protocol(mget_tcp_t *tcp);
int
	mget_tcp_get_local_port(mget_tcp_t *tcp);
void
	mget_tcp_set_debug(mget_tcp_t *tcp, int debug);
void
	mget_tcp_set_family(mget_tcp_t *tcp, int family);
void
	mget_tcp_set_preferred_family(mget_tcp_t *tcp, int family);
void
	mget_tcp_set_protocol(mget_tcp_t *tcp, int protocol);
void
	mget_tcp_set_bind_address(mget_tcp_t *tcp, const char *bind_address);
struct addrinfo *
	mget_tcp_resolve(mget_tcp_t *tcp, const char *restrict name, const char *restrict port) G_GNUC_MGET_NONNULL((2));
int
	mget_tcp_connect(mget_tcp_t *tcp, const char *host, const char *port) G_GNUC_MGET_NONNULL((1));
int
	mget_tcp_listen(mget_tcp_t *tcp, const char *host, const char *port, int backlog) G_GNUC_MGET_NONNULL((1));
mget_tcp_t
	*mget_tcp_accept(mget_tcp_t *parent_tcp) G_GNUC_MGET_NONNULL((1));
int
	mget_tcp_tls_start(mget_tcp_t *tcp) G_GNUC_MGET_NONNULL((1));
void
	mget_tcp_tls_stop(mget_tcp_t *tcp) G_GNUC_MGET_NONNULL((1));
ssize_t
	mget_tcp_vprintf(mget_tcp_t *tcp, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_tcp_printf(mget_tcp_t *tcp, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_tcp_write(mget_tcp_t *tcp, const char *buf, size_t count) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_tcp_read(mget_tcp_t *tcp, char *buf, size_t count) G_GNUC_MGET_NONNULL_ALL;
int
	mget_tcp_ready_2_transfer(mget_tcp_t *tcp, int flags) G_GNUC_MGET_NONNULL_ALL;

/*
 * SSL routines
 */

#define MGET_SSL_X509_FMT_PEM 0
#define MGET_SSL_X509_FMT_DER 1

#define MGET_SSL_SECURE_PROTOCOL   1
#define MGET_SSL_CA_DIRECTORY      2
#define MGET_SSL_CA_FILE           3
#define MGET_SSL_CERT_FILE         4
#define MGET_SSL_KEY_FILE          5
#define MGET_SSL_CA_TYPE           6
#define MGET_SSL_CERT_TYPE         7
#define MGET_SSL_KEY_TYPE          8
#define MGET_SSL_CHECK_CERTIFICATE 9
#define MGET_SSL_CHECK_HOSTNAME    10
#define MGET_SSL_PRINT_INFO        11
#define MGET_SSL_DIRECT_OPTIONS    12
#define MGET_SSL_CRL_FILE          13
#define MGET_SSL_OCSP_STAPLING     14
#define MGET_SSL_OCSP_SERVER       15
#define MGET_SSL_OCSP              16
#define MGET_SSL_OCSP_CACHE        17
#define MGET_SSL_ALPN              18

void
	mget_ssl_init(void);
void
	mget_ssl_deinit(void);
void
	mget_ssl_set_config_string(int key, const char *value);
void
	mget_ssl_set_config_int(int key, int value);
//void *
//	mget_ssl_open(int sockfd, const char *hostname, int connect_timeout) G_GNUC_MGET_NONNULL((2));
int
	mget_ssl_open(mget_tcp_t *tcp);
void
	mget_ssl_close(void **session);
void
	mget_ssl_set_check_certificate(char value);

void
	mget_ssl_server_init(void);
void
	mget_ssl_server_deinit(void);
int
	mget_ssl_server_open(mget_tcp_t *tcp);
void
	mget_ssl_server_close(void **session);

ssize_t
	mget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout) G_GNUC_MGET_NONNULL_ALL;

/*
 * HTTP routines
 */

typedef struct {
	const char *
		name;
	const char *
		value;
} mget_http_header_param_t;

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
} mget_http_link_t;

typedef struct {
	const char *
		algorithm;
	const char *
		encoded_digest;
} mget_http_digest_t;

typedef struct {
	const char *
		auth_scheme;
	mget_stringmap_t *
		params;
} mget_http_challenge_t;

enum {
	transfer_encoding_identity,
	transfer_encoding_chunked
};

// keep the request as simple as possible
typedef struct {
	mget_vector_t *
		headers;
	const char *
		scheme;
	void *
		nghttp2_context; // needed for nghttp2 callbacks
	mget_buffer_t
		esc_resource; // URI escaped resource
	mget_buffer_t
		esc_host; // URI escaped host
	int32_t
		stream_id; // HTTP2 stream id
	char
		esc_resource_buf[256];
	char
		esc_host_buf[64];
	char
		method[8]; // we just need HEAD, GET and POST
	char
		save_headers;
} mget_http_request_t;

// just parse the header lines that we need
typedef struct {
	mget_vector_t *
		links;
	mget_vector_t *
		digests;
	mget_vector_t *
		cookies;
	mget_vector_t *
		challenges;
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
	mget_buffer_t *
		header;
	mget_buffer_t *
		body;
	size_t
		content_length;
	time_t
		last_modified;
	time_t
		hsts_maxage;
	char
		hsts_include_subdomains;
	char
		hsts; // if hsts_maxage and hsts_include_subdomains are valid
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
		transfer_encoding;
	char
		content_encoding;
	char
		content_length_valid;
	char
		keep_alive;
} mget_http_response_t;

typedef struct {
	mget_tcp_t *
		tcp;
	const char *
		esc_host;
	const char *
		port;
	const char *
		scheme;
	mget_buffer_t *
		buf;
#ifdef WITH_LIBNGHTTP2
	nghttp2_session *
		http2_session;
#endif
	char
		protocol; // MGET_PROTOCOL_HTTP_1_1 or MGET_PROTOCOL_HTTP_2_0
	unsigned
		print_response_headers : 1;
} mget_http_connection_t;

int
	mget_http_isseperator(char c) G_GNUC_MGET_CONST;
int
	mget_http_istoken(char c) G_GNUC_MGET_CONST;

const char *
	mget_http_parse_token(const char *s, const char **token) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_quoted_string(const char *s, const char **qstring) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_param(const char *s, const char **param, const char **value) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_name(const char *s, const char **name) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_parse_name_fixed(const char *s, const char **name, size_t *namelen) G_GNUC_MGET_NONNULL_ALL;
time_t
	mget_http_parse_full_date(const char *s) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_link(const char *s, mget_http_link_t *link) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_digest(const char *s, mget_http_digest_t *digest) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_challenge(const char *s, mget_http_challenge_t *challenge) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_challenges(const char *s, mget_vector_t *challenges) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_location(const char *s, const char **location) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_transfer_encoding(const char *s, char *transfer_encoding) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_content_type(const char *s, const char **content_type, const char **charset) G_GNUC_MGET_NONNULL((1));
const char *
	mget_http_parse_content_encoding(const char *s, char *content_encoding) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_content_disposition(const char *s, const char **filename) G_GNUC_MGET_NONNULL((1));
const char *
	mget_http_parse_strict_transport_security(const char *s, time_t *maxage, char *include_subdomains) G_GNUC_MGET_NONNULL((1));
const char *
	mget_http_parse_connection(const char *s, char *keep_alive) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_http_parse_setcookie(const char *s, mget_cookie_t *cookie) G_GNUC_MGET_NONNULL((1));
const char *
	mget_http_parse_etag(const char *s, const char **etag) G_GNUC_MGET_NONNULL((1));

char *
	mget_http_print_date(time_t t, char *buf, size_t bufsize) G_GNUC_MGET_NONNULL_ALL;

void
	mget_http_add_param(mget_vector_t **params, mget_http_header_param_t *param) G_GNUC_MGET_NONNULL_ALL;
void
	mget_http_add_header_vprintf(mget_http_request_t *req, const char *name, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(3,0) G_GNUC_MGET_NONNULL_ALL;
void
	mget_http_add_header_printf(mget_http_request_t *req, const char *name, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL_ALL;
void
	mget_http_add_header(mget_http_request_t *req, const char *name, const char *value) G_GNUC_MGET_NONNULL_ALL;
void
	mget_http_add_header_param(mget_http_request_t *req, mget_http_header_param_t *param) G_GNUC_MGET_NONNULL_ALL;
void
	mget_http_add_credentials(mget_http_request_t *req, mget_http_challenge_t *challenge, const char *username, const char *password) G_GNUC_MGET_NONNULL((1));
void
	mget_http_set_http_proxy(const char *proxy, const char *encoding);
void
	mget_http_set_https_proxy(const char *proxy, const char *encoding);

int
	mget_http_free_param(mget_http_header_param_t *param);
void
	mget_http_free_cookie(mget_cookie_t *cookie);
void
	mget_http_free_digest(mget_http_digest_t *digest);
void
	mget_http_free_challenge(mget_http_challenge_t *challenge);
void
	mget_http_free_link(mget_http_link_t *link);

void
	mget_http_free_cookies(mget_vector_t **cookies);
void
	mget_http_free_digests(mget_vector_t **digests);
void
	mget_http_free_challenges(mget_vector_t **challenges);
void
	mget_http_free_links(mget_vector_t **links);
//void
//	mget_http_free_header(HTTP_HEADER **header);
void
	mget_http_free_request(mget_http_request_t **req);
void
	mget_http_free_response(mget_http_response_t **resp);

mget_http_response_t *
	mget_http_read_header(const mget_iri_t *iri) G_GNUC_MGET_NONNULL_ALL;
mget_http_response_t *
	mget_http_get_header(mget_iri_t *iri) G_GNUC_MGET_NONNULL_ALL;
mget_http_response_t *
	mget_http_parse_response_header(char *buf) G_GNUC_MGET_NONNULL_ALL;
mget_http_response_t *
	mget_http_get_response_cb(mget_http_connection_t *conn, mget_http_request_t *req, unsigned int flags,
		int (*header_callback)(void *context, mget_http_response_t *),
		int (*body_callback)(void *context, const char *data, size_t length),
		void *context) G_GNUC_MGET_NONNULL((1,5));
//HTTP_RESPONSE *
//	http_get_response_mem(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL_ALL,
mget_http_response_t *
	mget_http_get_response(mget_http_connection_t *conn,
		int(*header_callback)(void *, mget_http_response_t *),
		mget_http_request_t *req, unsigned int flags) G_GNUC_MGET_NONNULL((1));
mget_http_response_t *
	mget_http_get_response_fd(mget_http_connection_t *conn,
		int(*header_callback)(void *, mget_http_response_t *),
		int fd, unsigned int flags) G_GNUC_MGET_NONNULL_ALL;
mget_http_response_t *
	mget_http_get_response_stream(mget_http_connection_t *conn,
		int(*header_callback)(void *, mget_http_response_t *),
		FILE *stream, unsigned int flags) G_GNUC_MGET_NONNULL_ALL;
mget_http_response_t *
	mget_http_get_response_func(mget_http_connection_t *conn,
		int(*header_callback)(void *, mget_http_response_t *),
		int(*body_callback)(void *, const char *, size_t), void *context, unsigned int flags) G_GNUC_MGET_NONNULL((1,2));

int
	mget_http_open(mget_http_connection_t **_conn, const mget_iri_t *iri);
mget_http_request_t *
	mget_http_create_request(const mget_iri_t *iri, const char *method) G_GNUC_MGET_NONNULL_ALL;
void
	mget_http_close(mget_http_connection_t **conn) G_GNUC_MGET_NONNULL_ALL;
int
	mget_http_send_request(mget_http_connection_t *conn, mget_http_request_t *req) G_GNUC_MGET_NONNULL_ALL;
int
	mget_http_send_request_with_body(mget_http_connection_t *conn, mget_http_request_t *req, const void *body, size_t length) G_GNUC_MGET_NONNULL((1,2));
ssize_t
	mget_http_request_to_buffer(mget_http_request_t *req, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;

/*
 * Highlevel HTTP routines
 */

mget_http_response_t *
	mget_http_get(int first_key, ...) G_GNUC_MGET_NULL_TERMINATED;
mget_vector_t
	*mget_get_css_urls(const char *data);

/*
 * MD5 routines
 */

void
	mget_md5_printf_hex(char *digest_hex, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL_ALL;

/*
 * Hash / digest routines
 */

typedef struct _mget_hash_hd_st mget_hash_hd_t;

/**
 * mget_digest_algorithm_t:
 * @MGET_DIGTYPE_UNKNOWN: Unknown hash algorithm.
 * @MGET_DIGTYPE_MD5: MD5 algorithm.
 * @MGET_DIGTYPE_SHA1: SHA-1 algorithm.
 * @MGET_DIGTYPE_RMD160: RMD160 algorithm.
 * @MGET_DIGTYPE_MD2: MD2 algorithm.
 * @MGET_DIGTYPE_SHA256: SHA-256 algorithm.
 * @MGET_DIGTYPE_SHA384: SHA-384 algorithm.
 * @MGET_DIGTYPE_SHA512: SHA-512 algorithm.
 * @MGET_DIGTYPE_SHA224: SHA-224 algorithm.
 *
 * Enumeration of different hash digest algorithms.
 */
typedef enum {
	MGET_DIGTYPE_UNKNOWN,
	MGET_DIGTYPE_MD5,
	MGET_DIGTYPE_SHA1,
	MGET_DIGTYPE_RMD160,
	MGET_DIGTYPE_MD2,
	MGET_DIGTYPE_SHA256,
	MGET_DIGTYPE_SHA384,
	MGET_DIGTYPE_SHA512,
	MGET_DIGTYPE_SHA224
} mget_digest_algorithm_t;

mget_digest_algorithm_t
	mget_hash_get_algorithm(const char *name);
int
	mget_hash_fast(mget_digest_algorithm_t algorithm, const void *text, size_t textlen, void *digest);
int
	mget_hash_get_len(mget_digest_algorithm_t algorithm);
int
	mget_hash_init(mget_hash_hd_t *dig, mget_digest_algorithm_t algorithm);
int
	mget_hash(mget_hash_hd_t *handle, const void *text, size_t textlen);
void
	mget_hash_deinit(mget_hash_hd_t *handle, void *digest);

/*
 * Hash file routines
 */

int
	mget_hash_file_fd(const char *type, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) G_GNUC_MGET_NONNULL_ALL,
	mget_hash_file_offset(const char *type, const char *fname, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) G_GNUC_MGET_NONNULL_ALL,
	mget_hash_file(const char *type, const char *fname, char *digest_hex, size_t digest_hex_size) G_GNUC_MGET_NONNULL_ALL;

/*
 * Metalink types and routines
 */

typedef struct {
	mget_iri_t
		*iri;
	int
		priority;
	char
		location[8]; // location of the mirror, e.g. 'de', 'fr' or 'jp'
} mget_metalink_mirror_t;

typedef struct {
	char
		type[16], // type of hash, e.g. 'MD5' or 'SHA-256'
		hash_hex[128+1]; // hash value as HEX string
} mget_metalink_hash_t;

// Metalink piece, for checksumming after download
typedef struct {
	mget_metalink_hash_t
		hash;
	off_t
		position;
	off_t
		length;
} mget_metalink_piece_t;

typedef struct {
	const char
		*name;
	mget_vector_t
		*mirrors,
		*hashes, // checksums of complete file
		*pieces; // checksums of smaller pieces of the file
	off_t
		size; // total size of the file
} mget_metalink_t;

mget_metalink_t
	*metalink3_parse(const char *xml) G_GNUC_MGET_NONNULL((1)),
	*metalink4_parse(const char *xml) G_GNUC_MGET_NONNULL((1));
void
	mget_metalink_free(mget_metalink_t **metalink),
	mget_metalink_sort_mirrors(mget_metalink_t *metalink);

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
	mget_vector_t
		*paths;
	mget_vector_t
		*sitemaps;
} ROBOTS;

ROBOTS *
	mget_robots_parse(const char *data);
void
	mget_robots_free(ROBOTS **robots);

/*
 * Progress bar routines
 */

typedef struct _mget_bar_st mget_bar_t;

mget_bar_t *
	mget_bar_init(mget_bar_t *bar, int nslots, int max_width);
void
	mget_bar_deinit(mget_bar_t *bar);
void
	mget_bar_free(mget_bar_t **bar);
void
	mget_bar_update(const mget_bar_t *bar, int slotpos, int max, int cur);
void
	mget_bar_print(mget_bar_t *bar, int slotpos, const char *s);
ssize_t
	mget_bar_vprintf(mget_bar_t *bar, int slotpos, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(3,0) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_bar_printf(mget_bar_t *bar, int slotpos, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL_ALL;


MGET_END_DECLS

#endif /* _LIBMGET_LIBMGET_H */
