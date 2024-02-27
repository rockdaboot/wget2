/*
 * Copyright (c) 2012-2015 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for libwget library routines
 *
 * Changelog
 * 28.12.2012  Tim Ruehsen  created (moved wget.h and list.h and into here)
 *
 */

#ifndef WGET_WGET_H
#define WGET_WGET_H

#include <stddef.h> // size_t
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h> // va_list
#include <stdio.h> // FILE
#include <stdlib.h>
#include <stdbool.h> // bool
#include <stdint.h> // int64_t

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
 *
 * Clang also defines __GNUC__. It promotes a GCC version of 4.2.1.
 */

#if defined __GNUC__ && defined __GNUC_MINOR__
#	define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#	define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if defined __clang_major__ && defined __clang_minor__
#	define CLANG_VERSION_AT_LEAST(major, minor) ((__clang_major__ > (major)) || (__clang_major__ == (major) && __clang_minor__ >= (minor)))
#else
#	define CLANG_VERSION_AT_LEAST(major, minor) 0
#endif

#if GCC_VERSION_AT_LEAST(2,5)
#	define WGET_GCC_CONST __attribute__ ((const))
#else
#	define WGET_GCC_CONST
#endif

#define WGET_GCC_NORETURN_FUNCPTR
#if GCC_VERSION_AT_LEAST(2,8) || __SUNPRO_C >= 0x5110
#	define WGET_GCC_NORETURN __attribute__ ((__noreturn__))
#	undef WGET_GCC_NORETURN_FUNCPTR
#	define G_GNUC_NORETURN_FUNCPTR WGET_GCC_NORETURN
#elif _MSC_VER >= 1200
#	define WGET_GCC_NORETURN __declspec (noreturn)
#elif __STDC_VERSION__ >= 201112
#	define WGET_GCC_NORETURN _Noreturn
#else
#	define WGET_GCC_NORETURN
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#	define WGET_GCC_PRINTF_FORMAT(a, b) __attribute__ ((format (printf, a, b)))
#	define WGET_GCC_UNUSED __attribute__ ((unused))
#else
#	define WGET_GCC_PRINTF_FORMAT(a, b)
#	define WGET_GCC_UNUSED
#endif

#if GCC_VERSION_AT_LEAST(2,96)
#	define WGET_GCC_PURE __attribute__ ((pure))
#else
#	define WGET_GCC_PURE
#endif

#if GCC_VERSION_AT_LEAST(3,0)
#	define WGET_GCC_MALLOC __attribute__ ((malloc))
#	define unlikely(expr) __builtin_expect(!!(expr), 0)
#	define likely(expr) __builtin_expect(!!(expr), 1)
#else
#	define WGET_GCC_MALLOC
#	define unlikely(expr) expr
#	define likely(expr) expr
#endif

#if GCC_VERSION_AT_LEAST(3,1)
#	define WGET_GCC_ALWAYS_INLINE __attribute__ ((always_inline))
#   define WGET_GCC_FLATTEN __attribute__ ((flatten))
#   define WGET_GCC_DEPRECATED __attribute__ ((deprecated))
#else
#	define WGET_GCC_ALWAYS_INLINE
#	define WGET_GCC_FLATTEN
#	define WGET_GCC_DEPRECATED
#endif

// nonnull is dangerous to use with current gcc <= 4.7.1.
// see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308
// we have to use e.g. the clang analyzer if we want NONNULL.
// but even clang is not perfect - don't use nonnull in production
#if GCC_VERSION_AT_LEAST(3,3)
#	define WGET_GCC_NONNULL_ALL __attribute__ ((nonnull))
#	define WGET_GCC_NONNULL(a) __attribute__ ((nonnull a))
#else
#	define WGET_GCC_NONNULL_ALL
#	define WGET_GCC_NONNULL(a)
#endif

#if GCC_VERSION_AT_LEAST(3,4)
#	define WGET_GCC_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#	define WGET_GCC_UNUSED_RESULT
#endif

#if GCC_VERSION_AT_LEAST(4,0)
#	define WGET_GCC_NULL_TERMINATED __attribute__((__sentinel__))
#else
#	define WGET_GCC_NULL_TERMINATED
#endif

#if GCC_VERSION_AT_LEAST(4,9) || CLANG_VERSION_AT_LEAST(7,0)
#	define WGET_GCC_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#	define WGET_GCC_RETURNS_NONNULL
#endif

#if GCC_VERSION_AT_LEAST(4,3) || CLANG_VERSION_AT_LEAST(6,0)
#	define WGET_GCC_ALLOC_SIZE(a) __attribute__ ((__alloc_size__(a)))
#	define WGET_GCC_ALLOC_SIZE2(a, b) __attribute__ ((__alloc_size__(a, b)))
#else
#	define WGET_GCC_ALLOC_SIZE(a)
#	define WGET_GCC_ALLOC_SIZE2(a, b)
#endif

#ifdef BUILDING_LIBWGET
#	define LIBWGET_WARN_UNUSED_RESULT WGET_GCC_UNUSED_RESULT
#else
#	define LIBWGET_WARN_UNUSED_RESULT
#endif

// Let C++ include C headers
#ifdef  __cplusplus
#	define WGET_BEGIN_DECLS  extern "C" {
#	define WGET_END_DECLS    }
#else
#	define WGET_BEGIN_DECLS
#	define WGET_END_DECLS
#endif

// define MALLOC_RETURNS_NONNULL when using appropriate implementations of the alloc functions
#ifdef MALLOC_RETURNS_NONNULL
#  define RETURNS_NONNULL WGET_GCC_RETURNS_NONNULL
#  define NULLABLE
#else
#  define RETURNS_NONNULL
#  if defined __clang_major__ && defined WGET_MANYWARNINGS
#    define NULLABLE _Nullable
#  else
#    define NULLABLE
#  endif
#endif

#undef GCC_VERSION_AT_LEAST
#undef CLANG_VERSION_AT_LEAST

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
#define WGET_BIND_INTERFACE  1019

#define WGET_HTTP_URL                   2000
#define WGET_HTTP_URL_ENCODING          2001
#define WGET_HTTP_URI                   2002
#define WGET_HTTP_COOKIE_STORE          2003
#define WGET_HTTP_HEADER_ADD            2004
//#define WGET_HTTP_HEADER_DEL          2005
//#define WGET_HTTP_HEADER_SET          2006
//#define WGET_HTTP_BIND_ADDRESS        2007
#define WGET_HTTP_CONNECTION_PTR        2008
#define WGET_HTTP_RESPONSE_KEEPHEADER   2009
#define WGET_HTTP_MAX_REDIRECTIONS      2010
#define WGET_HTTP_BODY_SAVEAS_STREAM    2011
#define WGET_HTTP_BODY_SAVEAS_FILE      2012
#define WGET_HTTP_BODY_SAVEAS_FD        2013
#define WGET_HTTP_BODY_SAVEAS_FUNC      2014
#define WGET_HTTP_HEADER_FUNC           2015
#define WGET_HTTP_SCHEME                2016
#define WGET_HTTP_BODY                  2017
#define WGET_HTTP_BODY_SAVEAS           2018
#define WGET_HTTP_USER_DATA             2019
#define WGET_HTTP_RESPONSE_IGNORELENGTH 2020
#define WGET_HTTP_DEBUG_SKIP_BODY       2021

// definition of error conditions
typedef enum {
	WGET_E_SUCCESS = 0, /* OK */
	WGET_E_UNKNOWN = -1, /* general error if nothing else appropriate */
	WGET_E_MEMORY = -2, /* memory allocation failure */
	WGET_E_INVALID = -3, /* invalid value to function */
	WGET_E_TIMEOUT = -4, /* timeout condition */
	WGET_E_CONNECT = -5, /* connect failure */
	WGET_E_HANDSHAKE = -6, /* general TLS handshake failure */
	WGET_E_CERTIFICATE = -7, /* general TLS certificate failure */
	WGET_E_TLS_DISABLED = -8, /* TLS was not enabled at compile time */
	WGET_E_XML_PARSE_ERR = -9, /* XML parsing failed */
	WGET_E_OPEN = -10, /* Failed to open file */
	WGET_E_IO = -11, /* General I/O error (read/write/stat/...) */
	WGET_E_UNSUPPORTED = -12, /* Unsupported function */
} wget_error;

WGETAPI const char *
	wget_strerror(wget_error err);

typedef void wget_global_func(const char *, size_t);

WGETAPI void
	wget_global_init(int key, ...);
WGETAPI void
	wget_global_deinit(void);
WGETAPI const void * NULLABLE
	wget_global_get_ptr(int key);
WGETAPI int
	wget_global_get_int(int key);
WGETAPI wget_global_func *
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

// types for --restrict-file-names / wget_restrict_file_name()
#define WGET_RESTRICT_NAMES_NONE          0
#define WGET_RESTRICT_NAMES_UNIX       1<<0
#define WGET_RESTRICT_NAMES_WINDOWS    1<<1
#define WGET_RESTRICT_NAMES_NOCONTROL  1<<2
#define WGET_RESTRICT_NAMES_ASCII      1<<3
#define WGET_RESTRICT_NAMES_UPPERCASE  1<<4
#define WGET_RESTRICT_NAMES_LOWERCASE  1<<5

typedef int wget_update_load_fn(void *, FILE *fp);
typedef int wget_update_save_fn(void *, FILE *fp);

WGETAPI int
	wget_ready_2_read(int fd, int timeout);
WGETAPI int
	wget_ready_2_write(int fd, int timeout);
WGETAPI int
	wget_ready_2_transfer(int fd, int timeout, int mode);
WGETAPI int
	wget_strcmp(const char *s1, const char *s2) WGET_GCC_PURE;
WGETAPI int
	wget_strcasecmp(const char *s1, const char *s2) WGET_GCC_PURE;
WGETAPI int
	wget_strcasecmp_ascii(const char *s1, const char *s2) WGET_GCC_PURE;
WGETAPI int
	wget_strncasecmp_ascii(const char *s1, const char *s2, size_t n) WGET_GCC_PURE;
WGETAPI char *
	wget_strtolower(char *s);
WGETAPI int
	wget_strncmp(const char *s1, const char *s2, size_t n) WGET_GCC_PURE;
WGETAPI int
	wget_strncasecmp(const char *s1, const char *s2, size_t n) WGET_GCC_PURE;
WGETAPI void
	wget_memtohex(const unsigned char * __restrict src, size_t src_len, char * __restrict dst, size_t dst_size);
WGETAPI void
	wget_millisleep(int ms);
WGETAPI long long
	wget_get_timemillis(void);
WGETAPI int
	wget_percent_unescape(char *src);
WGETAPI int
	wget_match_tail(const char *s, const char *tail) WGET_GCC_PURE WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_match_tail_nocase(const char *s, const char *tail) WGET_GCC_PURE WGET_GCC_NONNULL_ALL;
WGETAPI char * NULLABLE
	wget_strnglob(const char *str, size_t n, int flags) WGET_GCC_PURE;
WGETAPI char *
	wget_human_readable(char *buf, size_t bufsize, uint64_t n);
WGETAPI int
	wget_get_screen_size(int *width, int *height);
WGETAPI ssize_t
	wget_fdgetline(char **buf, size_t *bufsize, int fd);
WGETAPI ssize_t
	wget_getline(char **buf, size_t *bufsize, FILE *fp);
WGETAPI FILE * NULLABLE
	wget_vpopenf(const char *type, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI FILE * NULLABLE
	wget_popenf(const char *type, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);
WGETAPI FILE * NULLABLE
	wget_popen2f(FILE **fpin, FILE **fpout, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(3,4);
WGETAPI pid_t
	wget_fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv);
WGETAPI pid_t
	wget_popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv);
WGETAPI char * NULLABLE
	wget_read_file(const char *fname, size_t *size) WGET_GCC_MALLOC;
WGETAPI int
	wget_update_file(const char *fname, wget_update_load_fn *load_func, wget_update_save_fn *save_func, void *context);
WGETAPI int
	wget_truncate(const char *path, off_t length);
WGETAPI const char *
	wget_local_charset_encoding(void);
WGETAPI int
	wget_memiconv(const char *src_encoding, const void *src, size_t srclen, const char *dst_encoding, char **out, size_t *outlen);
WGETAPI char * NULLABLE
	wget_striconv(const char *src, const char *src_encoding, const char *dst_encoding) WGET_GCC_MALLOC;
WGETAPI bool
	wget_str_needs_encoding(const char *s) WGET_GCC_PURE;
WGETAPI bool
	wget_str_is_valid_utf8(const char *utf8) WGET_GCC_PURE;
WGETAPI char * NULLABLE
	wget_str_to_utf8(const char *src, const char *encoding) WGET_GCC_MALLOC;
WGETAPI char * NULLABLE
	wget_utf8_to_str(const char *src, const char *encoding) WGET_GCC_MALLOC;
WGETAPI const char *
	wget_str_to_ascii(const char *src);

/**
 * WGET_COMPATIBILITY:
 *
 * General compatibility functions
 */

WGETAPI size_t
	wget_strlcpy(char *__restrict dst, const char *__restrict src, size_t size);
WGETAPI ssize_t
	wget_strscpy(char *__restrict dst, const char *__restrict src, size_t size);

/**
 * \ingroup libwget-list
 *
 * Type for double linked lists and list entries.
 */
typedef struct wget_list_st wget_list;
typedef int wget_list_browse_fn(void *context, void *elem);

WGETAPI void * NULLABLE
	wget_list_append(wget_list **list, const void *data, size_t size) WGET_GCC_NONNULL_ALL;
WGETAPI void * NULLABLE
	wget_list_prepend(wget_list **list, const void *data, size_t size) WGET_GCC_NONNULL_ALL;
WGETAPI void * NULLABLE
	wget_list_getfirst(const wget_list *list) WGET_GCC_CONST;
WGETAPI void * NULLABLE
	wget_list_getlast(const wget_list *list) WGET_GCC_PURE;
WGETAPI void * NULLABLE
	wget_list_getnext(const void *elem) WGET_GCC_PURE;
WGETAPI void
	wget_list_remove(wget_list **list, void *elem) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_list_free(wget_list **list) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_list_browse(const wget_list *list, wget_list_browse_fn *browse, void *context) WGET_GCC_NONNULL((2));

/**
 * \ingroup libwget-xalloc
 *
 * Memory allocation function pointers
 * @{
 */

// Don't leave freed pointers hanging around
#define wget_xfree(a) do { if (a) { wget_free((void *)(a)); a=NULL; } } while (0)

/// Type of malloc() function
typedef void *wget_malloc_function(size_t);

/// Type of calloc() function
typedef void *wget_calloc_function(size_t, size_t);

/// Type of realloc() function
typedef void *wget_realloc_function(void *, size_t);

/// Type of free() function
typedef void wget_free_function(void *);

/* For use in callbacks */
extern WGETAPI wget_malloc_function *wget_malloc_fn;
extern WGETAPI wget_calloc_function *wget_calloc_fn;
extern WGETAPI wget_realloc_function *wget_realloc_fn;
extern WGETAPI wget_free_function *wget_free;

// we use (inline) functions here to apply function attributes
RETURNS_NONNULL LIBWGET_WARN_UNUSED_RESULT WGET_GCC_ALLOC_SIZE(1) WGET_GCC_MALLOC
static inline void * NULLABLE wget_malloc(size_t size)
{
	return wget_malloc_fn(size);
}

RETURNS_NONNULL LIBWGET_WARN_UNUSED_RESULT WGET_GCC_ALLOC_SIZE2(1,2) WGET_GCC_MALLOC
static inline void * NULLABLE wget_calloc(size_t nmemb, size_t size)
{
	return wget_calloc_fn(nmemb, size);
}

RETURNS_NONNULL LIBWGET_WARN_UNUSED_RESULT WGET_GCC_ALLOC_SIZE(2)
static inline void * NULLABLE wget_realloc(void *ptr, size_t size)
{
	return wget_realloc_fn(ptr, size);
}

/** @} */

/*
 * String/Memory routines, slightly different than standard functions
 */

LIBWGET_WARN_UNUSED_RESULT WGET_GCC_ALLOC_SIZE(2)
WGETAPI void * NULLABLE
	wget_memdup(const void *m, size_t n);

LIBWGET_WARN_UNUSED_RESULT WGET_GCC_MALLOC
WGETAPI char * NULLABLE
	wget_strdup(const char *s);

LIBWGET_WARN_UNUSED_RESULT WGET_GCC_ALLOC_SIZE(2)
WGETAPI char * NULLABLE
	wget_strmemdup(const void *m, size_t n);

WGETAPI size_t
	wget_strmemcpy(char *__restrict s, size_t ssize, const void *__restrict m, size_t n);

LIBWGET_WARN_UNUSED_RESULT WGET_GCC_NONNULL_ALL
WGETAPI void * NULLABLE
	wget_strmemcpy_a(char *s, size_t ssize, const void *m, size_t n);

/*
 * Base64 routines
 */

WGETAPI bool
	wget_base64_is_string(const char *src) WGET_GCC_PURE;
WGETAPI size_t
	wget_base64_get_decoded_length(size_t len) WGET_GCC_PURE;
WGETAPI size_t
	wget_base64_get_encoded_length(size_t len) WGET_GCC_PURE;
WGETAPI size_t
	wget_base64_decode(char *__restrict dst, const char *__restrict src, size_t n) WGET_GCC_NONNULL_ALL;
WGETAPI size_t
	wget_base64_encode(char *__restrict dst, const char *__restrict src, size_t n) WGET_GCC_NONNULL_ALL;
WGETAPI size_t
	wget_base64_urlencode(char *__restrict dst, const char *__restrict src, size_t n) WGET_GCC_NONNULL_ALL;
WGETAPI char * NULLABLE
	wget_base64_decode_alloc(const char *src, size_t n, size_t *outlen) WGET_GCC_NONNULL((1));
WGETAPI char * NULLABLE
	wget_base64_encode_alloc(const char *src, size_t n) WGET_GCC_NONNULL_ALL;
WGETAPI char * NULLABLE
	wget_base64_encode_vprintf_alloc(const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(1,0) WGET_GCC_NONNULL_ALL;
WGETAPI char * NULLABLE
	wget_base64_encode_printf_alloc(const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(1,2) WGET_GCC_NONNULL_ALL;

/*
 * Bitmap routines
 */

typedef struct wget_bitmap_st wget_bitmap;

WGETAPI int
	wget_bitmap_init(wget_bitmap **bitmap, unsigned bits);
WGETAPI void
	wget_bitmap_free(wget_bitmap **bitmap);
WGETAPI void
	wget_bitmap_set(wget_bitmap *bitmap, unsigned n); // n is the index
WGETAPI void
	wget_bitmap_clear(wget_bitmap *bitmap, unsigned n);
WGETAPI bool
	wget_bitmap_get(const wget_bitmap *bitmap, unsigned n);

/*
 * Buffer routines
 */

typedef struct {
	char *
		data; //!< pointer to internal memory
	size_t
		length; //!< number of bytes in 'data'
	size_t
		size; //!< capacity of 'data' (terminating 0 byte doesn't count here)
	bool
		release_data : 1, //!< 'data' has been malloc'ed and must be freed
		release_buf : 1, //!< wget_buffer structure has been malloc'ed and must be freed
		error : 1; //!< a memory failure occurred, the result in 'data' is likely erroneous
} wget_buffer;

WGETAPI int
	wget_buffer_init(wget_buffer *buf, char *data, size_t size) WGET_GCC_NONNULL((1));
WGETAPI wget_buffer *
	wget_buffer_alloc(size_t size) WGET_GCC_MALLOC WGET_GCC_ALLOC_SIZE(1) RETURNS_NONNULL LIBWGET_WARN_UNUSED_RESULT;
WGETAPI int
	wget_buffer_ensure_capacity(wget_buffer *buf, size_t size) LIBWGET_WARN_UNUSED_RESULT;
WGETAPI void
	wget_buffer_deinit(wget_buffer *buf) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_buffer_free(wget_buffer **buf);
WGETAPI void
	wget_buffer_free_data(wget_buffer *buf);
WGETAPI void
	wget_buffer_reset(wget_buffer *buf);
WGETAPI size_t
	wget_buffer_memcpy(wget_buffer *buf, const void *data, size_t length);
WGETAPI size_t
	wget_buffer_memcat(wget_buffer *buf, const void *data, size_t length);
WGETAPI size_t
	wget_buffer_strcpy(wget_buffer *buf, const char *s);
WGETAPI size_t
	wget_buffer_strcat(wget_buffer *buf, const char *s);
WGETAPI size_t
	wget_buffer_bufcpy(wget_buffer *buf, wget_buffer *src);
WGETAPI size_t
	wget_buffer_bufcat(wget_buffer *buf, wget_buffer *src);
WGETAPI size_t
	wget_buffer_memset(wget_buffer *buf, char c, size_t length);
WGETAPI size_t
	wget_buffer_memset_append(wget_buffer *buf, char c, size_t length);
WGETAPI char *
	wget_buffer_trim(wget_buffer *buf);
WGETAPI size_t
	wget_buffer_vprintf_append(wget_buffer *buf, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_buffer_printf_append(wget_buffer *buf, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);
WGETAPI size_t
	wget_buffer_vprintf(wget_buffer *buf, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_buffer_printf(wget_buffer *buf, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);

/*
 * Printf-style routines
 */

WGETAPI size_t
	wget_vasprintf(char **__restrict strp, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_asprintf(char **__restrict strp, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);
WGETAPI char * NULLABLE
	wget_vaprintf(const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(1,0);
WGETAPI char * NULLABLE
	wget_aprintf(const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(1,2);
WGETAPI size_t
	wget_vfprintf(FILE *__restrict fp, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI size_t
	wget_fprintf(FILE *__restrict fp, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);
WGETAPI size_t
	wget_printf(const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(1,2);
WGETAPI size_t
	wget_vsnprintf(char *__restrict str, size_t size, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(3,0);
WGETAPI size_t
	wget_snprintf(char *__restrict str, size_t size, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(3,4);

/*
 * Logger routines
 */

typedef struct wget_logger_st wget_logger;
typedef void wget_logger_func(const char *buf , size_t len) WGET_GCC_NONNULL_ALL;

WGETAPI void
	wget_logger_set_func(wget_logger *logger, wget_logger_func *func);
WGETAPI void
	wget_logger_set_stream(wget_logger *logger, FILE *fp);
WGETAPI void
	wget_logger_set_file(wget_logger *logger, const char *fname);
WGETAPI wget_logger_func * NULLABLE
	wget_logger_get_func(wget_logger *logger) WGET_GCC_PURE;
WGETAPI FILE * NULLABLE
	wget_logger_get_stream(wget_logger *logger) WGET_GCC_PURE;
WGETAPI const char * NULLABLE
	wget_logger_get_file(wget_logger *logger) WGET_GCC_PURE;
WGETAPI bool
	wget_logger_is_active(wget_logger *logger) WGET_GCC_PURE;

/*
 * Logging routines
 */

#define WGET_LOGGER_INFO   1
#define WGET_LOGGER_ERROR  2
#define WGET_LOGGER_DEBUG  3

WGETAPI void
	wget_info_vprintf(const char *__restrict fmt, va_list args) WGET_GCC_NONNULL_ALL WGET_GCC_PRINTF_FORMAT(1,0);
WGETAPI void
	wget_info_printf(const char *__restrict fmt, ...) WGET_GCC_NONNULL((1)) WGET_GCC_PRINTF_FORMAT(1,2);
WGETAPI void
	wget_error_vprintf(const char *__restrict fmt, va_list args) WGET_GCC_NONNULL_ALL WGET_GCC_PRINTF_FORMAT(1,0);
WGETAPI void
	wget_error_printf(const char *__restrict fmt, ...) WGET_GCC_NONNULL((1)) WGET_GCC_PRINTF_FORMAT(1,2);
WGETAPI void WGET_GCC_NONNULL((1)) WGET_GCC_NORETURN WGET_GCC_PRINTF_FORMAT(1,2)
	wget_error_printf_exit(const char *__restrict fmt, ...);
WGETAPI void
	wget_debug_vprintf(const char *__restrict fmt, va_list args) WGET_GCC_NONNULL_ALL WGET_GCC_PRINTF_FORMAT(1,0);
WGETAPI void
	wget_debug_printf(const char *__restrict fmt, ...) WGET_GCC_NONNULL((1)) WGET_GCC_PRINTF_FORMAT(1,2);
WGETAPI void
	wget_debug_write(const char *buf, size_t len) WGET_GCC_NONNULL_ALL;
WGETAPI wget_logger *
	wget_get_logger(int id) WGET_GCC_CONST;

/*
 * Vector datatype routines
 */

typedef struct wget_vector_st wget_vector;
typedef int wget_vector_compare_fn(const void *elem1, const void *elem2);
typedef int wget_vector_find_fn(void *elem);
typedef int wget_vector_browse_fn(void *ctx, void *elem);
typedef void wget_vector_destructor(void *elem);

WGETAPI wget_vector * NULLABLE
	wget_vector_create(int max, wget_vector_compare_fn *cmp) WGET_GCC_MALLOC;
WGETAPI void
	wget_vector_set_resize_factor(wget_vector *v, float off);
WGETAPI int
	wget_vector_find(const wget_vector *v, const void *elem) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_findext(const wget_vector *v, int start, int direction, wget_vector_find_fn *find) WGET_GCC_NONNULL((4));
WGETAPI bool
	wget_vector_contains(const wget_vector *v, const void *elem) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_insert(wget_vector *v, const void *elem, int pos) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_insert_sorted(wget_vector *v, const void *elem) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_add_memdup(wget_vector *v, const void *elem, size_t size) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_add(wget_vector *v, const void *elem) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_add_vprintf(wget_vector *v, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI int
	wget_vector_add_printf(wget_vector *v, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);
WGETAPI int
	wget_vector_replace(wget_vector *v, const void *elem, int pos) WGET_GCC_NONNULL((2));
WGETAPI int
	wget_vector_move(wget_vector *v, int old_pos, int new_pos);
WGETAPI int
	wget_vector_swap(wget_vector *v, int pos1, int pos2);
WGETAPI int
	wget_vector_remove(wget_vector *v, int pos);
WGETAPI int
	wget_vector_remove_nofree(wget_vector *v, int pos);
WGETAPI int
	wget_vector_size(const wget_vector *v) WGET_GCC_PURE;
WGETAPI int
	wget_vector_browse(const wget_vector *v, wget_vector_browse_fn *browse, void *ctx) WGET_GCC_NONNULL((2));
WGETAPI void
	wget_vector_free(wget_vector **v);
WGETAPI void
	wget_vector_clear(wget_vector *v);
WGETAPI void
	wget_vector_clear_nofree(wget_vector *v);
WGETAPI void * NULLABLE
	wget_vector_get(const wget_vector *v, int pos) WGET_GCC_PURE;
WGETAPI void
	wget_vector_setcmpfunc(wget_vector *v, wget_vector_compare_fn *cmp) WGET_GCC_NONNULL((2));
WGETAPI void
	wget_vector_set_destructor(wget_vector *v, wget_vector_destructor *destructor);
WGETAPI void
	wget_vector_sort(wget_vector *v);

/**
 * \ingroup libwget-hashmap
 *
 * @{
 */

/// Type of the hashmap
typedef struct wget_hashmap_st wget_hashmap;

/// Type of the hashmap compare function
typedef int wget_hashmap_compare_fn(const void *key1, const void *key2);

/// Type of the hashmap hash function
typedef unsigned int wget_hashmap_hash_fn(const void *key);

/// Type of the hashmap browse callback function
typedef int wget_hashmap_browse_fn(void *ctx, const void *key, void *value);

/// Type of the hashmap key destructor function
typedef void wget_hashmap_key_destructor(void *key);

/// Type of the hashmap value destructor function
typedef void wget_hashmap_value_destructor(void *value);
/** @} */

WGETAPI wget_hashmap * NULLABLE
	wget_hashmap_create(int max, wget_hashmap_hash_fn *hash, wget_hashmap_compare_fn *cmp) WGET_GCC_MALLOC;
WGETAPI void
	wget_hashmap_set_resize_factor(wget_hashmap *h, float factor);
WGETAPI int
	wget_hashmap_put(wget_hashmap *h, const void *key, const void *value);
WGETAPI int
	wget_hashmap_size(const wget_hashmap *h) WGET_GCC_PURE;
WGETAPI int
	wget_hashmap_browse(const wget_hashmap *h, wget_hashmap_browse_fn *browse, void *ctx);
WGETAPI void
	wget_hashmap_free(wget_hashmap **h);
WGETAPI void
	wget_hashmap_clear(wget_hashmap *h);
WGETAPI int
	wget_hashmap_get(const wget_hashmap *h, const void *key, void **value) WGET_GCC_UNUSED_RESULT;
#define wget_hashmap_get(a, b, c) wget_hashmap_get((a), (b), (void **)(c))
WGETAPI int
	wget_hashmap_contains(const wget_hashmap *h, const void *key);
WGETAPI int
	wget_hashmap_remove(wget_hashmap *h, const void *key);
WGETAPI int
	wget_hashmap_remove_nofree(wget_hashmap *h, const void *key);
WGETAPI void
	wget_hashmap_setcmpfunc(wget_hashmap *h, wget_hashmap_compare_fn *cmp);
WGETAPI int
	wget_hashmap_sethashfunc(wget_hashmap *h, wget_hashmap_hash_fn *hash);
WGETAPI void
	wget_hashmap_set_key_destructor(wget_hashmap *h, wget_hashmap_key_destructor *destructor);
WGETAPI void
	wget_hashmap_set_value_destructor(wget_hashmap *h, wget_hashmap_value_destructor *destructor);
WGETAPI void
	wget_hashmap_set_load_factor(wget_hashmap *h, float factor);

/// Type of the hashmap iterator
typedef struct wget_hashmap_iterator_st wget_hashmap_iterator;

WGETAPI wget_hashmap_iterator * NULLABLE
	wget_hashmap_iterator_alloc(wget_hashmap *h) WGET_GCC_MALLOC;
WGETAPI void
	wget_hashmap_iterator_free(wget_hashmap_iterator **iter);
WGETAPI void * NULLABLE
	wget_hashmap_iterator_next(wget_hashmap_iterator *iter, void **value);

/**
 * \ingroup libwget-stringmap
 *
 * @{
 */

/// Type of the stringmap
typedef wget_hashmap wget_stringmap;

/// Type of the stringmap compare function
typedef int wget_stringmap_compare_fn(const char *key1, const char *key2);

/// Type of the stringmap hash function
typedef unsigned int wget_stringmap_hash_fn(const char *key);

/// Type of the stringmap browse callback function
typedef int wget_stringmap_browse_fn(void *ctx, const char *key, void *value);

/// Type of the stringmap key destructor function
typedef void wget_stringmap_key_destructor(char *key);

/// Type of the stringmap value destructor function
typedef void wget_stringmap_value_destructor(void *value);

/// Type of the stringmap iterator
typedef wget_hashmap_iterator wget_stringmap_iterator;

/// Wrapper around wget_hashmap_iterator_alloc().
#define wget_stringmap_iterator_alloc wget_hashmap_iterator_alloc
/// Wrapper around wget_hashmap_iterator_free().
#define wget_stringmap_iterator_free wget_hashmap_iterator_free

WGETAPI wget_stringmap * NULLABLE
	wget_stringmap_create(int max) WGET_GCC_MALLOC;
WGETAPI wget_stringmap * NULLABLE
	wget_stringmap_create_nocase(int max) WGET_GCC_MALLOC;
/** @} */

/**
 * \ingroup libwget-stringmap
 *
 * @{
 */

/**
 * \param[in] h Stringmap to put data into
 * \param[in] key Key to insert into \p h
 * \param[in] value Value to insert into \p h
 * \return 0 if inserted a new entry, 1 if entry existed
 *
 * Insert a key/value pair into stringmap \p h.
 *
 * \p key and \p value are *not* cloned, the stringmap takes 'ownership' of both.
 *
 * If \p key already exists and the pointer values the old and the new key differ,
 * the old key will be destroyed by calling the key destructor function (default is free()).
 *
 * To realize a hashset (just keys without values), \p value may be %NULL.
 *
 * Neither \p h nor \p key must be %NULL.
 */
static inline
int wget_stringmap_put(wget_stringmap *h, const char *key, const void *value)
{
	return wget_hashmap_put(h, key, value);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to search for
 * \param[out] value Value to be returned
 * \return 1 if \p key has been found, 0 if not found
 *
 * Get the value for a given key.
 *
 * Neither \p h nor \p key must be %NULL.
 */
static inline WGET_GCC_UNUSED_RESULT
int wget_stringmap_get(const wget_stringmap *h, const char *key, void **value)
{
	return wget_hashmap_get(h, key, value);
}
#define wget_stringmap_get(h, k, v) wget_stringmap_get((h), (k), (void **)(v))

/**
 * \param[in] h Stringmap
 * \param[in] key Key to search for
 * \return 1 if \p key has been found, 0 if not found
 *
 * Check if \p key exists in \p h.
 */
static inline
int wget_stringmap_contains(const wget_stringmap *h, const char *key)
{
	return wget_hashmap_contains(h, key);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to be removed
 * \return 1 if \p key has been removed, 0 if not found
 *
 * Remove \p key from stringmap \p h.
 *
 * If \p key is found, the key and value destructor functions are called
 * when removing the entry from the stringmap.
 */
static inline
int wget_stringmap_remove(wget_stringmap *h, const char *key)
{
	return wget_hashmap_remove(h, key);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to be removed
 * \return 1 if \p key has been removed, 0 if not found
 *
 * Remove \p key from stringmap \p h.
 *
 * Key and value destructor functions are *not* called when removing the entry from the stringmap.
 */
static inline
int wget_stringmap_remove_nofree(wget_stringmap *h, const char *key)
{
	return wget_hashmap_remove_nofree(h, key);
}

/**
 * \param[in] h Stringmap to be free'd
 *
 * Remove all entries from stringmap \p h and free the stringmap instance.
 *
 * Key and value destructor functions are called for each entry in the stringmap.
 */
static inline
void wget_stringmap_free(wget_stringmap **h)
{
	wget_hashmap_free(h);
}

/**
 * \param[in] h Stringmap to be cleared
 *
 * Remove all entries from stringmap \p h.
 *
 * Key and value destructor functions are called for each entry in the stringmap.
 */
static inline
void wget_stringmap_clear(wget_stringmap *h)
{
	wget_hashmap_clear(h);
}

/**
 * \param[in] h Stringmap
 * \return Number of entries in stringmap \p h
 *
 * Return the number of entries in the stringmap \p h.
 */
static inline
int wget_stringmap_size(const wget_stringmap *h)
{
	return wget_hashmap_size(h);
}

/**
 * \param[in] h Stringmap
 * \param[in] browse Function to be called for each element of \p h
 * \param[in] ctx Context variable use as param to \p browse
 * \return Return value of the last call to \p browse
 *
 * Call function \p browse for each element of stringmap \p h or until \p browse
 * returns a value not equal to zero.
 *
 * \p browse is called with \p ctx and the pointer to the current element.
 *
 * The return value of the last call to \p browse is returned or 0 if either \p h or \p browse is %NULL.
 */
static inline
int wget_stringmap_browse(const wget_stringmap *h, wget_stringmap_browse_fn *browse, void *ctx)
{
	return wget_hashmap_browse(h, (wget_hashmap_browse_fn *) browse, ctx);
}

/**
 * \param[in] h Stringmap
 * \param[in] cmp Comparison function used to find keys
 *
 * Set the comparison function.
 */
static inline
void wget_stringmap_setcmpfunc(wget_stringmap *h, wget_stringmap_compare_fn *cmp)
{
	wget_hashmap_setcmpfunc(h, (wget_hashmap_compare_fn *) cmp);
}

/**
 * \param[in] h Stringmap
 * \param[in] hash Hash function used to hash keys
 *
 * Set the key hash function.
 *
 * The keys of all entries in the stringmap will be hashed again.
 */
static inline
int wget_stringmap_sethashfunc(wget_stringmap *h, wget_stringmap_hash_fn *hash)
{
	return wget_hashmap_sethashfunc(h, (wget_hashmap_hash_fn *) hash);
}

/**
 * \param[in] h Stringmap
 * \param[in] destructor Destructor function for keys
 *
 * Set the key destructor function.
 *
 * Default is free().
 */
static inline
void wget_stringmap_set_key_destructor(wget_hashmap *h, wget_stringmap_key_destructor *destructor)
{
	wget_hashmap_set_key_destructor(h, (wget_hashmap_key_destructor *) destructor);
}

/**
 * \param[in] h Stringmap
 * \param[in] destructor Destructor function for values
 *
 * Set the value destructor function.
 *
 * Default is free().
 */
static inline
void wget_stringmap_set_value_destructor(wget_hashmap *h, wget_stringmap_value_destructor *destructor)
{
	wget_hashmap_set_value_destructor(h, (wget_hashmap_value_destructor *) destructor);
}

/**
 * \param[in] h Stringmap
 * \param[in] factor The load factor
 *
 * Set the load factor function.
 *
 * The load factor is determines when to resize the internal memory.
 * 0.75 means "resize if 75% or more of all slots are used".
 *
 * The resize strategy is set by wget_stringmap_set_growth_policy().
 *
 * The resize (and rehashing) occurs earliest on the next insertion of a new key.
 *
 * Default is 0.75.
 */
static inline
void wget_stringmap_set_load_factor(wget_stringmap *h, float factor)
{
	wget_hashmap_set_load_factor(h, factor);
}

/**
 * \param[in] h Stringmap
 * \param[in] off Stringmap growth factor
 *
 * Set the factor for resizing the stringmap when it's load factor is reached.
 *
 * The new size is 'factor * oldsize'. If the new size is less or equal 0,
 * the involved put function will do nothing and the internal state of
 * the stringmap will not change.
 *
 * Default is 2.
 */
static inline
void wget_stringmap_set_resize_factor(wget_stringmap *h, float factor)
{
	wget_hashmap_set_resize_factor(h, factor);
}

/**
 * \param[in] iter Stringmap iterator
 * \param[out] value Pointer to the value belonging to the returned key
 * \return Pointer to the key or NULL if no more elements left
 *
 * Returns the next key / value in the stringmap. If all key/value pairs have been
 * iterated over the function returns NULL and \p value is untouched.
 *
 * When iterating over a stringmap, the order of returned key/value pairs is not defined.
 */
static inline
void * NULLABLE wget_stringmap_iterator_next(wget_stringmap_iterator *h, void **value)
{
	return wget_hashmap_iterator_next(h, (void **) value);
}

/** @} */

/*
 * Thread wrapper routines
 */

typedef unsigned long wget_thread_id;
typedef struct wget_thread_st *wget_thread;
typedef struct wget_thread_mutex_st *wget_thread_mutex;
typedef struct wget_thread_cond_st *wget_thread_cond;

WGETAPI int
	wget_thread_start(wget_thread *thread, void *(*start_routine)(void *), void *arg, int flags);
WGETAPI int
	wget_thread_mutex_init(wget_thread_mutex *mutex);
WGETAPI int
	wget_thread_mutex_destroy(wget_thread_mutex *mutex);
WGETAPI void
	wget_thread_mutex_lock(wget_thread_mutex mutex);
WGETAPI void
	wget_thread_mutex_unlock(wget_thread_mutex mutex);
WGETAPI int
	wget_thread_kill(wget_thread thread, int sig);
WGETAPI int
	wget_thread_cancel(wget_thread thread);
WGETAPI int
	wget_thread_join(wget_thread *thread);
WGETAPI int
	wget_thread_cond_init(wget_thread_cond *cond);
WGETAPI int
	wget_thread_cond_destroy(wget_thread_cond *cond);
WGETAPI int
	wget_thread_cond_signal(wget_thread_cond cond);
WGETAPI int
	wget_thread_cond_wait(wget_thread_cond cond, wget_thread_mutex mutex, long long ms);
WGETAPI wget_thread_id
	wget_thread_self(void) WGET_GCC_CONST;
WGETAPI bool
	wget_thread_support(void) WGET_GCC_CONST;

/*
 * Decompressor routines
 */

typedef struct wget_decompressor_st wget_decompressor;
typedef int wget_decompressor_sink_fn(void *context, const char *data, size_t length);
typedef int wget_decompressor_error_handler(wget_decompressor *dc, int err);

typedef enum {
	wget_content_encoding_unknown = -1,
	wget_content_encoding_identity = 0,
	wget_content_encoding_gzip = 1,
	wget_content_encoding_deflate = 2,
	wget_content_encoding_xz = 3,
	wget_content_encoding_lzma = 4,
	wget_content_encoding_bzip2 = 5,
	wget_content_encoding_brotli = 6,
	wget_content_encoding_zstd = 7,
	wget_content_encoding_lzip = 8,
	wget_content_encoding_max = 9
} wget_content_encoding;

WGETAPI WGET_GCC_PURE wget_content_encoding
	wget_content_encoding_by_name(const char *name);
WGETAPI WGET_GCC_PURE const char * NULLABLE
	wget_content_encoding_to_name(wget_content_encoding type);
WGETAPI wget_decompressor * NULLABLE
	wget_decompress_open(wget_content_encoding encoding, wget_decompressor_sink_fn *data_sink, void *context);
WGETAPI void
	wget_decompress_close(wget_decompressor *dc);
WGETAPI int
	wget_decompress(wget_decompressor *dc, const char *src, size_t srclen);
WGETAPI void
	wget_decompress_set_error_handler(wget_decompressor *dc, wget_decompressor_error_handler *error_handler);
WGETAPI void * NULLABLE
	wget_decompress_get_context(wget_decompressor *dc);

/*
 * URI/IRI routines
 */

typedef enum {
	WGET_IRI_SCHEME_HTTP = 0,
	WGET_IRI_SCHEME_HTTPS = 1
} wget_iri_scheme;

// flags for wget_iri_get_basename()
#define WGET_IRI_WITH_QUERY  1

/**
 * \ingroup libwget-iri
 *
 * @{
 *
 * Internal representation of a URI/IRI.
 */
struct wget_iri_st {
	/**
	 * Pointer to the original URI string, unescaped and converted to UTF-8.
	 */
	const char *
		uri;

	/**
	 * Pointer to the URI which does not contain credentials.
	*/
	const char *
		safe_uri;
	/**
	 * Display part, if present.
	 */
	const char *
		display;
	/**
	 * Username, if present.
	 */
	const char *
		userinfo;
	/**
	 * Password, if present.
	 */
	const char *
		password;
	/**
	 * Hostname (or literal IP address). Lowercase and unescaped.
	 */
	const char *
		host;
	/**
	 * Path, if present. Unescaped.
	 */
	const char *
		path;
	/**
	 * Query part, if present. Unescaped.
	 */
	const char *
		query;
	/**
	 * Fragment part, if present. Unescaped.
	 */
	const char *
		fragment;
	/**
	 * Connection part. This is not specified by the spec, it's just a helper.
	 *
	 * The connection part is formed by the scheme, the hostname and the port together. Example:
	 *
	 *     https://www.example.com:8080
	 *
	 */
	const char *
		connection_part;
	/**
	 * Length of the directory part in `path`.
	 *
	 * This is the length from the beginning up to the last slash (`/`).
	 */
	size_t
		dirlen;
	/// size of memory to hold the parsed URI, it contains 0 bytes
	size_t
		msize;
	/// Port number
	uint16_t
		port;
	/// URI/IRI scheme (`http` or `https`).
	wget_iri_scheme
		scheme;
	/// If set, port was explicitly given
	bool
		port_given : 1;
	/// If set, free uri in iri_free()
	bool
		uri_allocated : 1;
	/// If set, free host in iri_free()
	bool
		host_allocated : 1;
	/// If set, free path in iri_free()
	bool
		path_allocated : 1;
	/// If set, free query in iri_free()
	bool
		query_allocated : 1;
	/// If set, free fragment in iri_free()
	bool
		fragment_allocated : 1;
	/// If set, the hostname part is a literal IPv4/IPv6 address
	bool
		is_ip_address : 1;
};

typedef struct wget_iri_st wget_iri;
/** @} */

WGETAPI void
	wget_iri_test(void);
WGETAPI void
	wget_iri_free(wget_iri **iri);
WGETAPI void
	wget_iri_free_content(wget_iri *iri);
WGETAPI void
	wget_iri_set_defaultpage(const char *page);
WGETAPI int
	wget_iri_set_defaultport(wget_iri_scheme scheme, unsigned short port);
WGETAPI bool
	wget_iri_supported(const wget_iri *iri) WGET_GCC_PURE WGET_GCC_NONNULL_ALL;
WGETAPI bool
	wget_iri_isgendelim(char c) WGET_GCC_CONST;
WGETAPI bool
	wget_iri_issubdelim(char c) WGET_GCC_CONST;
WGETAPI bool
	wget_iri_isreserved(char c) WGET_GCC_CONST;
WGETAPI bool
	wget_iri_isunreserved(char c) WGET_GCC_CONST;
WGETAPI int
	wget_iri_compare(const wget_iri *iri1, const wget_iri *iri2) WGET_GCC_PURE;
WGETAPI char *
	wget_iri_unescape_inline(char *src) WGET_GCC_NONNULL_ALL;
WGETAPI char *
	wget_iri_unescape_url_inline(char *src) WGET_GCC_NONNULL_ALL;
WGETAPI wget_iri *
	wget_iri_parse(const char *uri, const char *encoding);
WGETAPI wget_iri * NULLABLE
	wget_iri_parse_base(const wget_iri *base, const char *url, const char *encoding);
WGETAPI wget_iri * NULLABLE
	wget_iri_clone(const wget_iri *iri);
WGETAPI const char * NULLABLE
	wget_iri_get_connection_part(const wget_iri *iri, wget_buffer *buf);
WGETAPI const char *
	wget_iri_relative_to_abs(const wget_iri *base, const char *val, size_t len, wget_buffer *buf);
WGETAPI const char *
	wget_iri_escape(const char *src, wget_buffer *buf);
WGETAPI const char *
	wget_iri_escape_path(const char *src, wget_buffer *buf) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_iri_escape_query(const char *src, wget_buffer *buf) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_iri_get_escaped_host(const wget_iri *iri, wget_buffer *buf) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_iri_get_escaped_resource(const wget_iri *iri, wget_buffer *buf) WGET_GCC_NONNULL_ALL;
WGETAPI char *
	wget_iri_get_path(const wget_iri *iri, wget_buffer *buf, const char *encoding) WGET_GCC_NONNULL((1,2));
WGETAPI char *
	wget_iri_get_query_as_filename(const wget_iri *iri, wget_buffer *buf, const char *encoding) WGET_GCC_NONNULL((1,2));
WGETAPI char *
	wget_iri_get_basename(const wget_iri *iri, wget_buffer *buf, const char *encoding, int flags) WGET_GCC_NONNULL((1,2));
WGETAPI wget_iri_scheme
	wget_iri_set_scheme(wget_iri *iri, wget_iri_scheme scheme);
WGETAPI const char * NULLABLE
	wget_iri_scheme_get_name(wget_iri_scheme scheme);

/*
 * Cookie routines
 */

// typedef for cookie database
typedef struct wget_cookie_db_st wget_cookie_db;

// typedef for cookie
typedef struct wget_cookie_st wget_cookie;

WGETAPI wget_cookie * NULLABLE
	wget_cookie_init(wget_cookie *cookie);
WGETAPI void
	wget_cookie_deinit(wget_cookie *cookie);
WGETAPI void
	wget_cookie_free(wget_cookie **cookie);
WGETAPI char *
	wget_cookie_to_setcookie(wget_cookie *cookie);
WGETAPI const char *
	wget_cookie_parse_setcookie(const char *s, wget_cookie **cookie) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_cookie_normalize_cookies(const wget_iri *iri, const wget_vector *cookies);
WGETAPI int
	wget_cookie_store_cookie(wget_cookie_db *cookie_db, wget_cookie *cookie);
WGETAPI void
	wget_cookie_store_cookies(wget_cookie_db *cookie_db, wget_vector *cookies);
WGETAPI int
	wget_cookie_normalize(const wget_iri *iri, wget_cookie *cookie);
WGETAPI int
	wget_cookie_check_psl(const wget_cookie_db *cookie_db, const wget_cookie *cookie);
WGETAPI wget_cookie_db * NULLABLE
	wget_cookie_db_init(wget_cookie_db *cookie_db);
WGETAPI void
	wget_cookie_db_deinit(wget_cookie_db *cookie_db);
WGETAPI void
	wget_cookie_db_free(wget_cookie_db **cookie_db);
WGETAPI void
	wget_cookie_set_keep_session_cookies(wget_cookie_db *cookie_db, bool keep);
WGETAPI int
	wget_cookie_db_save(wget_cookie_db *cookie_db, const char *fname);
WGETAPI int
	wget_cookie_db_load(wget_cookie_db *cookie_db, const char *fname);
WGETAPI int
	wget_cookie_db_load_psl(wget_cookie_db *cookie_db, const char *fname);
WGETAPI char *
	wget_cookie_create_request_header(wget_cookie_db *cookie_db, const wget_iri *iri);

/*
 * HTTP Strict Transport Security (HSTS) routines
 */

/**
 * \ingroup libwget-hsts
 *
 * Structure representing HSTS database for storing HTTP Strict Transport Security (HSTS) entries
 */
typedef struct wget_hsts_db_st wget_hsts_db;

/**
 * \ingroup libwget-hsts
 *
 * It is possible to implement a custom HSTS database as a plugin.
 * See tests/test-plugin-dummy.c and tests/Makefile.am for details.
 */

typedef int wget_hsts_host_match_fn(const wget_hsts_db *hsts_db, const char *host, uint16_t port);
typedef wget_hsts_db *wget_hsts_db_init_fn(wget_hsts_db *hsts_db, const char *fname);
typedef void wget_hsts_db_deinit_fn(wget_hsts_db *hsts_db);
typedef void wget_hsts_db_free_fn(wget_hsts_db **hsts_db);
typedef void wget_hsts_db_add_fn(wget_hsts_db *hsts_db, const char *host, uint16_t port, int64_t maxage, bool include_subdomains);
typedef int wget_hsts_db_save_fn(wget_hsts_db *hsts_db);
typedef int wget_hsts_db_load_fn(wget_hsts_db *hsts_db);
typedef void wget_hsts_db_set_fname_fn(wget_hsts_db *hsts_db, const char *fname);

typedef struct {
	/// Callback replacing wget_hsts_host_match()
	wget_hsts_host_match_fn *host_match;
	/// Callback replacing wget_hsts_db_init()
	wget_hsts_db_init_fn *init;
	/// Callback replacing wget_hsts_db_deinit()
	wget_hsts_db_deinit_fn *deinit;
	/// Callback replacing wget_hsts_db_free()
	wget_hsts_db_free_fn *free;
	/// Callback replacing wget_hsts_db_add()
	wget_hsts_db_add_fn *add;
	/// Callback replacing wget_hsts_db_load()
	wget_hsts_db_load_fn *load;
	/// Callback replacing wget_hsts_db_save()
	wget_hsts_db_save_fn *save;
} wget_hsts_db_vtable;

WGETAPI wget_hsts_host_match_fn wget_hsts_host_match;
WGETAPI wget_hsts_db_init_fn wget_hsts_db_init;
WGETAPI wget_hsts_db_deinit_fn wget_hsts_db_deinit;
WGETAPI wget_hsts_db_free_fn wget_hsts_db_free;
WGETAPI wget_hsts_db_add_fn wget_hsts_db_add;
WGETAPI wget_hsts_db_load_fn wget_hsts_db_load;
WGETAPI wget_hsts_db_save_fn wget_hsts_db_save;
WGETAPI void
	wget_hsts_db_set_fname(wget_hsts_db *hsts_db, const char *fname);
WGETAPI void
	wget_hsts_set_plugin(const wget_hsts_db_vtable *vtable);

/*
 * HTTP Public Key Pinning (HPKP)
 */

/**
 * \ingroup libwget-hpkp
 *
 * HPKP database for storing HTTP Public Key Pinning (HPKP) entries
 */
typedef struct wget_hpkp_db_st wget_hpkp_db;

/**
 * \ingroup libwget-hpkp
 *
 * HPKP database entry. Corresponds to one 'Public-Key-Pins' HTTP response header.
 */
typedef struct wget_hpkp_st wget_hpkp;

/* FIXME: the following entries are not used. review the hpkp function return values ! */
/**
 * \addtogroup libwget-hpkp
 *
 * @{
 */
/// Success
#define WGET_HPKP_OK			 0
/// General error
#define WGET_HPKP_ERROR			-1
/// The HPKP entry is expired
#define WGET_HPKP_ENTRY_EXPIRED		-2
/// The HPKP entry was deleted
#define WGET_HPKP_WAS_DELETED		-3
/// The entry doesn't have enough PINs
#define WGET_HPKP_NOT_ENOUGH_PINS	-4
/// The entry already exists
#define WGET_HPKP_ENTRY_EXISTS		-5
/// Failed to open a file
#define WGET_HPKP_ERROR_FILE_OPEN	-6
/** @} */

/**
 * \ingroup libwget-hpkp
 *
 * It is possible to implement a custom HPKP database as a plugin.
 * See tests/test-plugin-dummy.c and tests/Makefile.am for details.
 */

typedef wget_hpkp_db *wget_hpkp_db_init_fn(wget_hpkp_db *hpkp_db, const char *fname);
typedef void wget_hpkp_db_deinit_fn(wget_hpkp_db *hpkp_db);
typedef void wget_hpkp_db_free_fn(wget_hpkp_db **hpkp_db);
typedef int wget_hpkp_db_check_pubkey_fn(wget_hpkp_db *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize);
typedef void wget_hpkp_db_add_fn(wget_hpkp_db *hpkp_db, wget_hpkp **hpkp);
typedef int wget_hpkp_db_load_fn(wget_hpkp_db *hpkp_db);
typedef int wget_hpkp_db_save_fn(wget_hpkp_db *hpkp_db);

typedef struct {
	/// Callback replacing \ref wget_hpkp_db_free "wget_hpkp_db_free()"
	wget_hpkp_db_init_fn *init;
	/// Callback replacing \ref wget_hpkp_db_free "wget_hpkp_db_free()"
	wget_hpkp_db_deinit_fn *deinit;
	/// Callback replacing \ref wget_hpkp_db_free "wget_hpkp_db_free()"
	wget_hpkp_db_free_fn *free;
	/// Callback replacing \ref wget_hpkp_db_check_pubkey "wget_hpkp_db_check_pubkey()"
	wget_hpkp_db_check_pubkey_fn *check_pubkey;
	/// Callback replacing \ref wget_hpkp_db_add "wget_hpkp_db_add()"
	wget_hpkp_db_add_fn *add;
	/// Callback replacing \ref wget_hpkp_db_load "wget_hpkp_db_load()"
	wget_hpkp_db_load_fn *load;
	/// Callback replacing \ref wget_hpkp_db_save "wget_hpkp_db_save()"
	wget_hpkp_db_save_fn *save;
} wget_hpkp_db_vtable;

WGETAPI wget_hpkp * NULLABLE
	wget_hpkp_new(void);
WGETAPI void
	wget_hpkp_free(wget_hpkp *hpkp);
WGETAPI void
	wget_hpkp_pin_add(wget_hpkp *hpkp, const char *pin_type, const char *pin_b64);
WGETAPI void
	wget_hpkp_set_host(wget_hpkp *hpkp, const char *host);
WGETAPI void
	wget_hpkp_set_maxage(wget_hpkp *hpkp, int64_t maxage);
WGETAPI void
	wget_hpkp_set_include_subdomains(wget_hpkp *hpkp, bool include_subdomains);
WGETAPI int
	wget_hpkp_get_n_pins(wget_hpkp *hpkp);
WGETAPI void
	wget_hpkp_get_pins_b64(wget_hpkp *hpkp, const char **pin_types, const char **pins_b64);
WGETAPI void
	wget_hpkp_get_pins(wget_hpkp *hpkp, const char **pin_types, size_t *sizes, const void **pins);
WGETAPI const char *
	wget_hpkp_get_host(wget_hpkp *hpkp);
WGETAPI int64_t
	wget_hpkp_get_maxage(wget_hpkp *hpkp);
WGETAPI bool
	wget_hpkp_get_include_subdomains(wget_hpkp *hpkp);

WGETAPI wget_hpkp_db_init_fn wget_hpkp_db_init;
WGETAPI wget_hpkp_db_deinit_fn wget_hpkp_db_deinit;
WGETAPI wget_hpkp_db_free_fn wget_hpkp_db_free;
WGETAPI wget_hpkp_db_check_pubkey_fn wget_hpkp_db_check_pubkey;
WGETAPI wget_hpkp_db_add_fn wget_hpkp_db_add;
WGETAPI wget_hpkp_db_load_fn wget_hpkp_db_load;
WGETAPI wget_hpkp_db_save_fn wget_hpkp_db_save;
WGETAPI void
	wget_hpkp_db_set_fname(wget_hpkp_db *hpkp_db, const char *fname);
WGETAPI void
	wget_hpkp_set_plugin(const wget_hpkp_db_vtable *vtable);

/*
 * TLS session resumption
 */

// structure for TLS resumption cache entries
typedef struct wget_tls_session_st wget_tls_session;
typedef struct wget_tls_session_db_st wget_tls_session_db;

WGETAPI wget_tls_session * NULLABLE
	wget_tls_session_init(wget_tls_session *tls_session);
WGETAPI void
	wget_tls_session_deinit(wget_tls_session *tls_session);
WGETAPI void
	wget_tls_session_free(wget_tls_session *tls_session);
WGETAPI wget_tls_session * NULLABLE
	wget_tls_session_new(const char *host, int64_t maxage, const void *data, size_t data_size);
WGETAPI int
	wget_tls_session_get(const wget_tls_session_db *tls_session_db, const char *host, void **data, size_t *size);
WGETAPI wget_tls_session_db * NULLABLE
	wget_tls_session_db_init(wget_tls_session_db *tls_session_db);
WGETAPI void
	wget_tls_session_db_deinit(wget_tls_session_db *tls_session_db);
WGETAPI void
	wget_tls_session_db_free(wget_tls_session_db **tls_session_db);
WGETAPI void
	wget_tls_session_db_add(wget_tls_session_db *tls_session_db, wget_tls_session *tls_session);
WGETAPI int
	wget_tls_session_db_save(wget_tls_session_db *tls_session_db, const char *fname);
WGETAPI int
	wget_tls_session_db_load(wget_tls_session_db *tls_session_db, const char *fname);
WGETAPI int
	wget_tls_session_db_changed(wget_tls_session_db *tls_session_db) WGET_GCC_PURE;

/*
 * Online Certificate Status Protocol (OCSP) routines
 */

/**
 * \ingroup libwget-ocsp
 *
 * structure for Online Certificate Status Protocol (OCSP) entries
 */
typedef struct wget_ocsp_db_st wget_ocsp_db;

/**
 * \ingroup libwget-ocsp
 *
 * It is possible to implement a custom OCSP database as a plugin.
 * See tests/test-plugin-dummy.c and tests/Makefile.am for details.
 */

typedef wget_ocsp_db *wget_ocsp_db_init_fn(wget_ocsp_db *ocsp_db, const char *fname);
typedef void wget_ocsp_db_deinit_fn(wget_ocsp_db *ocsp_db);
typedef void wget_ocsp_db_free_fn(wget_ocsp_db **ocsp_db);
typedef bool wget_ocsp_fingerprint_in_cache_fn(const wget_ocsp_db *ocsp_db, const char *fingerprint, int *valid);
typedef bool wget_ocsp_hostname_is_valid_fn(const wget_ocsp_db *ocsp_db, const char *hostname);
typedef void wget_ocsp_db_add_fingerprint_fn(wget_ocsp_db *ocsp_db, const char *fingerprint, int64_t maxage, bool valid);
typedef void wget_ocsp_db_add_host_fn(wget_ocsp_db *ocsp_db, const char *host, int64_t maxage);
typedef int wget_ocsp_db_save_fn(wget_ocsp_db *ocsp_db);
typedef int wget_ocsp_db_load_fn(wget_ocsp_db *ocsp_db);

typedef struct {
	/// Callback replacing wget_ocsp_db_free()
	wget_ocsp_db_init_fn *init;
	/// Callback replacing wget_ocsp_db_free()
	wget_ocsp_db_deinit_fn *deinit;
	/// Callback replacing wget_ocsp_db_free()
	wget_ocsp_db_free_fn *free;
	/// Callback replacing wget_ocsp_db_fingerprint_in_cache()
	wget_ocsp_fingerprint_in_cache_fn *fingerprint_in_cache;
	/// Callback replacing wget_ocsp_db_hostname_is_valid()
	wget_ocsp_hostname_is_valid_fn *hostname_is_valid;
	/// Callback replacing wget_ocsp_db_add_fingerprint()
	wget_ocsp_db_add_fingerprint_fn *add_fingerprint;
	/// Callback replacing wget_ocsp_db_add_host()
	wget_ocsp_db_add_host_fn *add_host;
	/// Callback replacing wget_ocsp_db_load()
	wget_ocsp_db_save_fn *load;
	/// Callback replacing wget_ocsp_db_save()
	wget_ocsp_db_load_fn *save;
} wget_ocsp_db_vtable;

WGETAPI wget_ocsp_db_init_fn wget_ocsp_db_init;
WGETAPI wget_ocsp_db_deinit_fn wget_ocsp_db_deinit;
WGETAPI wget_ocsp_db_free_fn wget_ocsp_db_free;
WGETAPI wget_ocsp_fingerprint_in_cache_fn wget_ocsp_fingerprint_in_cache;
WGETAPI wget_ocsp_hostname_is_valid_fn wget_ocsp_hostname_is_valid;
WGETAPI wget_ocsp_db_add_fingerprint_fn wget_ocsp_db_add_fingerprint;
WGETAPI wget_ocsp_db_add_host_fn wget_ocsp_db_add_host;
WGETAPI wget_ocsp_db_save_fn wget_ocsp_db_save;
WGETAPI wget_ocsp_db_load_fn wget_ocsp_db_load;
WGETAPI void
	wget_ocsp_db_set_fname(wget_ocsp_db *ocsp_db, const char *fname);
WGETAPI void
	wget_ocsp_set_plugin(const wget_ocsp_db_vtable *vtable);

/*
 * .netrc routines
 */

/**
 *  container for .netrc entries
 */
typedef struct wget_netrc_db_st wget_netrc_db;

/**
 *  structure for a single .netrc entry
 *
 * The GNU extensions are described at
 *   https://www.gnu.org/software/emacs/manual/html_node/gnus/NNTP.html.
 */
struct wget_netrc_st {
	const char *
		host;      //!< hostname/domain/ip
	const char *
		login;     //!< login/username for the host
	const char *
		password;  //!< password for the host
	uint16_t
		port;      //!< GNU extension: port number
	bool
		force : 1; //!< GNU extension: unused
};
typedef struct wget_netrc_st wget_netrc;

WGETAPI wget_netrc * NULLABLE
	wget_netrc_init(wget_netrc *netrc);
WGETAPI void
	wget_netrc_deinit(wget_netrc *netrc);
WGETAPI void
	wget_netrc_free(wget_netrc *netrc);
WGETAPI wget_netrc * NULLABLE
	wget_netrc_new(const char *machine, const char *login, const char *password);
WGETAPI wget_netrc_db *
	wget_netrc_db_init(wget_netrc_db *netrc_db);
WGETAPI void
	wget_netrc_db_deinit(wget_netrc_db *netrc_db);
WGETAPI void
	wget_netrc_db_free(wget_netrc_db **netrc_db);
WGETAPI void
	wget_netrc_db_add(wget_netrc_db *netrc_db, wget_netrc *netrc);
WGETAPI wget_netrc * NULLABLE
	wget_netrc_get(const wget_netrc_db *netrc_db, const char *host);
WGETAPI int
	wget_netrc_db_load(wget_netrc_db *netrc_db, const char *fname);

/*
 * CSS parsing routines
 */

struct wget_css_parsed_url_st {
	size_t
		len; //!< length of found URL
	size_t
		pos; //!< position of found URL within the scanned CSS data
	const char *
		url; //!< zero-terminated copy the found URL
	const char *
		abs_url; //!< the found URL converted into an absolute URL
};
typedef struct wget_css_parsed_url_st wget_css_parsed_url;

typedef void wget_css_parse_uri_callback(void *user_ctx, const char *url, size_t len, size_t pos);
typedef void wget_css_parse_encoding_callback(void *user_ctx, const char *url, size_t len);

WGETAPI void
	wget_css_parse_buffer(
		const char *buf,
		size_t len,
		wget_css_parse_uri_callback *callback_uri,
		wget_css_parse_encoding_callback *callback_encoding,
		void *user_ctx) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_css_parse_file(
		const char *fname,
		wget_css_parse_uri_callback *callback_uri,
		wget_css_parse_encoding_callback *callback_encoding,
		void *user_ctx) WGET_GCC_NONNULL((1));
WGETAPI wget_vector *
	wget_css_get_urls(
		const char *css,
		size_t len,
		wget_iri *base,
		const char **encoding) WGET_GCC_NONNULL((1));
WGETAPI wget_vector *
	wget_css_get_urls_from_localfile(
		const char *fname,
		wget_iri *base,
		const char **encoding) WGET_GCC_NONNULL((1));

typedef struct {
	const char
		*p; //!< pointer to memory region
	size_t
		len; //!< length of memory region
} wget_string;

typedef struct {
	wget_string
		url; //!< URL within the parsed document (pointer and length)
	wget_string
		download; //!< Value of additional 'download' attribute, the name to be saved to disk
	char
		attr[16]; //!< name of the attribute containing the URL, e.g. 'href'
	char
		tag[16]; //!< name of the HTML tag containing the URL, e.g. 'a'
	bool
		link_inline : 1; //!< 1 = rel was 'stylesheet' or 'shortcut icon'
} wget_html_parsed_url;

typedef struct {
	wget_vector
		*uris; //!< list of found URLs (entries: wget_html_parsed_url)
	const char *
		encoding; //!< the charset encoding set by the parsed document or NULL if none
	wget_string
		base; //!< the BASE set in the document or NULL if none
	bool
		follow : 1; //!< if the 'follow' attribute was found in a META tag
} wget_html_parsed_result;

/**
 * HTML tag consisting of name and an optional attribute
 */
typedef struct {
	const char *
		name; //!< name of HTML tag
	const char *
		attribute; //!< attribute of the HTML tag
} wget_html_tag;

WGETAPI wget_html_parsed_result * NULLABLE
	wget_html_get_urls_inline(const char *html, wget_vector *additional_tags, wget_vector *ignore_tags);
WGETAPI void
	wget_html_free_urls_inline(wget_html_parsed_result **res);
WGETAPI void
	wget_sitemap_get_urls_inline(const char *sitemap, wget_vector **urls, wget_vector **sitemap_urls);
WGETAPI void
	wget_atom_get_urls_inline(const char *atom, wget_vector **urls);
WGETAPI void
	wget_rss_get_urls_inline(const char *rss, wget_vector **urls);

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

typedef void wget_xml_callback(void *, int, const char *, const char *, const char *, size_t, size_t);

WGETAPI int
	wget_xml_parse_buffer(
		const char *buf,
		wget_xml_callback *callback,
		void *user_ctx,
		int hints) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_xml_parse_file(
		const char *fname,
		wget_xml_callback *callback,
		void *user_ctx,
		int hints) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_html_parse_buffer(
		const char *buf,
		wget_xml_callback *callback,
		void *user_ctx,
		int hints) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_html_parse_file(
		const char *fname,
		wget_xml_callback *callback,
		void *user_ctx,
		int hints) WGET_GCC_NONNULL((1));
WGETAPI char *
	wget_xml_decode_entities_inline(char *src) WGET_GCC_NONNULL((1));

/*
 * DNS caching routines
 */

typedef struct wget_dns_cache_st wget_dns_cache;

WGETAPI int
	wget_dns_cache_init(wget_dns_cache **cache);
WGETAPI void
	wget_dns_cache_free(wget_dns_cache **cache);
WGETAPI struct addrinfo * NULLABLE
	wget_dns_cache_get(wget_dns_cache *cache, const char *host, uint16_t port);
WGETAPI int
	wget_dns_cache_add(wget_dns_cache *cache, const char *host, uint16_t port, struct addrinfo **addrinfo);

/*
 * DNS resolving routines
 */

typedef struct wget_dns_st wget_dns;

WGETAPI int
	wget_dns_init(wget_dns **dns);
WGETAPI void
	wget_dns_free(wget_dns **dns);
WGETAPI void
	wget_dns_set_timeout(wget_dns *dns, int timeout);
WGETAPI void
	wget_dns_set_cache(wget_dns *dns, wget_dns_cache *cache);
WGETAPI wget_dns_cache * NULLABLE
	wget_dns_get_cache(wget_dns *dns) WGET_GCC_PURE;
WGETAPI struct addrinfo * NULLABLE
	wget_dns_resolve(wget_dns *dns, const char *host, uint16_t port, int family, int preferred_family);
WGETAPI void
	wget_dns_freeaddrinfo(wget_dns *dns, struct addrinfo **addrinfo);
WGETAPI int
	wget_dns_cache_ip(wget_dns *dns, const char *ip, const char *name, uint16_t port);

/*
 * TCP network routines
 */

#define WGET_NET_FAMILY_ANY  0
#define WGET_NET_FAMILY_IPV4 1
#define WGET_NET_FAMILY_IPV6 2

#define WGET_PROTOCOL_HTTP_1_1  0
#define WGET_PROTOCOL_HTTP_2_0  1

typedef struct wget_tcp_st wget_tcp;

WGETAPI int
	wget_net_init(void);
WGETAPI int
	wget_net_deinit(void);
WGETAPI wget_tcp * NULLABLE
	wget_tcp_init(void);
WGETAPI void
	wget_tcp_deinit(wget_tcp **tcp);
WGETAPI void
	wget_tcp_close(wget_tcp *tcp);
WGETAPI void
	wget_tcp_set_dns(wget_tcp *tcp, wget_dns *dns);
WGETAPI void
	wget_tcp_set_timeout(wget_tcp *tcp, int timeout);
WGETAPI int
	wget_tcp_get_timeout(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI void
	wget_tcp_set_connect_timeout(wget_tcp *tcp, int timeout);
WGETAPI void
	wget_tcp_set_tcp_fastopen(wget_tcp *tcp, bool tcp_fastopen);
WGETAPI void
	wget_tcp_set_tls_false_start(wget_tcp *tcp, bool false_start);
WGETAPI void
	wget_tcp_set_ssl(wget_tcp *tcp, bool ssl);
WGETAPI bool
	wget_tcp_get_ssl(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI const char * NULLABLE
	wget_tcp_get_ip(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI void
	wget_tcp_set_ssl_hostname(wget_tcp *tcp, const char *hostname);
WGETAPI const char *
	wget_tcp_get_ssl_hostname(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI void
	wget_tcp_set_ssl_ca_file(wget_tcp *tcp, const char *cafile);
WGETAPI void
	wget_tcp_set_ssl_key_file(wget_tcp *tcp, const char *certfile, const char *keyfile);
WGETAPI bool
	wget_tcp_get_tcp_fastopen(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI bool
	wget_tcp_get_tls_false_start(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI int
	wget_tcp_get_family(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI int
	wget_tcp_get_preferred_family(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI int
	wget_tcp_get_protocol(wget_tcp *tcp) WGET_GCC_PURE;
WGETAPI int
	wget_tcp_get_local_port(wget_tcp *tcp);
WGETAPI void
	wget_tcp_set_debug(wget_tcp *tcp, int debug);
WGETAPI void
	wget_tcp_set_family(wget_tcp *tcp, int family);
WGETAPI void
	wget_tcp_set_preferred_family(wget_tcp *tcp, int family);
WGETAPI void
	wget_tcp_set_protocol(wget_tcp *tcp, int protocol);
WGETAPI void
	wget_tcp_set_bind_address(wget_tcp *tcp, const char *bind_address);
WGETAPI void
	wget_tcp_set_bind_interface(wget_tcp *tcp, const char *bind_interface);
WGETAPI int
	wget_tcp_connect(wget_tcp *tcp, const char *host, uint16_t port);
WGETAPI int
	wget_tcp_tls_start(wget_tcp *tcp);
WGETAPI void
	wget_tcp_tls_stop(wget_tcp *tcp);
WGETAPI ssize_t
	wget_tcp_vprintf(wget_tcp *tcp, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
WGETAPI ssize_t
	wget_tcp_printf(wget_tcp *tcp, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3);
WGETAPI ssize_t
	wget_tcp_write(wget_tcp *tcp, const char *buf, size_t count);
WGETAPI ssize_t
	wget_tcp_read(wget_tcp *tcp, char *buf, size_t count);
WGETAPI int
	wget_tcp_ready_2_transfer(wget_tcp *tcp, int flags);

WGETAPI bool
	wget_ip_is_family(const char *host, int family) WGET_GCC_PURE;

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
#define WGET_SSL_CRL_FILE          13
#define WGET_SSL_OCSP_STAPLING     14
#define WGET_SSL_OCSP_SERVER       15
#define WGET_SSL_OCSP              16
#define WGET_SSL_OCSP_CACHE        17
#define WGET_SSL_ALPN              18
#define WGET_SSL_SESSION_CACHE     19
#define WGET_SSL_HPKP_CACHE        20
#define WGET_SSL_OCSP_NONCE        21
#define WGET_SSL_OCSP_DATE         22
#define WGET_SSL_REPORT_INVALID_CERT 23
#define WGET_SSL_DANE              24

WGETAPI void
	wget_ssl_init(void);
WGETAPI void
	wget_ssl_deinit(void);
WGETAPI void
	wget_ssl_set_config_string(int key, const char *value);
WGETAPI void
	wget_ssl_set_config_object(int key, void *value);
WGETAPI void
	wget_ssl_set_config_int(int key, int value);
WGETAPI int
	wget_ssl_open(wget_tcp *tcp);
WGETAPI void
	wget_ssl_close(void **session);
WGETAPI void
	wget_ssl_set_check_certificate(char value);
WGETAPI ssize_t
	wget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout) WGET_GCC_NONNULL_ALL;
WGETAPI ssize_t
	wget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_ssl_default_cert_dir(void);
WGETAPI const char *
	wget_ssl_default_ca_bundle_path(void);

/*
 * HTTP routines
 */

/**
 * Parsed name/value pair as often found in HTTP headers
 */
typedef struct {
	const char *
		name; //!< name of the param
	const char *
		value; //!< value of the param (might be NULL)
} wget_http_header_param;

/**
 * Parsed Link HTTP header
 */
typedef struct {
	const char *
		uri; //!< URI reference
	const char *
		type; //!< value of type param or NULL
	int
		pri; //!< value of pri param
	enum {
		link_rel_none = 0,
		link_rel_describedby,
		link_rel_duplicate
	} rel; //!< value of 'rel' param, either none (if not found), 'describedby' or 'duplicate'
} wget_http_link;

/**
 * Parsed Digest HTTP header (RFC 3230)
 */
typedef struct {
	const char *
		algorithm; //!< name of the digest, e.g. 'md5'
	const char *
		encoded_digest; //!< value of the digest
} wget_http_digest;

/**
 * Parsed WWW-Authenticate or Proxy-Authenticate HTTP header
 */
typedef struct {
	const char *
		auth_scheme; //!< name of the challenge, e.g. 'basic' or 'digest'
	wget_stringmap *
		params; //!< name/value pairs of the challenge
} wget_http_challenge;

typedef enum {
	wget_transfer_encoding_identity = 0,
	wget_transfer_encoding_chunked = 1
} wget_transfer_encoding;

typedef struct wget_http_response_st wget_http_response;
typedef int wget_http_header_callback(wget_http_response *, void *);
typedef int wget_http_body_callback(wget_http_response *, void *, const char *, size_t);

/**
 * HTTP request data
 */
typedef struct {
	wget_vector *
		headers; //!< list of HTTP headers
	const char *
		body; //!< body data to be sent or NULL
	wget_http_header_callback
		*header_callback; //!< called after HTTP header has been received
	wget_http_body_callback
		*body_callback; //!< called for each body data packet received
	void *
		user_data; //!< user data for the request (used by async application code)
	void *
		header_user_data; //!< meant to be used in header callback function
	void *
		body_user_data; //!< meant to be used in body callback function
	wget_buffer
		esc_resource; //!< URI escaped resource
	wget_buffer
		esc_host; //!< URI escaped host
	size_t
		body_length; //!< length of the body data
	int32_t
		stream_id; //!< HTTP2 stream id
	wget_iri_scheme
		scheme; //!< scheme of the request for proxied connections
	char
		esc_resource_buf[256]; //!< static buffer used by esc_resource (avoids mallocs)
	char
		esc_host_buf[64]; //!< static buffer used by esc_host (avoids mallocs)
	char
		method[8]; //!< currently we just need HEAD, GET and POST
	bool
		response_keepheader : 1; //!< the application wants the response header data
	bool
		response_ignorelength : 1; //!< ignore the Content-Length in the response header
	bool
		debug_skip_body : 1; //!< if set, do not print the request body (e.g. because it's binary)
	long long
		request_start; //!< When this request was sent out
	long long
		first_response_start; //!< The time we read the first bytes back

} wget_http_request;

/**
 * HTTP response data
 */
struct wget_http_response_st {
	wget_http_request *
		req;
	wget_vector *
		links;
	wget_vector *
		digests;
	wget_vector *
		cookies;
	wget_vector *
		challenges;
	wget_hpkp *
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
		etag; //!< ETag value
	wget_buffer *
		header; //!< the raw header data if requested by the application
	wget_buffer *
		body; //!< the body data
	long long
		response_end; //!< when this response was received
	size_t
		content_length; //!< length of the body data
	size_t
		cur_downloaded,
		accounted_for;	// reported to bar
	int64_t
		last_modified;
	int64_t
		hsts_maxage;
	char
		reason[32]; //!< reason string after the status code
	int
		icy_metaint; //!< value of the SHOUTCAST header 'icy-metaint'
	short
		major; //!< HTTP major version
	short
		minor; //!< HTTP minor version
	short
		code; //!< request only status code
	wget_transfer_encoding
		transfer_encoding;
	char
		content_encoding;
	bool
		hsts_include_subdomains,
		keep_alive;
	bool
		content_length_valid : 1,
		length_inconsistent : 1, //!< set when length of data received is not same as Content-Length
		hsts : 1, //!< if hsts_maxage and hsts_include_subdomains are valid
		csp : 1;
};

typedef struct wget_http_connection_st wget_http_connection;

WGETAPI const char *
	wget_http_get_host(const wget_http_connection *conn) WGET_GCC_NONNULL_ALL;
WGETAPI uint16_t
	wget_http_get_port(const wget_http_connection *conn) WGET_GCC_NONNULL_ALL;
WGETAPI wget_iri_scheme
	wget_http_get_scheme(const wget_http_connection *conn) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_http_get_protocol(const wget_http_connection *conn) WGET_GCC_NONNULL_ALL;

WGETAPI bool
	wget_http_isseparator(char c) WGET_GCC_CONST;
WGETAPI bool
	wget_http_istoken(char c) WGET_GCC_CONST;

WGETAPI const char *
	wget_http_parse_token(const char *s, const char **token) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_quoted_string(const char *s, const char **qstring) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_param(const char *s, const char **param, const char **value) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_name(const char *s, const char **name) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_parse_name_fixed(const char *s, const char **name, size_t *namelen) WGET_GCC_NONNULL_ALL;
WGETAPI int64_t
	wget_http_parse_full_date(const char *s) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_link(const char *s, wget_http_link *link) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_digest(const char *s, wget_http_digest *digest) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_challenge(const char *s, wget_http_challenge *challenge) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_challenges(const char *s, wget_vector *challenges) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_location(const char *s, const char **location) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_transfer_encoding(const char *s, wget_transfer_encoding *transfer_encoding) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_content_type(const char *s, const char **content_type, const char **charset) WGET_GCC_NONNULL((1));
WGETAPI const char *
	wget_http_parse_content_encoding(const char *s, char *content_encoding) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_content_disposition(const char *s, const char **filename) WGET_GCC_NONNULL((1));
WGETAPI const char *
	wget_http_parse_strict_transport_security(const char *s, int64_t *maxage, bool *include_subdomains) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_public_key_pins(const char *s, wget_hpkp *hpkp) WGET_GCC_NONNULL((1));
WGETAPI const char *
	wget_http_parse_connection(const char *s, bool *keep_alive) WGET_GCC_NONNULL_ALL;
WGETAPI const char *
	wget_http_parse_setcookie(const char *s, wget_cookie **cookie) WGET_GCC_NONNULL((1));
WGETAPI const char *
	wget_http_parse_etag(const char *s, const char **etag) WGET_GCC_NONNULL((1));

WGETAPI char *
	wget_http_print_date(int64_t t, char *buf, size_t bufsize) WGET_GCC_NONNULL_ALL;

WGETAPI void
	wget_http_add_param(wget_vector **params, wget_http_header_param *param) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_http_add_header_vprintf(wget_http_request *req, const char *name, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(3,0) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_http_add_header_printf(wget_http_request *req, const char *name, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(3,4) WGET_GCC_NONNULL((1,2,3));
WGETAPI int
	wget_http_add_header(wget_http_request *req, const char *name, const char *value) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_http_add_header_param(wget_http_request *req, wget_http_header_param *param) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_http_add_credentials(wget_http_request *req, wget_http_challenge *challenge, const char *username, const char *password, int proxied) WGET_GCC_NONNULL((1));
WGETAPI int
	wget_http_set_http_proxy(const char *proxy, const char *encoding);
WGETAPI int
	wget_http_set_https_proxy(const char *proxy, const char *encoding);
WGETAPI int
	wget_http_set_no_proxy(const char *no_proxy, const char *encoding);
WGETAPI const wget_vector *
	wget_http_get_no_proxy(void);
WGETAPI int
	wget_http_match_no_proxy(const wget_vector *no_proxies, const char *host);
WGETAPI void
	wget_http_abort_connection(wget_http_connection *conn);
WGETAPI bool
	wget_http_connection_receive_only(wget_http_connection *conn);

WGETAPI void
	wget_http_free_param(wget_http_header_param *param);
WGETAPI void
	wget_http_free_cookie(wget_cookie *cookie);
WGETAPI void
	wget_http_free_digest(wget_http_digest *digest);
WGETAPI void
	wget_http_free_challenge(wget_http_challenge *challenge);
WGETAPI void
	wget_http_free_link(wget_http_link *link);

WGETAPI void
	wget_http_free_cookies(wget_vector **cookies);
WGETAPI void
	wget_http_free_hpkp_entries(wget_hpkp **hpkp);
WGETAPI void
	wget_http_free_digests(wget_vector **digests);
WGETAPI void
	wget_http_free_challenges(wget_vector **challenges);
WGETAPI void
	wget_http_free_links(wget_vector **links);
//WGETAPI void
//	wget_http_free_header(HTTP_HEADER **header);
WGETAPI void
	wget_http_free_request(wget_http_request **req);
WGETAPI void
	wget_http_free_response(wget_http_response **resp);

WGETAPI int
	wget_http_parse_header_line(wget_http_response *resp, const char *name, size_t namelen, const char *value, size_t valuelen);
WGETAPI wget_http_response * NULLABLE
	wget_http_parse_response_header(char *buf) WGET_GCC_NONNULL_ALL;
WGETAPI wget_http_response * NULLABLE
	wget_http_get_response_cb(wget_http_connection *conn) WGET_GCC_NONNULL((1));
//WGETAPI HTTP_RESPONSE *
//	http_get_response_mem(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL_ALL;
WGETAPI wget_http_response * NULLABLE
	wget_http_get_response(wget_http_connection *conn) WGET_GCC_NONNULL((1));

WGETAPI void
	wget_http_init(void);
WGETAPI void
	wget_http_exit(void);
WGETAPI int
	wget_http_open(wget_http_connection **_conn, const wget_iri *iri);
WGETAPI wget_http_request * NULLABLE
	wget_http_create_request(const wget_iri *iri, const char *method) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_http_close(wget_http_connection **conn) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_http_request_set_header_cb(wget_http_request *req, wget_http_header_callback *cb, void *user_data) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_http_request_set_body_cb(wget_http_request *req, wget_http_body_callback *cb, void *user_data) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_http_request_set_int(wget_http_request *req, int key, int value) WGET_GCC_NONNULL((1));
WGETAPI int
	wget_http_request_get_int(wget_http_request *req, int key) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_http_request_set_ptr(wget_http_request *req, int key, void *value) WGET_GCC_NONNULL((1));
WGETAPI void *
	wget_http_request_get_ptr(wget_http_request *req, int key) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_http_request_set_body(wget_http_request *req, const char *mimetype, char *body, size_t length) WGET_GCC_NONNULL((1));
WGETAPI int
	wget_http_send_request(wget_http_connection *conn, wget_http_request *req) WGET_GCC_NONNULL_ALL;
WGETAPI ssize_t
	wget_http_request_to_buffer(wget_http_request *req, wget_buffer *buf, int proxied, int port) WGET_GCC_NONNULL_ALL;

/*
 * Highlevel HTTP routines
 */

WGETAPI wget_http_response *
	wget_http_get(int first_key, ...);


/*
 * random routines
 */

WGETAPI void
	wget_random_init(void);
WGETAPI void
	wget_random_exit(void);
WGETAPI int
	wget_random(void);
WGETAPI void
	wget_srandom(unsigned int seed);


/**
 * \ingroup libwget-hash
 * \brief Type for hash / digest routines
 */
	typedef struct wget_hash_hd_st wget_hash_hd;

/**
 * \ingroup libwget-hash
 * \brief Enumeration of different hash digest algorithms
 */
typedef enum {
	WGET_DIGTYPE_UNKNOWN = 0, /**< Indicates 'Unknown hash algorithm', returned by wget_hash_get_algorithm() */
	WGET_DIGTYPE_MD5,     /**< Type 'MD5' digest */
	WGET_DIGTYPE_SHA1,    /**< Type SHA1 digest */
	WGET_DIGTYPE_RMD160,  /**< Type RMD160 digest */
	WGET_DIGTYPE_MD2,     /**< Type 'MD2' digest */
	WGET_DIGTYPE_SHA256,  /**< Type 'SHA256' digest */
	WGET_DIGTYPE_SHA384,  /**< Type 'SHA384' digest */
	WGET_DIGTYPE_SHA512,  /**< Type 'SHA512' digest */
	WGET_DIGTYPE_SHA224,  /**< Type 'SHA224' digest */
	WGET_DIGTYPE_MAX      /**< Number of digest types */
} wget_digest_algorithm;

WGETAPI wget_digest_algorithm
	wget_hash_get_algorithm(const char *hashname);
WGETAPI int
	wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest);
WGETAPI int
	wget_hash_get_len(wget_digest_algorithm algorithm) WGET_GCC_CONST;
WGETAPI int
	wget_hash_init(wget_hash_hd **dig, wget_digest_algorithm algorithm);
WGETAPI int
	wget_hash(wget_hash_hd *handle, const void *text, size_t textlen);
WGETAPI int
	wget_hash_deinit(wget_hash_hd **handle, void *digest);

/*
 * Hash file routines
 */

WGETAPI int
	wget_hash_file_fd(const char *hashname, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_hash_file_offset(const char *hashname, const char *fname, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) WGET_GCC_NONNULL_ALL;
WGETAPI int
	wget_hash_file(const char *hashname, const char *fname, char *digest_hex, size_t digest_hex_size) WGET_GCC_NONNULL_ALL;

/*
 * Hash convenience routines
 */

// don't use 'restrict' here as out, fmt and argument pointers may overlap
WGETAPI void WGET_GCC_PRINTF_FORMAT(4,5) WGET_GCC_NONNULL_ALL
	wget_hash_printf_hex(wget_digest_algorithm algorithm, char *out, size_t outsize, const char *fmt, ...);


/*
 * Metalink types and routines
 */

typedef struct {
	const wget_iri
		*iri;        //!< parsed URL of the mirror
	int
		priority;    //!< priority of the mirror
	char
		location[8]; //!< location of the mirror, e.g. 'de', 'fr' or 'jp'
} wget_metalink_mirror;

typedef struct {
	char
		type[16],        //!< type of hash, e.g. 'MD5' or 'SHA-256'
		hash_hex[128+1]; //!< hash value as HEX string
} wget_metalink_hash;

// Metalink piece, for checksumming after download
typedef struct {
	wget_metalink_hash
		hash;     //!< hash of the data chunk
	off_t
		position; //!< start position of the data chunk in the file
	off_t
		length;   //!< length of the data chunk
} wget_metalink_piece;

typedef struct {
	const char
		*name;    //!< filename
	wget_vector
		*mirrors, //!< mirrors that provide the file (element: wget_metalink_mirror)
		*hashes,  //!< checksums of complete file (element: wget_metalink_hash)
		*pieces;  //!< checksums of smaller pieces of the file (element: wget_metalink_piece)
	off_t
		size;     //!< total size of the file
} wget_metalink;

WGETAPI wget_metalink * NULLABLE
	wget_metalink_parse(const char *xml);
WGETAPI void
	wget_metalink_free(wget_metalink **metalink);
WGETAPI void
	wget_metalink_sort_mirrors(wget_metalink *metalink);

/*
 * Robots types and routines
 */

typedef struct wget_robots_st wget_robots;

WGETAPI int
	wget_robots_parse(wget_robots **robots, const char *data, const char *client);
WGETAPI void
	wget_robots_free(wget_robots **robots);
WGETAPI int
	wget_robots_get_path_count(wget_robots *robots);
WGETAPI wget_string * NULLABLE
	wget_robots_get_path(wget_robots *robots, int index);
WGETAPI int
	wget_robots_get_sitemap_count(wget_robots *robots);
WGETAPI const char * NULLABLE
	wget_robots_get_sitemap(wget_robots *robots, int index);

/*
 * Progress bar routines
 */

// values for --report-speed and wget_bar_set_speed_type()
typedef enum {
	WGET_REPORT_SPEED_BYTES,
	WGET_REPORT_SPEED_BITS
} wget_report_speed;

typedef struct wget_bar_st wget_bar;

WGETAPI wget_bar * NULLABLE
	wget_bar_init(wget_bar *bar, int nslots);
WGETAPI void
	wget_bar_deinit(wget_bar *bar);
WGETAPI void
	wget_bar_free(wget_bar **bar);
WGETAPI void
	wget_bar_print(wget_bar *bar, int slot, const char *s);
WGETAPI void
	wget_bar_vprintf(wget_bar *bar, int slot, const char *__restrict fmt, va_list args) WGET_GCC_PRINTF_FORMAT(3,0) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_printf(wget_bar *bar, int slot, const char *__restrict fmt, ...) WGET_GCC_PRINTF_FORMAT(3,4) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_slot_begin(wget_bar *bar, int slot, const char *filename, int new_file, ssize_t filesize) WGET_GCC_NONNULL((1));
WGETAPI void
	wget_bar_slot_downloaded(wget_bar *bar, int slot, size_t nbytes);
WGETAPI void
	wget_bar_slot_deregister(wget_bar *bar, int slot) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_update(wget_bar *bar) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_set_slots(wget_bar *bar, int nslots) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_screen_resized(void);
WGETAPI void
	wget_bar_write_line(wget_bar *bar, const char *buf, size_t len) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_write_line_ext(wget_bar *bar, const char *buf, size_t len, const char *pre, const char *post) WGET_GCC_NONNULL_ALL;
WGETAPI void
	wget_bar_set_speed_type(wget_report_speed type);

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
} wget_console_color;

WGETAPI int
	wget_console_init(void);
WGETAPI int
	wget_console_deinit(void);
WGETAPI void
	wget_console_set_fg_color(wget_console_color colorid);
WGETAPI void
	wget_console_reset_fg_color(void);

/*
 * Plugin support
 */

/**
 * \ingroup libwget-plugin
 *
 * Mark a function to be exported.
 * A common use for this is to mark the `wget_plugin_initializer()` function for plugin initialization.
 *
 *     WGET_EXPORT void wget_plugin_initializer(wget_plugin *plugin);
 */
#ifdef _WIN32
#	define WGET_EXPORT __declspec(dllexport)
#elif __GNUC__ > 4
#	define WGET_EXPORT __attribute__ ((__visibility__("default")))
#else
#	define WGET_EXPORT
#endif

struct wget_plugin_vtable;

/**
 * \ingroup libwget-plugin
 *
 * A handle used to identify the plugin.
 *
 * Only two members shown here are public, and only plugin_data is writable.
 */
struct wget_plugin_st
{
	/// Plugin specific data. Plugins are free to assign any value to this.
	void *plugin_data;

	/// Pointer to the vtable. Used by wget to implement functions.
	struct wget_plugin_vtable *vtable;
};

typedef struct wget_plugin_st wget_plugin;

/**
 * \ingroup libwget-plugin
 *
 * Prototype for the initializer function.
 *
 * \param[in] plugin The plugin handle
 * \return Should return 0 if initialization succeeded, or any other value to indicate failure.
 *         On failure, wget2 will continue without the plugin
 *         and will not call the finalizer function even if registered.
 */
typedef int wget_plugin_initializer_fn(wget_plugin *plugin);

/**
 * \ingroup libwget-plugin
 *
 * Prototype of the finalizer function.
 *
 * \param[in] plugin The plugin handle
 * \param[in] exit_status The exit status wget will exit with
 */
typedef void wget_plugin_finalizer_fn(wget_plugin *plugin, int exit_status);

// Gets the name the plugin is known as.
WGETAPI const char *
	wget_plugin_get_name(wget_plugin *plugin) WGET_GCC_NONNULL_ALL;

// Registers a function to be called when wget exits.
WGETAPI void
	wget_plugin_register_finalizer(wget_plugin *plugin, wget_plugin_finalizer_fn *fn) WGET_GCC_NONNULL((1));

/**
 * \ingroup libwget-plugin
 *
 * Prototype for the function that will accept forwarded command line arguments.
 *
 * \param[in] plugin The plugin handle
 * \param[in] option Option name. If the option is "help", a help message must be printed to stdout.
 * \param[in] value  The value of the option if provided, or NULL
 * \return Must return 0 if option and its value is valid, or any other value if invalid. In that case wget will exit.
 */
typedef int wget_plugin_option_callback(wget_plugin *plugin, const char *option, const char *value);

// Registers a function for command line option forwarding.
WGETAPI void
	wget_plugin_register_option_callback(wget_plugin *plugin, wget_plugin_option_callback *fn) WGET_GCC_NONNULL((1));

/**
 * \ingroup libwget-plugin
 *
 * Stores any action taken by the plugin
 */
typedef struct {
	struct wget_plugin_vtable *vtable;
} wget_intercept_action;

// Marks the URL to be rejected.
WGETAPI void
	wget_intercept_action_reject(wget_intercept_action *action) WGET_GCC_NONNULL_ALL;

// Marks the URL to be accepted.
WGETAPI void
	wget_intercept_action_accept(wget_intercept_action *action) WGET_GCC_NONNULL_ALL;

// Specifies an alternative URL to be fetched instead.
WGETAPI void
	wget_intercept_action_set_alt_url(wget_intercept_action *action, const wget_iri *iri) WGET_GCC_NONNULL((1));

// Specifies that the fetched data should be written to an alternative file.
WGETAPI void
	wget_intercept_action_set_local_filename(wget_intercept_action *action, const char *local_filename) WGET_GCC_NONNULL((1));

/**
 * \ingroup libwget-plugin
 *
 * Prototype for the function for intercepting URLs
 * The function must be thread-safe.
 *
 * \param[in] plugin The plugin handle
 * \param[in] iri The URL about to be fetched
 * \param[in] action Output the action to be taken
 */
typedef void wget_plugin_url_filter_callback(wget_plugin *plugin, const wget_iri *iri, wget_intercept_action *action);

// Registers a plugin function for intercepting URLs
WGETAPI void
	wget_plugin_register_url_filter_callback(wget_plugin *plugin, wget_plugin_url_filter_callback *filter_fn);

/**
 * \ingroup libwget-plugin
 *
 * Handle that represents a downloaded file.
 */
typedef struct {
	struct wget_plugin_vtable *vtable;
} wget_downloaded_file;

// Gets the source address the file was downloaded from.
WGETAPI const wget_iri *
	wget_downloaded_file_get_source_url(wget_downloaded_file *file);

// Gets the file name the downloaded file was written to.
WGETAPI const char *
	wget_downloaded_file_get_local_filename(wget_downloaded_file *file);

// Gets the size of the downloaded file.
WGETAPI uint64_t
	wget_downloaded_file_get_size(wget_downloaded_file *file);

// Reads the downloaded file into memory.
WGETAPI int
	wget_downloaded_file_get_contents(wget_downloaded_file *file, const void **data, size_t *size);

// Opens the downloaded file as a new stream.
WGETAPI FILE *
	wget_downloaded_file_open_stream(wget_downloaded_file *file);

// Gets whether the file should be scanned for more URLs.
WGETAPI bool
	wget_downloaded_file_get_recurse(wget_downloaded_file *file);

// Adds a URL for recursive downloading.
WGETAPI void
	wget_downloaded_file_add_recurse_url(wget_downloaded_file *file, const wget_iri *iri);

/**
 * \ingroup libwget-plugin
 *
 * Prototype of the function for intercepting downloaded files. The function must be thread-safe.
 *
 * \param[in] plugin The plugin handle
 * \param[in] file Downloaded file handle
 * \return 0 if further postprocessing of downloaded files should be stopped.
 */
typedef int wget_plugin_post_processor(wget_plugin *plugin, wget_downloaded_file *file);

// Registers a plugin function for intercepting downloaded files.
WGETAPI void
	wget_plugin_register_post_processor(wget_plugin *plugin, wget_plugin_post_processor *fn);

/**
 * \ingroup libwget-plugin
 *
 * vtable for implementing plugin API in wget
*/
struct wget_plugin_vtable
{
	const char * (* get_name)(wget_plugin *);
	void (* register_finalizer)(wget_plugin *, wget_plugin_finalizer_fn *);
	void (* register_argp)(wget_plugin *, wget_plugin_option_callback *);

	void (* action_reject)(wget_intercept_action *);
	void (* action_accept)(wget_intercept_action *);
	void (* action_set_alt_url)(wget_intercept_action *, const wget_iri *);
	void (* action_set_local_filename)(wget_intercept_action *, const char *);
	void (* register_url_filter)(wget_plugin *, wget_plugin_url_filter_callback *);

	const wget_iri *(*file_get_source_url)(wget_downloaded_file *);
	const char *(*file_get_local_filename)(wget_downloaded_file *);
	uint64_t (*file_get_size)(wget_downloaded_file *);
	int (*file_get_contents)(wget_downloaded_file *, const void **data, size_t *size);
	FILE *(*file_open_stream)(wget_downloaded_file *);
	bool (*file_get_recurse)(wget_downloaded_file *);
	void (*file_add_recurse_url)(wget_downloaded_file *, const wget_iri *);
	void (*register_post_processor)(wget_plugin *, wget_plugin_post_processor *);
};

/**
 * \ingroup libwget-dns
 *
 * DNS statistics data
 *
 * @{
 */
typedef struct
{
	const char
		*hostname, //!< hostname/domain to be resolved
		*ip; //!< resulting IP string
	uint16_t
		port; //!< port to be resolved
	long long
		dns_secs; //!< milliseconds it took to resolve
} wget_dns_stats_data;

typedef void
	wget_dns_stats_callback(wget_dns *dns, wget_dns_stats_data *stats, void *ctx);

WGETAPI void
	wget_dns_set_stats_callback(wget_dns *dns, wget_dns_stats_callback *fn, void *ctx);

/**
 * \ingroup libwget-ssl
 *
 * TLS statistics data
 *
 * @{
 */
typedef struct
{
	const char
		*hostname;
	int
		nvalid,
		nrevoked,
		nignored,
		stapling;
} wget_ocsp_stats_data;

typedef void
	wget_ocsp_stats_callback(wget_ocsp_stats_data *stats, void *ctx);

WGETAPI void
	wget_ssl_set_stats_callback_ocsp(wget_ocsp_stats_callback *fn, void *ctx);
/** @} */

/**
 * \ingroup libwget-ssl
 *
 * OCSP statistics data
 *
 * @{
 */
typedef struct
{
	const char
		*hostname,
		*alpn_protocol;
	long long
		tls_secs; //milliseconds
	int
		version,
		cert_chain_size;
	char
		http_protocol;
	bool
		false_start,
		tfo,
		tls_con,
		resumed;
} wget_tls_stats_data;

typedef void
	wget_tls_stats_callback(wget_tls_stats_data *stats, void *ctx);

WGETAPI void
	wget_ssl_set_stats_callback_tls(wget_tls_stats_callback *fn, void *ctx);
/** @} */

typedef enum {
	WGET_STATS_HPKP_NO = 0,
	WGET_STATS_HPKP_MATCH = 1,
	WGET_STATS_HPKP_NOMATCH = 2,
	WGET_STATS_HPKP_ERROR = 3
} wget_hpkp_stats_result;

typedef void
	wget_server_stats_callback(wget_http_connection *conn, wget_http_response *resp);

WGETAPI void
	wget_server_set_stats_callback(wget_server_stats_callback *fn);

typedef enum {
	WGET_STATS_FORMAT_HUMAN = 0,
	WGET_STATS_FORMAT_CSV = 1,
} wget_stats_format;

WGET_END_DECLS

/*
 * Regex Types
 */

#define WGET_REGEX_TYPE_POSIX 0
#define WGET_REGEX_TYPE_PCRE 1

#undef RETURNS_NONNULL

#endif /* WGET_WGET_H */
