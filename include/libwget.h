/*
 * Copyright(c) 2012-2015 Tim Ruehsen
 * Copyright(c) 2015 Free Software Foundation, Inc.
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
# define _LIBWGET_LIBWGET_H

# include <stddef.h>
# ifdef HAVE_LIBPTHREAD
#  include <pthread.h>
# endif
# include <sys/types.h>
# include <unistd.h>
# include <stdarg.h>
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# ifdef WITH_LIBNGHTTP2
#  include <nghttp2/nghttp2.h>
# endif

// transitional defines, remove when migration to libwget is done
# define xmalloc wget_malloc
# define xcalloc wget_calloc
# define xrealloc wget_realloc

/*
 * Attribute defines specific for clang (especially for improving clang analyzer)
 * Using G_GNU_ as prefix to let gtk-doc recognize the attributes.
 */

/*
 * Attribute defines for GCC and compatible compilers
 * Using G_GNU_ as prefix to let gtk-doc recognize the attributes.
 */

# if defined(__GNUC__) && defined(__GNUC_MINOR__)
#  define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
# else
#  define GCC_VERSION_AT_LEAST(major, minor) 0
# endif

# if GCC_VERSION_AT_LEAST(2,5)
#  define G_GNUC_WGET_CONST __attribute__ ((const))
#  define G_GNUC_WGET_NORETURN __attribute__ ((noreturn))
# else
#  define G_GNUC_WGET_CONST
#  define G_GNUC_WGET_NORETURN
# endif

# if GCC_VERSION_AT_LEAST(2,95)
#  define G_GNUC_WGET_PRINTF_FORMAT(a, b) __attribute__ ((format (printf, a, b)))
#  define G_GNUC_WGET_UNUSED __attribute__ ((unused))
# else
#  define G_GNUC_WGET_PRINT_FORMAT(a, b)
#  define G_GNUC_WGET_UNUSED
# endif

# if GCC_VERSION_AT_LEAST(2,96)
#  define G_GNUC_WGET_PURE __attribute__ ((pure))
# else
#  define G_GNUC_WGET_PURE
# endif

# if GCC_VERSION_AT_LEAST(3,0)
#  define G_GNUC_WGET_MALLOC __attribute__ ((malloc))
#  define unlikely(expr) __builtin_expect(!!(expr), 0)
#  define likely(expr) __builtin_expect(!!(expr), 1)
# else
#  define G_GNUC_WGET_MALLOC
#  define unlikely(expr) expr
#  define likely(expr) expr
# endif

# if GCC_VERSION_AT_LEAST(3,1)
#  define G_GNUC_WGET_ALWAYS_INLINE __attribute__ ((always_inline))
#  define G_GNUC_WGET_DEPRECATED __attribute__ ((deprecated))
# else
#  define G_GNUC_WGET_ALWAYS_INLINE
#  define G_GNUC_WGET_DEPRECATED
# endif

// nonnull is dangerous to use with current gcc <= 4.7.1.
// see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308
// we have to use e.g. the clang analyzer if we want NONNULL.
// but even clang is not perfect - don't use nonnull in production
# if defined(__clang__)
#  if GCC_VERSION_AT_LEAST(3,3)
#   define G_GNUC_WGET_NONNULL_ALL __attribute__ ((nonnull))
#   define G_GNUC_WGET_NONNULL(a) __attribute__ ((nonnull a))
#  else
#   define G_GNUC_WGET_NONNULL_ALL
#   define G_GNUC_WGET_NONNULL(a)
#  endif
# elif GCC_VERSION_AT_LEAST(3,3)
#  define G_GNUC_WGET_NONNULL_ALL __attribute__ ((nonnull))
#  define G_GNUC_WGET_NONNULL(a) __attribute__ ((nonnull a))
# else
#  define G_GNUC_WGET_NONNULL_ALL
#  define G_GNUC_WGET_NONNULL(a)
# endif

# if GCC_VERSION_AT_LEAST(3,4)
#  define G_GNUC_WGET_UNUSED_RESULT __attribute__ ((warn_unused_result))
# else
#  define G_GNUC_WGET_UNUSED_RESULT
# endif

# if GCC_VERSION_AT_LEAST(4,0)
#  define G_GNUC_WGET_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_WGET_NULL_TERMINATED
# endif

# if defined(__clang__)
#  define G_GNUC_WGET_ALLOC_SIZE(a)
#  define G_GNUC_WGET_ALLOC_SIZE2(a, b)
# elif GCC_VERSION_AT_LEAST(4,3)
#  define G_GNUC_WGET_ALLOC_SIZE(a) __attribute__ ((__alloc_size__(a)))
#  define G_GNUC_WGET_ALLOC_SIZE2(a, b) __attribute__ ((__alloc_size__(a, b)))
# else
#  define G_GNUC_WGET_ALLOC_SIZE(a)
#  define G_GNUC_WGET_ALLOC_SIZE2(a, b)
# endif

// Let C++ include C headers
# ifdef  __cplusplus
#  define WGET_BEGIN_DECLS  extern "C" {
#  define WGET_END_DECLS    }
# else
#  define WGET_BEGIN_DECLS
#  define WGET_END_DECLS
# endif

// Include libintl.h before we redefine gettext stuff
# ifdef HAVE_LIBINTL_H
#  include <libintl.h>
# endif

# if ENABLE_NLS != 0
#  undef gettext
#  define _(STRING) gettext(STRING)
# else
#  undef ngettext
#  define _(STRING) STRING
#  define ngettext(STRING1,STRING2,N) STRING2
# endif

//#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901
//#  define restrict
//#endif

# undef GCC_VERSION_AT_LEAST

// we can prefix the exposed functions as we want
# ifndef _WGET_PREFIX
#  define _WGET_PREFIX wget_
# endif

WGET_BEGIN_DECLS
/*
 * Library initialization functions
 */
// Why not using enum ? Might result in different values if one entry is inserted.
// And that might break the ABI.
# define WGET_DEBUG_STREAM 1000
# define WGET_DEBUG_FUNC   1001
# define WGET_DEBUG_FILE   1002
# define WGET_ERROR_STREAM 1003
# define WGET_ERROR_FUNC   1004
# define WGET_ERROR_FILE   1005
# define WGET_INFO_STREAM  1006
# define WGET_INFO_FUNC    1007
# define WGET_INFO_FILE    1008
# define WGET_DNS_CACHING  1009
# define WGET_COOKIE_SUFFIXES 1010
# define WGET_COOKIES_ENABLED 1011
# define WGET_COOKIE_FILE 1012
# define WGET_COOKIE_DB 1013
# define WGET_COOKIE_KEEPSESSIONCOOKIES 1014
# define WGET_BIND_ADDRESS 1015
# define WGET_NET_FAMILY_EXCLUSIVE 1016
# define WGET_NET_FAMILY_PREFERRED 1017
# define WGET_TCP_FASTFORWARD  1018
# define WGET_HTTP_URL          2000
# define WGET_HTTP_URL_ENCODING 2001
# define WGET_HTTP_URI          2002
# define WGET_HTTP_COOKIE_STORE 2003
# define WGET_HTTP_HEADER_ADD   2004
//#define WGET_HTTP_HEADER_DEL   2005
//#define WGET_HTTP_HEADER_SET   2006
//#define WGET_HTTP_BIND_ADDRESS 2007
# define WGET_HTTP_CONNECTION_PTR 2008
# define WGET_HTTP_RESPONSE_KEEPHEADER 2009
# define WGET_HTTP_MAX_REDIRECTIONS 2010
# define WGET_HTTP_BODY_SAVEAS_STREAM 2011
# define WGET_HTTP_BODY_SAVEAS_FILE 2012
# define WGET_HTTP_BODY_SAVEAS_FD 2013
# define WGET_HTTP_BODY_SAVEAS_FUNC 2014
# define WGET_HTTP_HEADER_FUNC 2015
// definition of error conditions
# define WGET_E_SUCCESS 0  /* OK */
# define WGET_E_UNKNOWN -1  /* general error if nothing else appropriate */
# define WGET_E_INVALID -2  /* invalid value to function */
# define WGET_E_TIMEOUT -3  /* timeout condition */
# define WGET_E_CONNECT -4  /* connect failure */
# define WGET_E_HANDSHAKE -5  /* general TLS handshake failure */
# define WGET_E_CERTIFICATE -6  /* general TLS certificate failure */
void
wget_global_init (int key, ...)
G_GNUC_WGET_NULL_TERMINATED;
void wget_global_deinit (void);
const void *wget_global_get_ptr (int key);
int wget_global_get_int (int key);

/*
 * Utility functions
 */

/**
 * WGET_UTILITY:
 *
 * General utility functions
 */

// <mode> values for wget_ready_to_transfer()
# define WGET_IO_READABLE 1
# define WGET_IO_WRITABLE 2

int wget_ready_2_read (int fd, int timeout);
int wget_ready_2_write (int fd, int timeout);
int wget_ready_2_transfer (int fd, int timeout, short mode);
int wget_strcmp (const char *s1, const char *s2) G_GNUC_WGET_PURE;
int wget_strcasecmp (const char *s1, const char *s2) G_GNUC_WGET_PURE;
int
wget_strcasecmp_ascii (const char *s1,
                       const char *s2) G_GNUC_WGET_PURE;
int wget_strncasecmp_ascii (const char *s1, const char *s2,
                            size_t n) G_GNUC_WGET_PURE;
char *wget_strtolower (char *s);
int
wget_strncmp (const char *s1, const char *s2,
              size_t n) G_GNUC_WGET_PURE;
int wget_strncasecmp (const char *s1, const char *s2,
                      size_t n) G_GNUC_WGET_PURE;
void wget_memtohex (const unsigned char *src, size_t src_len, char *dst,
                    size_t dst_size) G_GNUC_WGET_NONNULL_ALL;
void wget_millisleep (int ms);
int wget_percent_unescape (char *src);
int wget_match_tail (const char *s, const char *tail) G_GNUC_WGET_PURE;
int
wget_match_tail_nocase (const char *s,
                        const char *tail) G_GNUC_WGET_PURE;
ssize_t
wget_fdgetline (char **buf, size_t * bufsize, int fd)
  G_GNUC_WGET_NONNULL_ALL;
ssize_t
wget_getline (char **buf, size_t * bufsize, FILE * fp)
  G_GNUC_WGET_NONNULL_ALL;
FILE *wget_vpopenf (const char *type, const char *fmt,
                    va_list args) G_GNUC_WGET_PRINTF_FORMAT (2,
                                                             0)
  G_GNUC_WGET_NONNULL ((1, 2));
FILE *wget_popenf (const char *type, const char *fmt,
                   ...) G_GNUC_WGET_PRINTF_FORMAT (2,
                                                   3)
  G_GNUC_WGET_NONNULL ((1, 2));
FILE *wget_popen2f (FILE ** fpin, FILE ** fpout, const char *fmt,
                    ...) G_GNUC_WGET_PRINTF_FORMAT (3,
                                                    4)
  G_GNUC_WGET_NONNULL ((3));
pid_t
wget_fd_popen3 (int *fdin, int *fdout, int *fderr, const char *const *argv);
pid_t
wget_popen3 (FILE ** fpin, FILE ** fpout, FILE ** fperr,
             const char *const *argv);
/*
  size_t
  wget_vbsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, va_list) G_GNUC_WGET_PRINTF_FORMAT(3,0);
  size_t
  wget_bsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(3,4);
*/
char *wget_read_file (const char *fname, size_t * size);
const char *wget_local_charset_encoding (void);
char *wget_charset_transcode (const char *src, const char *src_encoding,
                              const char *dst_encoding)
  G_GNUC_WGET_MALLOC;
int wget_str_needs_encoding (const char *s) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_PURE;
int wget_str_is_valid_utf8 (const char *utf8) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_PURE;
char *wget_str_to_utf8 (const char *src,
                        const char *encoding) G_GNUC_WGET_MALLOC;
char *wget_utf8_to_str (const char *src,
                        const char *encoding) G_GNUC_WGET_MALLOC;
const char *wget_str_to_ascii (const char *src);

/**
 * WGET_COMPATIBILITY:
 *
 * General compatibility functions
 */

# ifndef HAVE_STRNDUP
char *strndup (const char *s, size_t n)
  G_GNUC_WGET_MALLOC G_GNUC_WGET_NONNULL_ALL;
# endif

# ifndef HAVE_STRDUP
#  define strdup(s) strndup((s), strlen(s))
# endif

# ifndef HAVE_STRLCPY
size_t
strlcpy (char *restrict dst, const char *restrict src, size_t size)
  G_GNUC_WGET_NONNULL_ALL;
# endif

# ifndef HAVE_DPRINTF
int
vdprintf (int fd, const char *restrict fmt,
          va_list) G_GNUC_WGET_PRINTF_FORMAT (2, 0);
int dprintf (int fd, const char *restrict fmt,
             ...) G_GNUC_WGET_PRINTF_FORMAT (2, 3);
# endif /* HAVE_DPRINTF */

/*
 * Double linked list
 */

/**
 * WGET_LIST:
 *
 * Type for double linked lists and list entries.
 */
typedef struct _wget_list_st wget_list_t;

void *wget_list_append (wget_list_t ** list, const void *data,
                        size_t size) G_GNUC_WGET_NONNULL_ALL;
void *wget_list_prepend (wget_list_t ** list, const void *data,
                         size_t size) G_GNUC_WGET_NONNULL_ALL;
void *wget_list_getfirst (const wget_list_t * list) G_GNUC_WGET_CONST;
void *wget_list_getlast (const wget_list_t * list) G_GNUC_WGET_PURE;
void
wget_list_remove (wget_list_t ** list,
                  void *elem) G_GNUC_WGET_NONNULL_ALL;
void wget_list_free (wget_list_t ** list) G_GNUC_WGET_NONNULL_ALL;
int
wget_list_browse (const wget_list_t * list,
                  int (*browse) (void *context, void *elem),
                  void *context) G_GNUC_WGET_NONNULL ((2));

/*
 * Memory allocation routines
 */

// I try to never leave freed pointers hanging around
# define wget_xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

void *wget_malloc (size_t size)
  G_GNUC_WGET_MALLOC G_GNUC_WGET_ALLOC_SIZE (1);
void *wget_calloc (size_t nmemb, size_t size)
  G_GNUC_WGET_MALLOC G_GNUC_WGET_ALLOC_SIZE2 (1, 2);
void *wget_realloc (void *ptr, size_t size) G_GNUC_WGET_ALLOC_SIZE (2);
void wget_set_oomfunc (void (*oom_callback) (void));

/*
 * String/Memory routines, slightly different than standard functions
 */

void *wget_memdup (const void *s, size_t n) G_GNUC_WGET_ALLOC_SIZE (2);
char *wget_strdup (const char *s) G_GNUC_WGET_MALLOC;
char *wget_strmemdup (const void *s,
                      size_t n) G_GNUC_WGET_ALLOC_SIZE (2);
void wget_strmemcpy (char *s, size_t ssize, const void *m,
                     size_t n) G_GNUC_WGET_NONNULL_ALL;

/*
 * Base64 routines
 */

int wget_base64_is_string (const char *src) G_GNUC_WGET_PURE;
size_t
wget_base64_decode (char *restrict dst, const char *restrict src, int n)
  G_GNUC_WGET_NONNULL_ALL;
size_t
wget_base64_encode (char *restrict dst, const char *restrict src, int n)
  G_GNUC_WGET_NONNULL_ALL;
char *wget_base64_decode_alloc (const char *restrict src,
                                int n) G_GNUC_WGET_NONNULL_ALL;
char *wget_base64_encode_alloc (const char *restrict src,
                                int n) G_GNUC_WGET_NONNULL_ALL;
char *wget_base64_encode_vprintf_alloc (const char *restrict fmt,
                                        va_list args)
  G_GNUC_WGET_PRINTF_FORMAT (1, 0) G_GNUC_WGET_NONNULL_ALL;
char *wget_base64_encode_printf_alloc (const char *restrict fmt,
                                       ...) G_GNUC_WGET_PRINTF_FORMAT (1,
                                                                       2)
  G_GNUC_WGET_NONNULL_ALL;

/*
 * Buffer routines
 */

typedef struct
{
  char *data;    // pointer to internal memory
  size_t length;    // number of bytes in 'data'
  size_t size;    // capacity of 'data' (terminating 0 byte doesn't count here)
  unsigned int release_data:1;  // 'data' has been malloc'ed and must be freed
  unsigned int release_buf:1;  // buffer_t structure has been malloc'ed and must be freed
} wget_buffer_t;

wget_buffer_t *wget_buffer_init (wget_buffer_t * buf, char *data,
                                 size_t size);
wget_buffer_t *wget_buffer_alloc (size_t size)
  G_GNUC_WGET_MALLOC G_GNUC_WGET_ALLOC_SIZE (1);
void
wget_buffer_ensure_capacity (wget_buffer_t * buf,
                             size_t size) G_GNUC_WGET_NONNULL ((1));
void wget_buffer_deinit (wget_buffer_t * buf);
void wget_buffer_free (wget_buffer_t ** buf);
void wget_buffer_free_data (wget_buffer_t * buf);
void
wget_buffer_realloc (wget_buffer_t * buf,
                     size_t size) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_ALLOC_SIZE (2);
void wget_buffer_reset (wget_buffer_t * buf);
size_t
wget_buffer_memcpy (wget_buffer_t * buf, const void *data, size_t length)
  G_GNUC_WGET_NONNULL ((1, 2));
size_t
wget_buffer_memcat (wget_buffer_t * buf, const void *data, size_t length)
  G_GNUC_WGET_NONNULL ((1, 2));
size_t
wget_buffer_strcpy (wget_buffer_t * buf, const char *s)
  G_GNUC_WGET_NONNULL ((1, 2));
size_t
wget_buffer_strcat (wget_buffer_t * buf, const char *s)
  G_GNUC_WGET_NONNULL ((1, 2));
size_t
wget_buffer_bufcpy (wget_buffer_t * buf, wget_buffer_t * src)
  G_GNUC_WGET_NONNULL ((1, 2));
size_t
wget_buffer_bufcat (wget_buffer_t * buf, wget_buffer_t * src)
  G_GNUC_WGET_NONNULL ((1, 2));
size_t
wget_buffer_memset (wget_buffer_t * buf, char c, size_t length)
  G_GNUC_WGET_NONNULL ((1));
size_t
wget_buffer_memset_append (wget_buffer_t * buf, char c, size_t length)
  G_GNUC_WGET_NONNULL ((1));
char *wget_buffer_trim (wget_buffer_t * buf) G_GNUC_WGET_NONNULL ((1));
size_t
wget_buffer_vprintf_append (wget_buffer_t * buf, const char *fmt,
                            va_list args)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 0);
size_t
wget_buffer_printf_append (wget_buffer_t * buf, const char *fmt, ...)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 3);
size_t
wget_buffer_vprintf (wget_buffer_t * buf, const char *fmt, va_list args)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 0);
size_t
wget_buffer_printf (wget_buffer_t * buf, const char *fmt, ...)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 3);
size_t
wget_buffer_vprintf_append2 (wget_buffer_t * buf, const char *fmt,
                             va_list args)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 0);
size_t
wget_buffer_printf_append2 (wget_buffer_t * buf, const char *fmt, ...)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 3);
size_t
wget_buffer_vprintf2 (wget_buffer_t * buf, const char *fmt, va_list args)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 0);
size_t
wget_buffer_printf2 (wget_buffer_t * buf, const char *fmt, ...)
  G_GNUC_WGET_NONNULL ((1, 2))
  G_GNUC_WGET_PRINTF_FORMAT (2, 3);

/*
 * Logger routines
 */

typedef struct _wget_logger_st wget_logger_t;
typedef void (*wget_logger_func_t) (const char *buf,
                                    size_t len) G_GNUC_WGET_NONNULL_ALL;

void wget_logger_set_func (wget_logger_t * logger, wget_logger_func_t);
//  wget_logger_set_func(wget_logger_t *logger, void (*func)(const char *buf G_GNUC_WGET_NONNULL, size_t len));
void wget_logger_set_stream (wget_logger_t * logger, FILE * fp);
void wget_logger_set_file (wget_logger_t * logger, const char *fname);
void
(*wget_logger_get_func (wget_logger_t * logger)) (const char *,
                                                  size_t)
  G_GNUC_WGET_PURE;
FILE *wget_logger_get_stream (wget_logger_t * logger) G_GNUC_WGET_PURE;
const char *wget_logger_get_file (wget_logger_t *
                                  logger) G_GNUC_WGET_PURE;

/*
 * Logging routines
 */

# define WGET_LOGGER_INFO   1
# define WGET_LOGGER_ERROR  2
# define WGET_LOGGER_DEBUG  3

void wget_info_vprintf (const char *fmt, va_list args)
  G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT (1, 0);
void
wget_info_printf (const char *fmt,
                  ...) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_PRINTF_FORMAT (1, 2);
void wget_error_vprintf (const char *fmt, va_list args)
  G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT (1, 0);
void
wget_error_printf (const char *fmt,
                   ...) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_PRINTF_FORMAT (1, 2);
void wget_error_printf_exit (const char *fmt,
                             ...) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_NORETURN G_GNUC_WGET_PRINTF_FORMAT (1, 2);
void wget_debug_vprintf (const char *fmt, va_list args)
  G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT (1, 0);
void
wget_debug_printf (const char *fmt,
                   ...) G_GNUC_WGET_NONNULL ((1))
  G_GNUC_WGET_PRINTF_FORMAT (1, 2);
void wget_debug_write (const char *buf,
                       size_t len) G_GNUC_WGET_NONNULL_ALL;
wget_logger_t *wget_get_logger (int id) G_GNUC_WGET_CONST;

/*
 * Vector datatype routines
 */

typedef struct _wget_vector_st wget_vector_t;

wget_vector_t *wget_vector_create (int max, int off,
                                   int (*cmp) (const void *,
                                               const void *))
  G_GNUC_WGET_MALLOC;
int wget_vector_find (const wget_vector_t * v,
                      const void *elem) G_GNUC_WGET_NONNULL ((2));
int wget_vector_findext (const wget_vector_t * v, int start,
                         int direction,
                         int (*find) (void *)) G_GNUC_WGET_NONNULL ((4));
int wget_vector_contains (const wget_vector_t * v,
                          const void *elem) G_GNUC_WGET_NONNULL ((2));
int wget_vector_insert (wget_vector_t * v, const void *elem, size_t size,
                        int pos) G_GNUC_WGET_NONNULL ((2));
int wget_vector_insert_noalloc (wget_vector_t * v, const void *elem,
                                int pos) G_GNUC_WGET_NONNULL ((2));
int wget_vector_insert_sorted (wget_vector_t * v, const void *elem,
                               size_t size) G_GNUC_WGET_NONNULL ((2));
int wget_vector_insert_sorted_noalloc (wget_vector_t * v,
                                       const void *elem)
  G_GNUC_WGET_NONNULL ((2));
int wget_vector_add (wget_vector_t * v, const void *elem,
                     size_t size) G_GNUC_WGET_NONNULL ((2));
int wget_vector_add_noalloc (wget_vector_t * v,
                             const void *elem) G_GNUC_WGET_NONNULL ((2));
int wget_vector_add_str (wget_vector_t * v,
                         const char *s) G_GNUC_WGET_NONNULL ((2));
int wget_vector_add_vprintf (wget_vector_t * v, const char *fmt,
                             va_list args) G_GNUC_WGET_PRINTF_FORMAT (2,
                                                                      0)
  G_GNUC_WGET_NONNULL ((2));
int wget_vector_add_printf (wget_vector_t * v, const char *fmt,
                            ...) G_GNUC_WGET_PRINTF_FORMAT (2,
                                                            3)
  G_GNUC_WGET_NONNULL ((2));
int wget_vector_replace (wget_vector_t * v, const void *elem,
                         size_t size, int pos) G_GNUC_WGET_NONNULL ((2));
int wget_vector_replace_noalloc (wget_vector_t * v, const void *elem,
                                 int pos) G_GNUC_WGET_NONNULL ((2));
int wget_vector_move (wget_vector_t * v, int old_pos, int new_pos);
int wget_vector_swap (wget_vector_t * v, int pos1, int pos2);
int wget_vector_remove (wget_vector_t * v, int pos);
int wget_vector_remove_nofree (wget_vector_t * v, int pos);
int wget_vector_size (const wget_vector_t * v) G_GNUC_WGET_PURE;
int
wget_vector_browse (const wget_vector_t * v,
                    int (*browse) (void *ctx, void *elem),
                    void *ctx) G_GNUC_WGET_NONNULL ((2));
void wget_vector_free (wget_vector_t ** v);
void wget_vector_clear (wget_vector_t * v);
void wget_vector_clear_nofree (wget_vector_t * v);
void *wget_vector_get (const wget_vector_t * v,
                       int pos) G_GNUC_WGET_PURE;
void wget_vector_setcmpfunc (wget_vector_t * v,
                             int (*cmp) (const void *elem1,
                                         const void *elem2))
  G_GNUC_WGET_NONNULL ((2));
void wget_vector_set_destructor (wget_vector_t * v,
                                 void (*destructor) (void *elem));
void wget_vector_sort (wget_vector_t * v);

/*
 * Hashmap datatype routines
 */

typedef struct _wget_hashmap_st wget_hashmap_t;

wget_hashmap_t
* wget_hashmap_create (int max, int off,
                       unsigned int (*hash) (const void *),
                       int (*cmp) (const void *, const void *))
  G_GNUC_WGET_MALLOC;
int
wget_hashmap_put (wget_hashmap_t * h, const void *key, size_t keysize,
                  const void *value, size_t valuesize);
int
wget_hashmap_put_noalloc (wget_hashmap_t * h, const void *key,
                          const void *value);
//int
//  wget_hashmap_put_ident(WGET_HASHMAP *h, const void *key, size_t keysize);
//int
//  wget_hashmap_put_ident_noalloc(WGET_HASHMAP *h, const void *key);
int
wget_hashmap_size (const wget_hashmap_t * h)
  G_GNUC_WGET_PURE;
int
wget_hashmap_browse (const wget_hashmap_t * h,
                     int (*browse) (void *ctx, const void *key,
                                    void *value), void *ctx)
  G_GNUC_WGET_NONNULL ((2));
void
wget_hashmap_free (wget_hashmap_t ** h);
void
wget_hashmap_clear (wget_hashmap_t * h);
void *
wget_hashmap_get (const wget_hashmap_t * h, const void *key);
int
wget_hashmap_get_null (const wget_hashmap_t * h, const void *key,
                       void **value);
int
wget_hashmap_contains (const wget_hashmap_t * h, const void *key);
int
wget_hashmap_remove (wget_hashmap_t * h, const void *key);
int
wget_hashmap_remove_nofree (wget_hashmap_t * h, const void *key);
void
wget_hashmap_setcmpfunc (wget_hashmap_t * h,
                         int (*cmp) (const void *key1,
                                     const void *key2));
void
wget_hashmap_sethashfunc (wget_hashmap_t * h,
                          unsigned int (*hash) (const void *key));
void
wget_hashmap_set_key_destructor (wget_hashmap_t * h,
                                 void (*destructor) (void *key));
void
wget_hashmap_set_value_destructor (wget_hashmap_t * h,
                                   void (*destructor) (void *value));
void
wget_hashmap_setloadfactor (wget_hashmap_t * h, float factor);

/*
 * Hashmap datatype routines
 */

typedef wget_hashmap_t
wget_stringmap_t;

wget_stringmap_t *
wget_stringmap_create (int max)
  G_GNUC_WGET_MALLOC;
wget_stringmap_t *
wget_stringmap_create_nocase (int max)
  G_GNUC_WGET_MALLOC;
int
wget_stringmap_put (wget_stringmap_t * h, const char *key,
                    const void *value, size_t valuesize);
int
wget_stringmap_put_noalloc (wget_stringmap_t * h, const char *key,
                            const void *value);
//int
//  wget_stringmap_put_ident(WGET_STRINGMAP *h, const char *key);
//int
//  wget_stringmap_put_ident_noalloc(WGET_STRINGMAP *h, const char *key);
int
wget_stringmap_size (const wget_stringmap_t * h)
  G_GNUC_WGET_PURE;
int
wget_stringmap_browse (const wget_stringmap_t * h,
                       int (*browse) (void *ctx, const char *key,
                                      void *value), void *ctx)
  G_GNUC_WGET_NONNULL ((2));
void
wget_stringmap_free (wget_stringmap_t ** h);
void
wget_stringmap_clear (wget_stringmap_t * h);
void *
wget_stringmap_get (const wget_stringmap_t * h, const char *key);
int
wget_stringmap_get_null (const wget_stringmap_t * h, const char *key,
                         void **value);
int
wget_stringmap_contains (const wget_stringmap_t * h, const char *key);
int
wget_stringmap_remove (wget_stringmap_t * h, const char *key);
int
wget_stringmap_remove_nofree (wget_stringmap_t * h, const char *key);
void
wget_stringmap_setcmpfunc (wget_stringmap_t * h,
                           int (*cmp) (const char *key1,
                                       const char *key2));
void
wget_stringmap_sethashfunc (wget_stringmap_t * h,
                            unsigned int (*hash) (const char *key));
void
wget_stringmap_setloadfactor (wget_stringmap_t * h, float factor);
void
wget_stringmap_set_value_destructor (wget_hashmap_t * h,
                                     void (*destructor) (void *value));

/*
 * Thread wrapper routines
 */

# ifdef PTHREAD_MUTEX_INITIALIZER
#  define WGET_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#  define WGET_THREAD_COND_INITIALIZER PTHREAD_COND_INITIALIZER
typedef pthread_t
wget_thread_t;
typedef pthread_mutex_t
wget_thread_mutex_t;
typedef pthread_cond_t
wget_thread_cond_t;
# else
#  define WGET_THREAD_MUTEX_INITIALIZER 0
typedef unsigned long int
wget_thread_t;
typedef int
wget_thread_mutex_t;
typedef int
wget_thread_cond_t;
# endif

int
wget_thread_start (wget_thread_t * thread,
                   void *(*start_routine) (void *), void *arg,
                   int flags);
int
wget_thread_mutex_init (wget_thread_mutex_t * mutex);
void
wget_thread_mutex_lock (wget_thread_mutex_t *);
void
wget_thread_mutex_unlock (wget_thread_mutex_t *);
int
wget_thread_kill (wget_thread_t thread, int sig);
int
wget_thread_join (wget_thread_t thread);
int
wget_thread_cond_init (wget_thread_cond_t * cond);
int
wget_thread_cond_signal (wget_thread_cond_t * cond);
int
wget_thread_cond_wait (wget_thread_cond_t * cond,
                       wget_thread_mutex_t * mutex);
wget_thread_t
wget_thread_self (void)
  G_GNUC_WGET_CONST;

/*
 * Decompressor routines
 */

typedef struct _wget_decompressor_st wget_decompressor_t;

enum
  {
    wget_content_encoding_identity,
    wget_content_encoding_gzip,
    wget_content_encoding_deflate,
    wget_content_encoding_lzma,
    wget_content_encoding_bzip2
  };

wget_decompressor_t *wget_decompress_open (int encoding,
                                           int (*put_data) (void
                                                            *context,
                                                            const char
                                                            *data,
                                                            size_t
                                                            length),
                                           void *context);
void wget_decompress_close (wget_decompressor_t * dc);
int wget_decompress (wget_decompressor_t * dc, char *src, size_t srclen);

/*
 * URI/IRI routines
 */

// TODO: i have to move this away from libwget.h
extern const char *const wget_iri_schemes[];

# define WGET_IRI_SCHEME_HTTP    (wget_iri_schemes[0])
# define WGET_IRI_SCHEME_HTTPS   (wget_iri_schemes[1])
# define WGET_IRI_SCHEME_FTP     (wget_iri_schemes[2])
# define WGET_IRI_SCHEME_DEFAULT WGET_IRI_SCHEME_HTTP

typedef struct wget_iri_st
{
  const char *uri;    // pointer to original URI string, unescaped and converted to UTF-8
  const char *display;
  const char *scheme;
  const char *userinfo;
  const char *password;
  const char *host;  // unescaped, toASCII converted, lowercase host (or IP address) part
  const char *port;
  const char *resolv_port;
  const char *path;  // unescaped path part or NULL
  const char *query;  // unescaped query part or NULL
  const char *fragment;  // unescaped fragment part or NULL
  const char *connection_part;  // helper, e.g. http://www.example.com:8080
  size_t dirlen;    // length of directory part in 'path' (needed/initialized with --no-parent)
  char host_allocated;  // if set, free host in iri_free()
} wget_iri_t;

void wget_iri_test (void);
void wget_iri_free (wget_iri_t ** iri);
void wget_iri_free_content (wget_iri_t * iri);
void wget_iri_set_defaultpage (const char *page);
int wget_iri_supported (const wget_iri_t * iri)
  G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL_ALL;
int wget_iri_isgendelim (char c) G_GNUC_WGET_CONST;
int wget_iri_issubdelim (char c) G_GNUC_WGET_CONST;
int wget_iri_isreserved (char c) G_GNUC_WGET_CONST;
int wget_iri_isunreserved (char c) G_GNUC_WGET_PURE;
int wget_iri_isunreserved_path (char c) G_GNUC_WGET_PURE;
int wget_iri_compare (wget_iri_t * iri1, wget_iri_t * iri2)
  G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL_ALL;
wget_iri_t *wget_iri_parse (const char *uri, const char *encoding);
wget_iri_t *wget_iri_parse_base (wget_iri_t * base, const char *url,
                                 const char *encoding);
wget_iri_t *wget_iri_clone (wget_iri_t * iri);
const char *wget_iri_get_connection_part (wget_iri_t * iri);
const char *wget_iri_relative_to_abs (wget_iri_t * base, const char *val,
                                      size_t len, wget_buffer_t * buf);
const char *wget_iri_escape (const char *src,
                             wget_buffer_t *
                             buf) G_GNUC_WGET_NONNULL_ALL;
const char *wget_iri_escape_path (const char *src,
                                  wget_buffer_t *
                                  buf) G_GNUC_WGET_NONNULL_ALL;
const char *wget_iri_escape_query (const char *src,
                                   wget_buffer_t *
                                   buf) G_GNUC_WGET_NONNULL_ALL;
const char *wget_iri_get_escaped_host (const wget_iri_t * iri,
                                       wget_buffer_t *
                                       buf) G_GNUC_WGET_NONNULL_ALL;
const char *wget_iri_get_escaped_resource (const wget_iri_t * iri,
                                           wget_buffer_t *
                                           buf) G_GNUC_WGET_NONNULL_ALL;
char *wget_iri_get_path (const wget_iri_t * iri, wget_buffer_t * buf,
                         const char *encoding) G_GNUC_WGET_NONNULL ((1,
                                                                     2));
char *wget_iri_get_query_as_filename (const wget_iri_t * iri,
                                      wget_buffer_t * buf,
                                      const char *encoding)
  G_GNUC_WGET_NONNULL ((1, 2));
char *wget_iri_get_filename (const wget_iri_t * iri, wget_buffer_t * buf,
                             const char *encoding)
  G_GNUC_WGET_NONNULL ((1, 2));

/*
 * Cookie routines
 */

// typedef and structure for cookie database
typedef struct wget_cookie_db_st wget_cookie_db_t;

// structure for cookie store
//typedef struct wget_cookie_db_st wget_cookie_db_t;

typedef struct wget_cookie_st
{
  const char *name;
  const char *value;
  const char *domain;
  const char *path;
  time_t expires;  // time of expiration (format YYYYMMDDHHMMSS)
  time_t maxage;    // like expires, but precedes it if set
  time_t last_access;
  time_t creation;
  unsigned int domain_dot:1;  // for compatibility with Netscape cookie format
  unsigned int normalized:1;
  unsigned int persistent:1;
  unsigned int host_only:1;
  unsigned int secure_only:1;  // cookie should be used over secure connections only (TLS/HTTPS)
  unsigned int http_only:1;  // just use the cookie via HTTP/HTTPS protocol
} wget_cookie_t;

wget_cookie_t *wget_cookie_init (wget_cookie_t * cookie);
void wget_cookie_deinit (wget_cookie_t * cookie);
void wget_cookie_free (wget_cookie_t ** cookie);
void
wget_cookie_normalize_cookies (const wget_iri_t * iri,
                               const wget_vector_t * cookies);
int wget_cookie_store_cookie (wget_cookie_db_t * cookie_db,
                              wget_cookie_t * cookie);
void wget_cookie_store_cookies (wget_cookie_db_t * cookie_db,
                                wget_vector_t * cookies);
int wget_cookie_normalize (const wget_iri_t * iri,
                           wget_cookie_t * cookie);
int wget_cookie_check_psl (const wget_cookie_db_t * cookie_db,
                           const wget_cookie_t * cookie);
wget_cookie_db_t *wget_cookie_db_init (wget_cookie_db_t * cookie_db);
void wget_cookie_db_deinit (wget_cookie_db_t * cookie_db);
void wget_cookie_db_free (wget_cookie_db_t ** cookie_db);
int
wget_cookie_db_save (wget_cookie_db_t * cookie_db, const char *fname,
                     int keep_session_cookies);
int wget_cookie_db_load (wget_cookie_db_t * cookie_db, const char *fname,
                         int keep_session_cookies);
int wget_cookie_db_load_psl (wget_cookie_db_t * cookie_db,
                             const char *fname);
char *wget_cookie_create_request_header (wget_cookie_db_t * cookie_db,
                                         const wget_iri_t * iri);

/*
 * HTTP Strict Transport Security (HSTS) routines
 */

// structure for HTTP Strict Transport Security (HSTS) entries
typedef struct _wget_hsts_st wget_hsts_t;
typedef struct _wget_hsts_db_st wget_hsts_db_t;

wget_hsts_t *wget_hsts_init (wget_hsts_t * hsts);
void wget_hsts_deinit (wget_hsts_t * hsts);
void wget_hsts_free (wget_hsts_t * hsts);
wget_hsts_t *wget_hsts_new (const char *host, int port, time_t maxage,
                            int include_subdomains);
int wget_hsts_host_match (const wget_hsts_db_t * hsts_db,
                          const char *host, int port);

wget_hsts_db_t *wget_hsts_db_init (wget_hsts_db_t * hsts_db);
void wget_hsts_db_deinit (wget_hsts_db_t * hsts_db);
void wget_hsts_db_free (wget_hsts_db_t ** hsts_db);
void wget_hsts_db_add (wget_hsts_db_t * hsts_db, wget_hsts_t * hsts);
int wget_hsts_db_save (wget_hsts_db_t * hsts_db, const char *fname);
int wget_hsts_db_load (wget_hsts_db_t * hsts_db, const char *fname);

/*
 * Online Certificate Status Protocol (OCSP) routines
 */

// structure for Online Certificate Status Protocol (OCSP) entries
typedef struct _wget_ocsp_st wget_ocsp_t;
typedef struct _wget_ocsp_db_st wget_ocsp_db_t;

wget_ocsp_t *wget_ocsp_init (wget_ocsp_t * ocsp);
void wget_ocsp_deinit (wget_ocsp_t * ocsp);
void wget_ocsp_free (wget_ocsp_t * ocsp);
wget_ocsp_t *wget_ocsp_new (const char *fingerprint, time_t maxage,
                            int valid);
int wget_ocsp_fingerprint_in_cache (const wget_ocsp_db_t * ocsp_db,
                                    const char *fingerprint, int *valid);
int wget_ocsp_hostname_is_valid (const wget_ocsp_db_t * ocsp_db,
                                 const char *fingerprint);

wget_ocsp_db_t *wget_ocsp_db_init (wget_ocsp_db_t * ocsp_db);
void wget_ocsp_db_deinit (wget_ocsp_db_t * ocsp_db);
void wget_ocsp_db_free (wget_ocsp_db_t ** ocsp_db);
void
wget_ocsp_db_add_fingerprint (wget_ocsp_db_t * ocsp_db,
                              wget_ocsp_t * ocsp);
void wget_ocsp_db_add_host (wget_ocsp_db_t * ocsp_db,
                            wget_ocsp_t * ocsp);
int wget_ocsp_db_save (wget_ocsp_db_t * ocsp_db, const char *fname);
int wget_ocsp_db_load (wget_ocsp_db_t * ocsp_db, const char *fname);

/*
 * CSS parsing routines
 */

typedef struct
{
  size_t len;
  size_t pos;
  const char *url;
  const char *abs_url;
} WGET_PARSED_URL;

void
wget_css_parse_buffer (const char *buf,
                       void (*callback_uri) (void *user_ctx,
                                             const char *url,
                                             size_t len, size_t pos),
                       void (*callback_encoding) (void *user_ctx,
                                                  const char *url,
                                                  size_t len),
                       void *user_ctx) G_GNUC_WGET_NONNULL ((1));
void wget_css_parse_file (const char *fname,
                          void (*callback_uri) (void *user_ctx,
                                                const char *url,
                                                size_t len, size_t pos),
                          void (*callback_encoding) (void *user_ctx,
                                                     const char *url,
                                                     size_t len),
                          void *user_ctx) G_GNUC_WGET_NONNULL ((1));
wget_vector_t *wget_css_get_urls (const char *css, wget_iri_t * base,
                                  const char **encoding)
  G_GNUC_WGET_NONNULL ((1));
wget_vector_t *wget_css_get_urls_from_localfile (const char *fname,
                                                 wget_iri_t * base,
                                                 const char **encoding)
  G_GNUC_WGET_NONNULL ((1));

typedef struct
{
  const char *p;
  size_t len;
} wget_string_t;

typedef struct
{
  wget_string_t url;
  char attr[16];
  char dir[16];
} WGET_HTML_PARSED_URL;

typedef struct
{
  wget_vector_t * uris;
  const char *encoding;
  wget_string_t base;
  char follow;
} WGET_HTML_PARSED_RESULT;

typedef struct
{
  const char *name;
  const char *attribute;
} wget_html_tag_t;

WGET_HTML_PARSED_RESULT *wget_html_get_urls_inline (const char *html,
                                                    wget_vector_t *
                                                    additional_tags,
                                                    wget_vector_t *
                                                    ignore_tags);
void wget_html_free_urls_inline (WGET_HTML_PARSED_RESULT ** res);

void
wget_sitemap_get_urls_inline (const char *sitemap,
                              wget_vector_t ** urls,
                              wget_vector_t ** sitemap_urls);

void wget_atom_get_urls_inline (const char *atom, wget_vector_t ** urls);

void wget_rss_get_urls_inline (const char *rss, wget_vector_t ** urls);

/*
 * XML and HTML parsing routines
 */

# define XML_FLG_BEGIN      (1<<0)  // <
# define XML_FLG_CLOSE      (1<<1)  // >
# define XML_FLG_END        (1<<2)  // </elem>
# define XML_FLG_ATTRIBUTE  (1<<3)  // attr="value"
# define XML_FLG_CONTENT    (1<<4)
# define XML_FLG_COMMENT    (1<<5)  // <!-- ... -->
//#define XML_FLG_CDATA      (1<<6) // <![CDATA[...]]>, now same handling as 'special'
# define XML_FLG_PROCESSING (1<<7)  // e.g. <? ... ?>
# define XML_FLG_SPECIAL    (1<<8)  // e.g. <!DOCTYPE ...>

# define XML_HINT_REMOVE_EMPTY_CONTENT (1<<0)  // merge spaces, remove empty content
# define XML_HINT_HTML                 (1<<1)  // parse HTML instead of XML

# define HTML_HINT_REMOVE_EMPTY_CONTENT XML_HINT_REMOVE_EMPTY_CONTENT

typedef void wget_xml_callback_t (void *, int, const char *,
                                  const char *, const char *, size_t,
                                  size_t);

void
wget_xml_parse_buffer (const char *buf, wget_xml_callback_t * callback,
                       //    void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
                       void *user_ctx, int hints)
  G_GNUC_WGET_NONNULL ((1)),
  wget_xml_parse_file (const char *fname, wget_xml_callback_t * callback,
                       //    void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
                       void *user_ctx, int hints)
  G_GNUC_WGET_NONNULL ((1)),
  wget_html_parse_buffer (const char *buf, wget_xml_callback_t * callback,
                          //    void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
                          void *user_ctx, int hints)
  G_GNUC_WGET_NONNULL ((1)),
  wget_html_parse_file (const char *fname, wget_xml_callback_t * callback,
                        //    void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
                        void *user_ctx, int hints)
  G_GNUC_WGET_NONNULL ((1));

/*
 * TCP network routines
 */

# define WGET_NET_FAMILY_ANY  0
# define WGET_NET_FAMILY_IPV4 1
# define WGET_NET_FAMILY_IPV6 2

# define WGET_PROTOCOL_HTTP_1_1  0
# define WGET_PROTOCOL_HTTP_2_0  1

typedef struct wget_tcp_st wget_tcp_t;

wget_tcp_t *wget_tcp_init (void);
void wget_tcp_deinit (wget_tcp_t ** tcp);
void wget_dns_cache_free (void);
void wget_tcp_close (wget_tcp_t * tcp);
void wget_tcp_set_timeout (wget_tcp_t * tcp, int timeout);
int wget_tcp_get_timeout (wget_tcp_t * tcp) G_GNUC_WGET_PURE;
void wget_tcp_set_connect_timeout (wget_tcp_t * tcp, int timeout);
void wget_tcp_set_dns_timeout (wget_tcp_t * tcp, int timeout);
void wget_tcp_set_dns_caching (wget_tcp_t * tcp, int caching);
void wget_tcp_set_tcp_fastopen (wget_tcp_t * tcp, int tcp_fastopen);
void wget_tcp_set_ssl (wget_tcp_t * tcp, int ssl);
int wget_tcp_get_ssl (wget_tcp_t * tcp) G_GNUC_WGET_PURE;
void wget_tcp_set_ssl_hostname (wget_tcp_t * tcp, const char *hostname);
const char *wget_tcp_get_ssl_hostname (wget_tcp_t *
                                       tcp) G_GNUC_WGET_PURE;
void wget_tcp_set_ssl_ca_file (wget_tcp_t * tcp, const char *cafile);
void
wget_tcp_set_ssl_key_file (wget_tcp_t * tcp, const char *certfile,
                           const char *keyfile);
int wget_tcp_get_dns_caching (wget_tcp_t * tcp) G_GNUC_WGET_PURE;
int wget_tcp_get_family (wget_tcp_t * tcp) G_GNUC_WGET_PURE;
int wget_tcp_get_preferred_family (wget_tcp_t * tcp) G_GNUC_WGET_PURE;
int wget_tcp_get_protocol (wget_tcp_t * tcp);
int wget_tcp_get_local_port (wget_tcp_t * tcp);
void wget_tcp_set_debug (wget_tcp_t * tcp, int debug);
void wget_tcp_set_family (wget_tcp_t * tcp, int family);
void wget_tcp_set_preferred_family (wget_tcp_t * tcp, int family);
void wget_tcp_set_protocol (wget_tcp_t * tcp, int protocol);
void
wget_tcp_set_bind_address (wget_tcp_t * tcp, const char *bind_address);
struct addrinfo *wget_tcp_resolve (wget_tcp_t * tcp,
                                   const char *restrict name,
                                   const char *restrict port)
  G_GNUC_WGET_NONNULL ((2));
int wget_tcp_connect (wget_tcp_t * tcp, const char *host,
                      const char *port) G_GNUC_WGET_NONNULL ((1));
int wget_tcp_listen (wget_tcp_t * tcp, const char *host,
                     const char *port,
                     int backlog) G_GNUC_WGET_NONNULL ((1));
wget_tcp_t * wget_tcp_accept (wget_tcp_t *
                              parent_tcp) G_GNUC_WGET_NONNULL ((1));
int
wget_tcp_tls_start (wget_tcp_t * tcp)
  G_GNUC_WGET_NONNULL ((1));
void
wget_tcp_tls_stop (wget_tcp_t * tcp)
  G_GNUC_WGET_NONNULL ((1));
ssize_t
wget_tcp_vprintf (wget_tcp_t * tcp, const char *fmt, va_list args)
  G_GNUC_WGET_PRINTF_FORMAT (2, 0)
  G_GNUC_WGET_NONNULL_ALL;
ssize_t
wget_tcp_printf (wget_tcp_t * tcp, const char *fmt, ...)
  G_GNUC_WGET_PRINTF_FORMAT (2, 3)
  G_GNUC_WGET_NONNULL_ALL;
ssize_t
wget_tcp_write (wget_tcp_t * tcp, const char *buf, size_t count)
  G_GNUC_WGET_NONNULL_ALL;
ssize_t
wget_tcp_read (wget_tcp_t * tcp, char *buf, size_t count)
  G_GNUC_WGET_NONNULL_ALL;
int
wget_tcp_ready_2_transfer (wget_tcp_t * tcp,
                           int flags) G_GNUC_WGET_NONNULL_ALL;

/*
 * SSL routines
 */

# define WGET_SSL_X509_FMT_PEM 0
# define WGET_SSL_X509_FMT_DER 1

# define WGET_SSL_SECURE_PROTOCOL   1
# define WGET_SSL_CA_DIRECTORY      2
# define WGET_SSL_CA_FILE           3
# define WGET_SSL_CERT_FILE         4
# define WGET_SSL_KEY_FILE          5
# define WGET_SSL_CA_TYPE           6
# define WGET_SSL_CERT_TYPE         7
# define WGET_SSL_KEY_TYPE          8
# define WGET_SSL_CHECK_CERTIFICATE 9
# define WGET_SSL_CHECK_HOSTNAME    10
# define WGET_SSL_PRINT_INFO        11
# define WGET_SSL_DIRECT_OPTIONS    12
# define WGET_SSL_CRL_FILE          13
# define WGET_SSL_OCSP_STAPLING     14
# define WGET_SSL_OCSP_SERVER       15
# define WGET_SSL_OCSP              16
# define WGET_SSL_OCSP_CACHE        17
# define WGET_SSL_ALPN              18

void wget_ssl_init (void);
void wget_ssl_deinit (void);
void wget_ssl_set_config_string (int key, const char *value);
void wget_ssl_set_config_int (int key, int value);
//void *
//  wget_ssl_open(int sockfd, const char *hostname, int connect_timeout) G_GNUC_WGET_NONNULL((2));
int wget_ssl_open (wget_tcp_t * tcp);
void wget_ssl_close (void **session);
void wget_ssl_set_check_certificate (char value);

void wget_ssl_server_init (void);
void wget_ssl_server_deinit (void);
int wget_ssl_server_open (wget_tcp_t * tcp);
void wget_ssl_server_close (void **session);

ssize_t
wget_ssl_read_timeout (void *session, char *buf, size_t count, int timeout)
  G_GNUC_WGET_NONNULL_ALL;
ssize_t
wget_ssl_write_timeout (void *session, const char *buf, size_t count,
                        int timeout)
  G_GNUC_WGET_NONNULL_ALL;

/*
 * HTTP routines
 */

typedef struct
{
  const char *name;
  const char *value;
} wget_http_header_param_t;

typedef struct
{
  const char *uri;
  const char *type;
  int pri;
  enum
    {
      link_rel_describedby,
      link_rel_duplicate
    } rel;
} wget_http_link_t;

typedef struct
{
  const char *algorithm;
  const char *encoded_digest;
} wget_http_digest_t;

typedef struct
{
  const char *auth_scheme;
  wget_stringmap_t *params;
} wget_http_challenge_t;

enum
  {
    transfer_encoding_identity,
    transfer_encoding_chunked
  };

// keep the request as simple as possible
typedef struct
{
  wget_vector_t *headers;
  const char *scheme;
  void *nghttp2_context;  // needed for nghttp2 callbacks
  wget_buffer_t esc_resource;  // URI escaped resource
  wget_buffer_t esc_host;  // URI escaped host
  int32_t stream_id;  // HTTP2 stream id
  char esc_resource_buf[256];
  char esc_host_buf[64];
  char method[8];    // we just need HEAD, GET and POST
  char save_headers;
} wget_http_request_t;

// just parse the header lines that we need
typedef struct
{
  wget_vector_t *links;
  wget_vector_t *digests;
  wget_vector_t *cookies;
  wget_vector_t *challenges;
  const char *content_type;
  const char *content_type_encoding;
  const char *content_filename;
  const char *location;
  const char *etag;
  wget_buffer_t *header;
  wget_buffer_t *body;
  size_t content_length;
  time_t last_modified;
  time_t hsts_maxage;
  char hsts_include_subdomains;
  char hsts;    // if hsts_maxage and hsts_include_subdomains are valid
  char reason[32];
  int icy_metaint;
  short major;
  short minor;
  short code;    // request only status code
  char transfer_encoding;
  char content_encoding;
  char content_length_valid;
  char keep_alive;
} wget_http_response_t;

typedef struct
{
  wget_tcp_t *tcp;
  const char *esc_host;
  const char *port;
  const char *scheme;
  wget_buffer_t *buf;
# ifdef WITH_LIBNGHTTP2
  nghttp2_session *http2_session;
# endif
  char protocol;    // WGET_PROTOCOL_HTTP_1_1 or WGET_PROTOCOL_HTTP_2_0
  unsigned print_response_headers:1, abort_indicator:1;
} wget_http_connection_t;

int wget_http_isseperator (char c) G_GNUC_WGET_CONST;
int wget_http_istoken (char c) G_GNUC_WGET_CONST;

const char *wget_http_parse_token (const char *s,
                                   const char **token)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_quoted_string (const char *s,
                                           const char **qstring)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_param (const char *s, const char **param,
                                   const char **value)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_name (const char *s,
                                  const char **name)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_parse_name_fixed (const char *s, const char **name,
                                   size_t *
                                   namelen) G_GNUC_WGET_NONNULL_ALL;
time_t
wget_http_parse_full_date (const char *s)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_link (const char *s,
                                  wget_http_link_t *
                                  link) G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_digest (const char *s,
                                    wget_http_digest_t *
                                    digest) G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_challenge (const char *s,
                                       wget_http_challenge_t *
                                       challenge)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_challenges (const char *s,
                                        wget_vector_t *
                                        challenges)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_location (const char *s,
                                      const char **location)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_transfer_encoding (const char *s,
                                               char *transfer_encoding)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_content_type (const char *s,
                                          const char **content_type,
                                          const char **charset)
  G_GNUC_WGET_NONNULL ((1));
const char *wget_http_parse_content_encoding (const char *s,
                                              char *content_encoding)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_content_disposition (const char *s,
                                                 const char **filename)
  G_GNUC_WGET_NONNULL ((1));
const char *wget_http_parse_strict_transport_security (const char *s,
                                                       time_t * maxage,
                                                       char
                                                       *include_subdomains)
  G_GNUC_WGET_NONNULL ((1));
const char *wget_http_parse_connection (const char *s,
                                        char *keep_alive)
  G_GNUC_WGET_NONNULL_ALL;
const char *wget_http_parse_setcookie (const char *s,
                                       wget_cookie_t *
                                       cookie) G_GNUC_WGET_NONNULL ((1));
const char *wget_http_parse_etag (const char *s,
                                  const char **etag)
  G_GNUC_WGET_NONNULL ((1));

char *wget_http_print_date (time_t t, char *buf,
                            size_t bufsize) G_GNUC_WGET_NONNULL_ALL;

void
wget_http_add_param (wget_vector_t ** params,
                     wget_http_header_param_t *
                     param) G_GNUC_WGET_NONNULL_ALL;
void wget_http_add_header_vprintf (wget_http_request_t * req,
                                   const char *name, const char *fmt,
                                   va_list args)
  G_GNUC_WGET_PRINTF_FORMAT (3, 0) G_GNUC_WGET_NONNULL_ALL;
void wget_http_add_header_printf (wget_http_request_t * req,
                                  const char *name, const char *fmt,
                                  ...) G_GNUC_WGET_PRINTF_FORMAT (3,
                                                                  4)
  G_GNUC_WGET_NONNULL_ALL;
void wget_http_add_header (wget_http_request_t * req, const char *name,
                           const char *value) G_GNUC_WGET_NONNULL_ALL;
void wget_http_add_header_param (wget_http_request_t * req,
                                 wget_http_header_param_t *
                                 param) G_GNUC_WGET_NONNULL_ALL;
void wget_http_add_credentials (wget_http_request_t * req,
                                wget_http_challenge_t * challenge,
                                const char *username,
                                const char *password)
  G_GNUC_WGET_NONNULL ((1));
void wget_http_set_http_proxy (const char *proxy, const char *encoding);
void wget_http_set_https_proxy (const char *proxy, const char *encoding);
void wget_http_abort_connection (wget_http_connection_t * conn);

int wget_http_free_param (wget_http_header_param_t * param);
void wget_http_free_cookie (wget_cookie_t * cookie);
void wget_http_free_digest (wget_http_digest_t * digest);
void wget_http_free_challenge (wget_http_challenge_t * challenge);
void wget_http_free_link (wget_http_link_t * link);

void wget_http_free_cookies (wget_vector_t ** cookies);
void wget_http_free_digests (wget_vector_t ** digests);
void wget_http_free_challenges (wget_vector_t ** challenges);
void wget_http_free_links (wget_vector_t ** links);
//void
//  wget_http_free_header(HTTP_HEADER **header);
void wget_http_free_request (wget_http_request_t ** req);
void wget_http_free_response (wget_http_response_t ** resp);

wget_http_response_t *wget_http_read_header (const wget_iri_t *
                                             iri)
  G_GNUC_WGET_NONNULL_ALL;
wget_http_response_t *wget_http_get_header (wget_iri_t *
                                            iri) G_GNUC_WGET_NONNULL_ALL;
wget_http_response_t *wget_http_parse_response_header (char *buf)
  G_GNUC_WGET_NONNULL_ALL;
wget_http_response_t *wget_http_get_response_cb (wget_http_connection_t *
                                                 conn,
                                                 wget_http_request_t *
                                                 req, unsigned int flags,
                                                 int (*header_callback)
                                                 (void *context,
                                                  wget_http_response_t
                                                  *),
                                                 int (*body_callback)
                                                 (void *context,
                                                  const char *data,
                                                  size_t length),
                                                 void *context)
G_GNUC_WGET_NONNULL ((1, 5));
//HTTP_RESPONSE *
//  http_get_response_mem(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL_ALL,
wget_http_response_t *wget_http_get_response (wget_http_connection_t *
                                              conn,
                                              int (*header_callback)
                                              (void *,
                                               wget_http_response_t *),
                                              wget_http_request_t * req,
                                              unsigned int flags)
  G_GNUC_WGET_NONNULL ((1));
wget_http_response_t *wget_http_get_response_fd (wget_http_connection_t *
                                                 conn,
                                                 int (*header_callback)
                                                 (void *,
                                                  wget_http_response_t
                                                  *), int fd,
                                                 unsigned int flags)
  G_GNUC_WGET_NONNULL_ALL;
wget_http_response_t
*wget_http_get_response_stream (wget_http_connection_t * conn,
                                int (*header_callback) (void *,
                                                        wget_http_response_t
                                                        *),
                                FILE * stream,
                                unsigned int flags)
  G_GNUC_WGET_NONNULL_ALL;
wget_http_response_t *wget_http_get_response_func (wget_http_connection_t
                                                   * conn,
                                                   int (*header_callback)
                                                   (void *,
                                                    wget_http_response_t
                                                    *),
                                                   int (*body_callback)
                                                   (void *, const char *,
                                                    size_t),
                                                   void *context,
                                                   unsigned int flags)
G_GNUC_WGET_NONNULL ((1, 2));

int
wget_http_open (wget_http_connection_t ** _conn,
                const wget_iri_t * iri);
wget_http_request_t *wget_http_create_request (const wget_iri_t * iri,
                                               const char *method)
  G_GNUC_WGET_NONNULL_ALL;
void wget_http_close (wget_http_connection_t **
                      conn) G_GNUC_WGET_NONNULL_ALL;
int wget_http_send_request (wget_http_connection_t * conn,
                            wget_http_request_t *
                            req) G_GNUC_WGET_NONNULL_ALL;
int wget_http_send_request_with_body (wget_http_connection_t * conn,
                                      wget_http_request_t * req,
                                      const void *body,
                                      size_t length)
  G_GNUC_WGET_NONNULL ((1, 2));
ssize_t
wget_http_request_to_buffer (wget_http_request_t * req, wget_buffer_t * buf)
  G_GNUC_WGET_NONNULL_ALL;

/*
 * Highlevel HTTP routines
 */

wget_http_response_t *wget_http_get (int first_key,
                                     ...) G_GNUC_WGET_NULL_TERMINATED;
wget_vector_t * wget_get_css_urls (const char *data);

/*
 * MD5 routines
 */

void
wget_md5_printf_hex (char *digest_hex, const char *fmt, ...)
  G_GNUC_WGET_PRINTF_FORMAT (2, 3)
  G_GNUC_WGET_NONNULL_ALL;

/*
 * Hash / digest routines
 */

typedef struct _wget_hash_hd_st
wget_hash_hd_t;

/**
 * wget_digest_algorithm_t:
 * @WGET_DIGTYPE_UNKNOWN: Unknown hash algorithm.
 * @WGET_DIGTYPE_MD5: MD5 algorithm.
 * @WGET_DIGTYPE_SHA1: SHA-1 algorithm.
 * @WGET_DIGTYPE_RMD160: RMD160 algorithm.
 * @WGET_DIGTYPE_MD2: MD2 algorithm.
 * @WGET_DIGTYPE_SHA256: SHA-256 algorithm.
 * @WGET_DIGTYPE_SHA384: SHA-384 algorithm.
 * @WGET_DIGTYPE_SHA512: SHA-512 algorithm.
 * @WGET_DIGTYPE_SHA224: SHA-224 algorithm.
 *
 * Enumeration of different hash digest algorithms.
 */
typedef enum
  {
    WGET_DIGTYPE_UNKNOWN,
    WGET_DIGTYPE_MD5,
    WGET_DIGTYPE_SHA1,
    WGET_DIGTYPE_RMD160,
    WGET_DIGTYPE_MD2,
    WGET_DIGTYPE_SHA256,
    WGET_DIGTYPE_SHA384,
    WGET_DIGTYPE_SHA512,
    WGET_DIGTYPE_SHA224
  } wget_digest_algorithm_t;

wget_digest_algorithm_t
wget_hash_get_algorithm (const char *name);
int
wget_hash_fast (wget_digest_algorithm_t algorithm, const void *text,
                size_t textlen, void *digest);
int wget_hash_get_len (wget_digest_algorithm_t algorithm);
int
wget_hash_init (wget_hash_hd_t * dig,
                wget_digest_algorithm_t algorithm);
int wget_hash (wget_hash_hd_t * handle, const void *text,
               size_t textlen);
void wget_hash_deinit (wget_hash_hd_t * handle, void *digest);

/*
 * Hash file routines
 */

int
wget_hash_file_fd (const char *type, int fd, char *digest_hex,
                   size_t digest_hex_size, off_t offset,
                   off_t length) G_GNUC_WGET_NONNULL_ALL,
  wget_hash_file_offset (const char *type, const char *fname,
                         char *digest_hex, size_t digest_hex_size,
                         off_t offset, off_t length) G_GNUC_WGET_NONNULL_ALL,
  wget_hash_file (const char *type, const char *fname, char *digest_hex,
                  size_t digest_hex_size) G_GNUC_WGET_NONNULL_ALL;

/*
 * Metalink types and routines
 */

typedef struct
{
  wget_iri_t * iri;
  int priority;
  char location[8];  // location of the mirror, e.g. 'de', 'fr' or 'jp'
} wget_metalink_mirror_t;

typedef struct
{
  char type[16],    // type of hash, e.g. 'MD5' or 'SHA-256'
    hash_hex[128 + 1];  // hash value as HEX string
} wget_metalink_hash_t;

// Metalink piece, for checksumming after download
typedef struct
{
  wget_metalink_hash_t hash;
  off_t position;
  off_t length;
} wget_metalink_piece_t;

typedef struct
{
  const char *name;
  wget_vector_t * mirrors, *hashes,  // checksums of complete file
    *pieces;    // checksums of smaller pieces of the file
  off_t size;    // total size of the file
} wget_metalink_t;

wget_metalink_t * metalink3_parse (const char *xml)
  G_GNUC_WGET_NONNULL ((1)), *
  metalink4_parse (const char *xml)
  G_GNUC_WGET_NONNULL ((1));
void
wget_metalink_free (wget_metalink_t ** metalink),
  wget_metalink_sort_mirrors (wget_metalink_t * metalink);

/*
 * Robots types and routines
 */

typedef struct
{
  const char *path;
  size_t len;
} ROBOTS_PATH;

typedef struct ROBOTS
{
  wget_vector_t * paths;
  wget_vector_t * sitemaps;
} ROBOTS;

ROBOTS *wget_robots_parse (const char *data);
void wget_robots_free (ROBOTS ** robots);

/*
 * Progress bar routines
 */

typedef struct _wget_bar_st wget_bar_t;

wget_bar_t *wget_bar_init (wget_bar_t * bar, int nslots, int max_width);
void wget_bar_deinit (wget_bar_t * bar);
void wget_bar_free (wget_bar_t ** bar);
void
wget_bar_update (const wget_bar_t * bar, int slotpos, int max,
                 int cur);
void wget_bar_print (wget_bar_t * bar, int slotpos, const char *s);
ssize_t
wget_bar_vprintf (wget_bar_t * bar, int slotpos, const char *fmt,
                  va_list args)
  G_GNUC_WGET_PRINTF_FORMAT (3, 0)
  G_GNUC_WGET_NONNULL_ALL;
ssize_t
wget_bar_printf (wget_bar_t * bar, int slotpos, const char *fmt, ...)
  G_GNUC_WGET_PRINTF_FORMAT (3, 4)
  G_GNUC_WGET_NONNULL_ALL;


WGET_END_DECLS
#endif /* _LIBWGET_LIBWGET_H */
