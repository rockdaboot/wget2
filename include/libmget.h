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
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

// transitional defines, remove when migration to libmget is done
#define xmalloc mget_malloc
#define xcalloc mget_calloc
#define xrealloc mget_realloc


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

// Let C++ include C headers
#ifdef  __cplusplus
# define MGET_BEGIN_DECLS  extern "C" {
# define MGET_END_DECLS    }
#else
# define MGET_BEGIN_DECLS
# define MGET_END_DECLS
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

// we can prefix the exposed functions as we want
#ifndef _MGET_PREFIX
#	define _MGET_PREFIX mget_
#endif

MGET_BEGIN_DECLS

/*
 * Utility functions
 */

/**
 * MGET_UTILITY:
 *
 * General utility functions
 */

int
	mget_strcmp(const char *s1, const char *s2) G_GNUC_MGET_PURE;
int
	mget_strcasecmp(const char *s1, const char *s2) G_GNUC_MGET_PURE;
void
   mget_memtohex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_fdgetline(char **buf, size_t *bufsize, int fd) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_getline(char **buf, size_t *bufsize, FILE *fp) G_GNUC_MGET_NONNULL_ALL;
FILE *
	mget_vpopenf(const char *type, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL((1,2));
FILE *
	mget_popenf(const char *type, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL((1,2));
FILE *
	popen2f(FILE **fpin, FILE **fpout, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL((3));
pid_t
	mget_fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv);
pid_t
	mget_popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv);
size_t
	vbsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, va_list) G_GNUC_MGET_PRINTF_FORMAT(3,0);
size_t
	bsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4);

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
#	define strdup(s) strndup((s), strlen(s));
#endif

#ifndef HAVE_STRLCPY
size_t
	strlcpy(char *restrict dst, const char *restrict src, size_t size) G_GNUC_MGET_NONNULL_ALL;
#endif

#ifndef HAVE_VASPRINTF
int
	vasprintf(char **restrict buf, const char *restrict fmt, va_list) G_GNUC_MGET_PRINTF_FORMAT(2,0);
int
	asprintf(char **restrict buf, const char *restrict fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3);
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
	mget_set_oomfunc(G_GNUC_MGET_NORETURN void (*oom_func)(void));

/*
 * String/Memory routines, slightly different than standard functions
 */

void *
	mget_memdup(const void *s, size_t n) G_GNUC_MGET_MALLOC G_GNUC_MGET_ALLOC_SIZE(2);
char *
	mget_strdup(const char *s) G_GNUC_MGET_MALLOC;

/*
 * Base64 routines
 */

int
	mget_base64_is_string(const char *src);
int
	mget_base64_decode(char *restrict dst, const char *restrict src, int n) G_GNUC_MGET_NONNULL_ALL;
int
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
	char
		*data; // pointer to internal memory
	size_t
		length; // number of bytes in 'data'
	size_t
		size; // capacity of 'data' (terminating 0 byte doesn't count here)
	unsigned int
		release_data : 1, // 'data' has been malloc'ed and must be freed
		release_buf : 1; // buffer_t structure has been malloc'ed and must be freed
} mget_buffer_t;

mget_buffer_t *
	mget_buffer_init(mget_buffer_t *buf, char *data, size_t size);
mget_buffer_t *
	mget_buffer_alloc(size_t size);
void
	mget_buffer_ensure_capacity(mget_buffer_t *buf, size_t size) G_GNUC_MGET_NONNULL((1));
void
	mget_buffer_deinit(mget_buffer_t *buf) G_GNUC_MGET_NONNULL((1));
void
	mget_buffer_free(mget_buffer_t **buf) G_GNUC_MGET_NONNULL((1));
void
	mget_buffer_free_data(mget_buffer_t *buf) G_GNUC_MGET_NONNULL((1));
void
	mget_buffer_realloc(mget_buffer_t *buf, size_t size) G_GNUC_MGET_NONNULL((1));
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

typedef struct _MGET_LOGGER MGET_LOGGER;

void
	mget_logger_set_func(MGET_LOGGER *logger, void (*func)(const char *buf, size_t len) G_GNUC_MGET_NONNULL_ALL);
void
	mget_logger_set_file(MGET_LOGGER *logger, FILE *fp);
void
	mget_logger_set_filename(MGET_LOGGER *logger, const char *fname);

/*
 * Logging routines
 */

#define MGET_LOGGER_INFO   1
#define MGET_LOGGER_ERROR  2
#define MGET_LOGGER_DEBUG  3

void
	mget_info_vprintf(const char *fmt, va_list args) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,0);
void
	mget_info_printf(const char *fmt, ...) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_error_vprintf(const char *fmt, va_list args) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,0);
void
	mget_error_printf(const char *fmt, ...) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_error_printf_exit(const char *fmt, ...) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_NORETURN G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_debug_vprintf(const char *fmt, va_list args) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,0);
void
	mget_debug_printf(const char *fmt, ...) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(1,2);
void
	mget_debug_write(const char *buf, int len) G_GNUC_MGET_NONNULL_ALL;
MGET_LOGGER *
	mget_get_logger(int id);

/*
 * Vector datatype routines
 */

typedef struct _MGET_VECTOR VECTOR;

VECTOR *
	mget_vector_create(int max, int off, int (*cmp)(const void *, const void *)) G_GNUC_MGET_MALLOC;
int
	mget_vector_find(const VECTOR *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_findext(const VECTOR *v, int start, int direction, int (*find)(void *)) G_GNUC_MGET_NONNULL((4));
int
	mget_vector_insert(VECTOR *v, const void *elem, size_t size, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert_noalloc(VECTOR *v, const void *elem, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert_sorted(VECTOR *v, const void *elem, size_t size) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_insert_sorted_noalloc(VECTOR *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add(VECTOR *v, const void *elem, size_t size) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_noalloc(VECTOR *v, const void *elem) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_str(VECTOR *v, const char *s) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_vprintf(VECTOR *v, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_add_printf(VECTOR *v, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_replace(VECTOR *v, const void *elem, size_t size, int pos) G_GNUC_MGET_NONNULL((2));
int
	mget_vector_move(VECTOR *v, int old_pos, int new_pos);
int
	mget_vector_swap(VECTOR *v, int pos1, int pos2);
int
	mget_vector_remove(VECTOR *v, int pos);
int
	mget_vector_remove_nofree(VECTOR *v, int pos);
int
	mget_vector_size(const VECTOR *v);
int
	mget_vector_browse(const VECTOR *v, int (*browse)(void *elem)) G_GNUC_MGET_NONNULL((2));
void
	mget_vector_free(VECTOR **v);
void
	mget_vector_clear(VECTOR *v);
void
	mget_vector_clear_nofree(VECTOR *v);
void *
	mget_vector_get(const VECTOR *v, int pos);
void
	mget_vector_setcmpfunc(VECTOR *v, int (*cmp)(const void *elem1, const void *elem2)) G_GNUC_MGET_NONNULL((2));
void
	mget_vector_sort(VECTOR *v);

/*
 * Hashmap datatype routines
 */

typedef struct _MGET_HASHMAP MGET_HASHMAP;

MGET_HASHMAP
	*mget_hashmap_create(int max, int off, unsigned int (*hash)(const void *), int (*cmp)(const void *, const void *)) G_GNUC_MGET_MALLOC;
int
	mget_hashmap_put(MGET_HASHMAP *h, const void *key, size_t keysize, const void *value, size_t valuesize);
int
	mget_hashmap_put_noalloc(MGET_HASHMAP *h, const void *key, const void *value);
int
	mget_hashmap_put_ident(MGET_HASHMAP *h, const void *key, size_t keysize);
int
	mget_hashmap_put_ident_noalloc(MGET_HASHMAP *h, const void *key);
int
	mget_hashmap_size(const MGET_HASHMAP *h);
int
	mget_hashmap_browse(const MGET_HASHMAP *h, int (*browse)(const void *key, const void *value)) G_GNUC_MGET_NONNULL((2));
void
	mget_hashmap_free(MGET_HASHMAP **h);
void
	mget_hashmap_clear(MGET_HASHMAP *h);
void *
	mget_hashmap_get(const MGET_HASHMAP *h, const void *key);
void
	mget_hashmap_remove(MGET_HASHMAP *h, const void *key);
void
	mget_hashmap_remove_nofree(MGET_HASHMAP *h, const void *key);
void
	mget_hashmap_setcmpfunc(MGET_HASHMAP *h, int (*cmp)(const void *key1, const void *key2)) G_GNUC_MGET_NONNULL_ALL;
void
	mget_hashmap_sethashfunc(MGET_HASHMAP *h, unsigned int (*hash)(const void *key)) G_GNUC_MGET_NONNULL_ALL;
void
	mget_hashmap_setloadfactor(MGET_HASHMAP *h, float factor) G_GNUC_MGET_NONNULL_ALL;

/*
 * Hashmap datatype routines
 */

typedef struct _MGET_STRINGMAP MGET_STRINGMAP;

MGET_STRINGMAP *
	mget_stringmap_create(int max) G_GNUC_MGET_MALLOC;
MGET_STRINGMAP *
	mget_stringmap_create_nocase(int max) G_GNUC_MGET_MALLOC;
int
	mget_stringmap_put(MGET_STRINGMAP *h, const char *key, const void *value, size_t valuesize);
int
	mget_stringmap_put_noalloc(MGET_STRINGMAP *h, const char *key, const void *value);
int
	mget_stringmap_put_ident(MGET_STRINGMAP *h, const char *key);
int
	mget_stringmap_put_ident_noalloc(MGET_STRINGMAP *h, const char *key);
int
	mget_stringmap_size(const MGET_STRINGMAP *h);
int
	mget_stringmap_browse(const MGET_STRINGMAP *h, int (*browse)(const char *key, const void *value)) G_GNUC_MGET_NONNULL((2));
void
	mget_stringmap_free(MGET_STRINGMAP **h);
void
	mget_stringmap_clear(MGET_STRINGMAP *h);
void *
	mget_stringmap_get(const MGET_STRINGMAP *h, const char *key);
void
	mget_stringmap_remove(MGET_STRINGMAP *h, const char *key);
void
	mget_stringmap_remove_nofree(MGET_STRINGMAP *h, const char *key);
void
	mget_stringmap_setcmpfunc(MGET_STRINGMAP *h, int (*cmp)(const char *key1, const char *key2)) G_GNUC_MGET_NONNULL_ALL;
void
	mget_stringmap_sethashfunc(MGET_STRINGMAP *h, unsigned int (*hash)(const char *key)) G_GNUC_MGET_NONNULL_ALL;
void
	mget_stringmap_setloadfactor(MGET_STRINGMAP *h, float factor) G_GNUC_MGET_NONNULL_ALL;

/*
 * Decompressor routines
 */

typedef struct _MGET_DECOMPRESSOR MGET_DECOMPRESSOR;

enum {
	mget_content_encoding_identity,
	mget_content_encoding_gzip,
	mget_content_encoding_deflate
};

MGET_DECOMPRESSOR *
	mget_decompress_open(int encoding,
						 int (*put_data)(void *context, const char *data, size_t length),
						 void *context);
void
	mget_decompress_close(MGET_DECOMPRESSOR *dc);
int
	mget_decompress(MGET_DECOMPRESSOR *dc, char *src, size_t srclen);

/*
 * URI/IRI routines
 */

// TODO: i have to move this away from libmget.h
extern const char * const
	iri_schemes[];

#define IRI_SCHEME_HTTP    (iri_schemes[0])
#define IRI_SCHEME_HTTPS   (iri_schemes[1])
#define IRI_SCHEME_FTP     (iri_schemes[2])
#define IRI_SCHEME_DEFAULT IRI_SCHEME_HTTP

typedef struct {
	const char
		*uri,      // pointer to original URI string
		*display,
		*scheme,
		*userinfo,
		*password,
		*host, // unescaped, toASCII converted, lowercase
		*port,
		*resolv_port,
		*path, // unescaped
		*query, // unescaped
		*fragment, // unescaped
		*connection_part; // helper, e.g. http://www.example.com:8080
	char
		host_allocated; // if set, free host in iri_free()
} MGET_IRI;

void
	mget_iri_test(void);
void
	mget_iri_free(MGET_IRI **iri);
void
	mget_iri_free_content(MGET_IRI *iri);
void
	mget_iri_set_defaultpage(const char *page);
int
	mget_iri_supported(const MGET_IRI *iri) G_GNUC_MGET_PURE G_GNUC_MGET_NONNULL_ALL;
int
	mget_iri_isgendelim(char c) G_GNUC_MGET_CONST;
int
	mget_iri_issubdelim(char c) G_GNUC_MGET_CONST;
int
	mget_iri_isreserved(char c) G_GNUC_MGET_CONST;
int
	mget_iri_isunreserved(char c) G_GNUC_MGET_CONST;
int
	mget_iri_isunreserved_path(char c) G_GNUC_MGET_CONST;
int
	mget_iri_compare(MGET_IRI *iri1, MGET_IRI *iri2) G_GNUC_MGET_PURE G_GNUC_MGET_NONNULL_ALL;
MGET_IRI *
	mget_iri_parse(const char *uri, const char *encoding) G_GNUC_MGET_MALLOC;
const char *
	mget_iri_get_connection_part(MGET_IRI *iri);
const char *
	mget_iri_relative_to_abs(MGET_IRI *base, const char *val, size_t len, mget_buffer_t *buf);
const char *
	mget_iri_escape(const char *src, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_escape_path(const char *src, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_escape_query(const char *src, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_host(const MGET_IRI *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_resource(const MGET_IRI *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_path(const MGET_IRI *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_query(const MGET_IRI *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_fragment(const MGET_IRI *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
const char *
	mget_iri_get_escaped_file(const MGET_IRI *iri, mget_buffer_t *buf) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_str_to_utf8(const char *src, const char *encoding) G_GNUC_MGET_MALLOC;

/*
 * Cookie routines
 */

typedef struct {
	const char
		*name,
		*value,
		*domain,
		*path;
	time_t
		expires, // time of expiration (format YYYYMMDDHHMMSS)
		maxage, // like expires, but precedes it if set
		last_access,
		creation;
	unsigned int
		domain_dot : 1, // for compatibility with Netscape cookie format
		normalized : 1,
		persistent : 1,
		host_only : 1,
		secure_only : 1, // cookie should be used over secure connections only (TLS/HTTPS)
		http_only : 1; // just use the cookie via HTTP/HTTPS protocol
} MGET_COOKIE;

void
	mget_cookie_init_cookie(MGET_COOKIE *cookie) G_GNUC_MGET_NONNULL_ALL;
void
	mget_cookie_free_cookies(void);
void
	mget_cookie_normalize_cookies(const MGET_IRI *iri, const VECTOR *cookies) G_GNUC_MGET_NONNULL((1));
void
	mget_cookie_store_cookie(MGET_COOKIE *cookie) G_GNUC_MGET_NONNULL_ALL;
void
	mget_cookie_store_cookies(VECTOR *cookies) G_GNUC_MGET_NONNULL((1));
void
	mget_cookie_free_public_suffixes(void);
int
	mget_cookie_free_cookie(MGET_COOKIE *cookie) G_GNUC_MGET_NONNULL_ALL;
int
	mget_cookie_normalize_cookie(const MGET_IRI *iri, MGET_COOKIE *cookie) G_GNUC_MGET_NONNULL((2));
int
	mget_cookie_save(const char *fname, int keep_session_cookies) G_GNUC_MGET_NONNULL_ALL;
int
	mget_cookie_load(const char *fname, int keep_session_cookies) G_GNUC_MGET_NONNULL_ALL;
int
	mget_cookie_load_public_suffixes(const char *fname) G_GNUC_MGET_NONNULL_ALL;
int
	mget_cookie_suffix_match(const char *domain) G_GNUC_MGET_NONNULL_ALL;
char *
	mget_cookie_create_request_header(const MGET_IRI *iri) G_GNUC_MGET_NONNULL_ALL;

/*
 * CSS parsing routines
 */

void
	mget_css_parse_buffer(
		const char *buf,
		void(*callback_uri)(void *user_ctx, const char *url, size_t len),
		void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
		void *user_ctx),
	mget_css_parse_file(
		const char *fname,
		void(*callback_uri)(void *user_ctx, const char *url, size_t len),
		void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
		void *user_ctx);

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

void
	mget_xml_parse_buffer(
		const char *buf,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1)),
	mget_xml_parse_file(
		const char *fname,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1)),
	mget_html_parse_buffer(
		const char *buf,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1)),
	mget_html_parse_file(
		const char *fname,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) G_GNUC_MGET_NONNULL((1));

MGET_END_DECLS

#endif /* _LIBMGET_LIBMGET_H */
