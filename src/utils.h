/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for utility routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 31.05.2012               added popen3() and fd_popen3()
 *
 */

#ifndef _MGET_UTILS_H
#define _MGET_UTILS_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h> // for free()
#include <stdarg.h>
#include <unistd.h>

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)
#define countof(a) (sizeof(a)/sizeof(*(a)))

void
   buffer_to_hex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size) G_GNUC_MGET_NONNULL_ALL;
size_t
	strlcpy(char *restrict dst, const char *restrict src, size_t size) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	fdgetline0(char **buf, size_t *bufsize, int fd) G_GNUC_MGET_NONNULL_ALL,
	getline(char **buf, size_t *bufsize, FILE *fp) G_GNUC_MGET_NONNULL_ALL;
FILE
	*vpopenf(const char *type, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL((1,2)),
	*popenf(const char *type, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL((1,2)),
	*popen2f(FILE **fpin, FILE **fpout, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL((3));
pid_t
	fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv),
	popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv);
int
	null_strcmp(const char *s1, const char *s2) G_GNUC_MGET_PURE,
	null_strcasecmp(const char *s1, const char *s2) G_GNUC_MGET_PURE;

#ifndef HAVE_STRNDUP
char *
	strndup(const char *s, size_t n) G_GNUC_MGET_MALLOC G_GNUC_MGET_NONNULL_ALL;
#endif

#ifndef HAVE_STRDUP
# define strdup(s) strndup((s), strlen(s));
#endif

#endif /* _MGET_UTILS_H */
