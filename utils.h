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
 *
 */

#ifndef _MGET_UTILS_H
#define _MGET_UTILS_H

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "mget.h"

#define countof(a) (sizeof(a)/sizeof(*(a)))

void
   buffer_to_hex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size);
char
	*strndup(const char *s, size_t n);
size_t
	strlcpy(char *dst, const char *src, size_t size);
ssize_t
	fdgetline0(char **buf, size_t *bufsize, int fd),
	getline(char **buf, size_t *bufsize, FILE *fp);
FILE
	*vpopenf(const char *type, const char *fmt, va_list args) PRINTF_FORMAT(2,0),
	*popenf(const char *type, const char *fmt, ...) PRINTF_FORMAT(2,3),
	*popen2f(FILE **fpin, FILE **fpout, const char *fmt, ...) PRINTF_FORMAT(3,4);
pid_t
	fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv),
	popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv);

#endif /* _MGET_UTILS_H */
