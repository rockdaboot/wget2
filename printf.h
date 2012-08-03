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
 * Header file for logging routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_PRINTF_H
#define _MGET_PRINTF_H

#include <stddef.h>
#include <stdarg.h>

#include "mget.h"

int
	vasprintf(char **restrict buf, const char *restrict fmt, va_list),
	asprintf(char **restrict buf, const char *restrict fmt, ...) PRINTF_FORMAT(2,3),
	vdprintf(int fd, const char *restrict fmt, va_list),
	dprintf(int fd, const char *restrict fmt, ...) PRINTF_FORMAT(2,3);
size_t
	vbsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, va_list),
	bsprintf(char **restrict buf, size_t *restrict bufsize, const char *restrict fmt, ...) PRINTF_FORMAT(3,4);

#endif /* _MGET_PRINTF_H */
