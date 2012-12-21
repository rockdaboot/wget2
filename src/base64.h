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
 * Header file for base64 conversion routines
 *
 * Changelog
 * 21.12.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_BASE64_H
#define _MGET_BASE64_H

#include <stddef.h>

#include "mget.h"

int
	mget_base64_is_string(const char *src),
	mget_base64_decode(char *restrict dst, const char *restrict src, int n) NONNULL_ALL,
	mget_base64_encode(char *restrict dst, const char *restrict src, int n) NONNULL_ALL;
char
	*mget_base64_decode_alloc(const char *restrict src, int n) NONNULL_ALL,
	*mget_base64_encode_alloc(const char *restrict src, int n) NONNULL_ALL,
	*mget_base64_encode_vprintf_alloc(const char *restrict fmt, va_list args) PRINTF_FORMAT(1,0) NONNULL_ALL,
	*mget_base64_encode_printf_alloc(const char *restrict fmt, ...) PRINTF_FORMAT(1,2) NONNULL_ALL;

#endif /* _MGET_BASE64_H */
