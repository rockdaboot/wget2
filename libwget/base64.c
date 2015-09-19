/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * base64 conversion routines
 *
 * Changelog
 * 21.12.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

#include <libwget.h>
#include "private.h"


static const unsigned char base64_2_bin[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0,
	0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static int G_GNUC_WGET_CONST _isbase64(char c)
{
	// isalnum(c) does not work for all locales
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

int wget_base64_is_string(const char *src)
{
	if (src) {
		while (_isbase64(*src)) src++;

		if (!*src || (*src == '=' && src[1]) || (*src == '=' && src[1] == '=' && src[2]))
			return 1;
	}

	return 0;
}

// dst size must be at least ((n+3)/4)*3+1 bytes
size_t wget_base64_decode(char *dst, const char *src, int n)
{
	const unsigned char *usrc = (const unsigned char *)src;
	char *old = dst;
	int extra;

	// trim '=' at the end
	while (n > 0 && !_isbase64(usrc[n - 1]))
		n--;

	extra = n & 3;

	for (n /= 4; --n >= 0; usrc += 4) {
		*dst++ = base64_2_bin[usrc[0]] << 2 | base64_2_bin[usrc[1]] >> 4;
		*dst++ = (base64_2_bin[usrc[1]]&0x0F) << 4 | base64_2_bin[usrc[2]] >> 2;
		*dst++ = (base64_2_bin[usrc[2]]&0x03) << 6 | base64_2_bin[usrc[3]];
	}

	switch (extra) {
	case 1:
		// this should not happen
		*dst++ = base64_2_bin[usrc[0]] << 2;
		break;
	case 2:
		*dst++ = base64_2_bin[usrc[0]] << 2 | base64_2_bin[usrc[1]] >> 4;
		*dst = (base64_2_bin[usrc[1]]&0x0F) << 4;
		if (*dst) dst++;
		break;
	case 3:
		*dst++ = base64_2_bin[usrc[0]] << 2 | base64_2_bin[usrc[1]] >> 4;
		*dst++ = (base64_2_bin[usrc[1]]&0x0F) << 4 | base64_2_bin[usrc[2]] >> 2;
		*dst = (base64_2_bin[usrc[2]]&0x03) << 6;
		if (*dst) dst++;
		break;
	}

	*dst = 0;
	return (size_t) (dst - old);
}

char *wget_base64_decode_alloc(const char *src, int n)
{
	char *dst = xmalloc(((n + 3) / 4) * 3 + 1);

	wget_base64_decode(dst, src, n);

	return dst;
}

// dst size must be at least ((n+2)/3)*4+1 bytes
size_t wget_base64_encode(char *dst, const char *src, int n)
{
	static const char base64[64] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	const unsigned char *usrc = (const unsigned char *)src;
	char *start = dst;
	int extra = n % 3;

	// convert line by line
	for (n /= 3; --n >= 0; usrc += 3) {
		*dst++ = base64[usrc[0] >> 2];
		*dst++ = base64[((usrc[0]&3) << 4) | (usrc[1] >> 4)];
		*dst++ = base64[((usrc[1]&15) << 2) | (usrc[2] >> 6)];
		*dst++ = base64[usrc[2]&0x3f];
	}

	// special case
	switch (extra) {
	case 1:
		*dst++ = base64[usrc[0] >> 2];
		*dst++ = base64[(usrc[0]&3) << 4];
		*dst++ = '=';
		*dst++ = '=';
		break;
	case 2:
		*dst++ = base64[usrc[0] >> 2];
		*dst++ = base64[((usrc[0]&3) << 4) | (usrc[1] >> 4)];
		*dst++ = base64[((usrc[1]&15) << 2)];
		*dst++ = '=';
	}

	*dst = 0;

	return (size_t) (dst - start);
}

char *wget_base64_encode_alloc(const char *src, int n)
{
	char *dst = xmalloc(((n + 2) / 3) * 4 + 1);

	wget_base64_encode(dst, src, n);

	return dst;
}

char *wget_base64_encode_vprintf_alloc(const char *fmt, va_list args)
{
	char *data = NULL;
	int n;

	n = vasprintf(&data, fmt, args);

	if (data) {
		char *dst = wget_base64_encode_alloc(data, n);
		xfree(data);
		return dst;
	}

	return NULL;
}

char *wget_base64_encode_printf_alloc(const char *fmt, ...)
{
	char *dst;
	va_list args;

	va_start(args, fmt);
	dst = wget_base64_encode_vprintf_alloc(fmt, args);
	va_end(args);

	return dst;
}
