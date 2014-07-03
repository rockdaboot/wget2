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
 * a collection of utility routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include <libmget.h>
#include "private.h"

/**
 * SECTION:libmget-utils
 * @short_description: General utility functions
 * @title: libmget-utils
 * @stability: stable
 * @include: libmget.h
 *
 * This is a collections of short routines that are used with libmget and/or Mget code.
 * They may be useful to other developers that is why they are exported.
 */

/**
 * mget_strcmp:
 * @s1: String
 * @s2: String
 *
 * This functions compares @s1 and @s2 in the same way as strcmp() does,
 * except that it also handles %NULL values. It returns 0 if both @s1 and @s2
 * are %NULL. It returns -1 if @s1 is %NULL and @s2 is not %NULL. It returns 1 if
 * @s2 is %NULL and @s1 is not %NULL.
 *
 * Returns: Same as strcmp() if none of @s1 or @s2 is %NULL. Else see above.
 */
int mget_strcmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcmp(s1, s2);
	}
}

/**
 * mget_strcasecmp:
 * @s1: String
 * @s2: String
 *
 * This functions compares @s1 and @s2 in the same way as strcasecmp() does,
 * except that it also handles %NULL values. It returns 0 if both @s1 and @s2
 * are %NULL. It returns -1 if @s1 is %NULL and @s2 is not %NULL. It returns 1 if
 * @s2 is %NULL and @s1 is not %NULL.
 *
 * Returns: Same as strcasecmp() if none of @s1 or @s2 is %NULL. Else see above.
 */
int mget_strcasecmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcasecmp(s1, s2);
	}
}

/**
 * mget_strncmp:
 * @s1: String
 * @s2: String
 * @n: Max. number of chars to compare
 *
 * This functions compares @s1 and @s2 in the same way as strncmp() does,
 * except that it also handles %NULL values. It returns 0 if both @s1 and @s2
 * are %NULL. It returns -1 if @s1 is %NULL and @s2 is not %NULL. It returns 1 if
 * @s2 is %NULL and @s1 is not %NULL.
 *
 * Returns: Same as strncmp() if none of @s1 or @s2 is %NULL. Else see above.
 */
int mget_strncmp(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strncmp(s1, s2, n);
	}
}

/**
 * mget_strncasecmp:
 * @s1: String
 * @s2: String
 * @n: Max. number of chars to compare
 *
 * This functions compares @s1 and @s2 in the same way as strncasecmp() does,
 * except that it also handles %NULL values. It returns 0 if both @s1 and @s2
 * are %NULL. It returns -1 if @s1 is %NULL and @s2 is not %NULL. It returns 1 if
 * @s2 is %NULL and @s1 is not %NULL.
 *
 * Returns: Same as strncasecmp() if none of @s1 or @s2 is %NULL. Else see above.
 */

int mget_strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strncasecmp(s1, s2, n);
	}
}

/**
 * mget_memtohex:
 * @src: Pointer to bytes to encode
 * @src_len: Number of bytes to encode
 * @dst: Buffer to hold the encoded string
 * @dst_size: Size in bytes of @dst
 *
 * Encodes a number of bytes into a lowercase hexadecimal string.
 */
void mget_memtohex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size)
{
	size_t it;
	int adjust = 0, c;

	if (dst_size == 0)
		return;

	if (src_len * 2 >= dst_size) {
		src_len = (dst_size - 1) / 2;
		adjust = 1;
	}

	for (it = 0; it < src_len; it++, src++) {
		*dst++ = (c = (*src >> 4)) >= 10 ? c + 'a' - 10 : c + '0';
		*dst++ = (c = (*src & 0xf)) >= 10 ? c + 'a' - 10 : c + '0';
	}
	if (adjust && (dst_size & 1) == 0)
		*dst++ = (c = (*src >> 4)) >= 10 ? c + 'a' - 10 : c + '0';

	*dst = 0;
}

/**
 * mget_millisleep:
 * @ms: Number of milliseconds to sleep
 *
 * Pause for @ms milliseconds.
 */
void mget_millisleep(int ms)
{
	if (ms <= 0)
		return;

#ifdef HAVE_NANOSLEEP
	nanosleep(&(struct timespec){ .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000 }, NULL);
#elif defined HAVE_USLEEP
	usleep(ms); // obsoleted by POSIX.1-2001, use nanosleep instead
#else
	sleep((ms + 500) / 1000);
#endif
}

static inline unsigned char G_GNUC_MGET_CONST _unhex(unsigned char c)
{
	return c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
}

/**
 * mget_percent_unescape:
 * @src: String to unescape
 *
 * Does an inline percent unescape.
 * Each occurrence of %xx (x = hex digit) will converted into it's byte representation.
 *
 * Returns: 0 if the string did not change, 1 if unescaping took place.
 */
int mget_percent_unescape(unsigned char *src)
{
	int ret = 0;
	unsigned char *dst = src;

	while (*src) {
		if (*src == '%') {
			if (isxdigit(src[1]) && isxdigit(src[2])) {
				*dst++ = (_unhex(src[1]) << 4) | _unhex(src[2]);
				src += 3;
				ret = 1;
				continue;
			}
		}

		*dst++ = *src++;
	}
	*dst = 0;

	return ret;
}

/**
 * mget_match_tail:
 * @s: String
 * @tail: String
 *
 * Checks if @tail matches the end of the string @s.
 *
 * Returns: 1 if @tail matches the end of @s, 0 if not.
 */
int mget_match_tail(const char *s, const char *tail)
{
	const char *p = s + strlen(s) - strlen(tail);

	return p >= s && !strcmp(p, tail);
}

/**
 * mget_match_tail_nocase:
 * @s: String
 * @tail: String
 *
 * Checks if @tail matches the end of the string @s, disregarding the case.
 *
 * Returns: 1 if @tail matches the end of @s, 0 if not.
 */
int mget_match_tail_nocase(const char *s, const char *tail)
{
	const char *p = s + strlen(s) - strlen(tail);

	return p >= s && !strcasecmp(p, tail);
}
