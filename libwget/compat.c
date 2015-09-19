/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * a collection of compatibility routines
 *
 * Changelog
 * 11.01.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <libwget.h>

#ifndef HAVE_STRLCPY
// strlcpy is a BSD function that I really like.
// it is the same as snprintf(dst,dstsize,"%s",src), but much faster

size_t strlcpy(char *dst, const char *src, size_t size)
{
	const char *old = src;

	// Copy as many bytes as will fit
	if (size) {
		while (--size) {
			if (!(*dst++ = *src++))
				return src - old - 1;
		}

		*dst = 0;
	}

	while (*src++);
	return src - old - 1;
}
#endif

#ifndef HAVE_STRNDUP
// I found no strndup on my old SUSE 7.3 test system (gcc 2.95)

char *strndup(const char *s, size_t n)
{
	char *dst;
	size_t slen = strlen(s);

	if (slen > n)
		n = slen;

	dst = xmalloc(n + 1);

	memcpy(dst, s, n);
	dst[n] = 0;

	return dst;
}
#endif
