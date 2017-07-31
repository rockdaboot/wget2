/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015-2017 Free Software Foundation, Inc.
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
 * a collection of compatibility routines
 *
 * Changelog
 * 11.01.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stddef.h>
#include <string.h>

#include <wget.h>

// strlcpy is a BSD function that I really like.
// it is the same as snprintf(dst,dstsize,"%s",src), but much faster

size_t wget_strlcpy(char *dst, const char *src, size_t size)
{
	if (!src)
		return 0;

	if (!dst)
		return strlen(src);

#ifndef HAVE_STRLCPY
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
#else
	return strlcpy(dst, src, size);
#endif
}
