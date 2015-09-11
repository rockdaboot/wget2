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
 * Memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <libmget.h>
#include "private.h"

// strdup which accepts NULL values

char *mget_strdup(const char *s)
{
	return s ? strcpy(xmalloc(strlen(s) + 1), s) : NULL;
}

// memdup sometimes comes in handy

void *mget_memdup(const void *s, size_t n)
{
	return s ? memcpy(xmalloc(n), s, n) : NULL;
}

// convert memory chunk into allocated string

char *mget_strmemdup(const void *s, size_t n)
{
	if (!s)
		return NULL;

	char *ret = memcpy(xmalloc(n + 1), s, n);
	ret[n] = 0;

	return ret;
}

// convert memory chunk to string

void mget_strmemcpy(char *s, size_t ssize, const void *m, size_t n)
{
	if (n >= ssize)
		n = ssize - 1; // truncate

	memcpy(s, m, n);
	s[n] = 0;
}
