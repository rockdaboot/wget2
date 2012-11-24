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
 * Memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen  extracted from utils.c
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>

#include "log.h"
#include "xalloc.h"

void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
		err_printf_exit("No memory\n");
	return p;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (!p)
		err_printf_exit("No memory\n");
	return p;
}

void *xrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p)
		err_printf_exit("No memory\n");
	return p;
}

/*void xfree(const void **p)
{
	if (p && *p) {
		free(*p);
 *p = NULL;
	}
}*/

#ifndef HAVE_STRNDUP
// I found no strndup on my old SUSE 7.3 test system (gcc 2.95)

char *strndup(const char *s, size_t n)
{
	char *dst = xmalloc(n + 1);

	memcpy(dst, s, n);
	dst[n] = 0;

	return dst;
}
#endif

// strdup which accepts NULL values

char *strdup_null(const char *s)
{
	return s ? strdup(s) : NULL;
}

// xmemdup sometimes comes in handy

void *xmemdup(const void *s, size_t n)
{
	return memcpy(xmalloc(n), s, n);
}
