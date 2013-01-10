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

#include <stdlib.h>

#include <libmget.h>
#include "private.h"

static void G_GNUC_MGET_NORETURN
	(*_oom_func)(void);

static inline void G_GNUC_MGET_NORETURN _no_memory(void)
{
	if (_oom_func)
		_oom_func();

	exit(EXIT_FAILURE);
}

void mget_set_oomfunc(G_GNUC_MGET_NORETURN void (*oom_func)(void))
{
	_oom_func = oom_func;
}

void *mget_malloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
		_no_memory();
	return p;
}

void *mget_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (!p)
		_no_memory();
	return p;
}

void *mget_realloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p)
		_no_memory();
	return p;
}

/*void mget_free(const void **p)
{
	if (p && *p) {
		free(*p);
		*p = NULL;
	}
}*/

