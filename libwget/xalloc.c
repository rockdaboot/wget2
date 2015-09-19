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

#include <libwget.h>
#include "private.h"

/**
 * SECTION:libwget-xalloc
 * @short_description: Memory allocation functions
 * @title: libwget-xalloc
 * @stability: stable
 * @include: libwget.h
 *
 * The provided memory allocation functions are used by explicit libwget memory
 * allocations.
 * They differ from the standard ones in that they exit the program in an
 * out-of-memory situation with %EXIT_FAILURE. That means, you don't have to
 * check the returned value against %NULL.
 *
 * You can provide a out-of-memory function that will be called before exit(),
 * e.g. to print out a "No memory" message.
 *
 * To work around this behavior, provide your own allocation routines,
 * namely malloc(), calloc(), realloc().
 */

static void
	(*_oom_callback)(void);

static inline void G_GNUC_WGET_NORETURN _no_memory(void)
{
	if (_oom_callback)
		_oom_callback();

	exit(EXIT_FAILURE);
}

/**
 * wget_set_oomfunc:
 * @oom_callback: Pointer to your custom out-of-memory function.
 *
 * Set a custom out-of-memory function.
 */
void wget_set_oomfunc(void (*oom_callback)(void))
{
	_oom_callback = oom_callback;
}

/**
 * wget_malloc:
 * @size: Number of bytes to allocate.
 *
 * Like the standard malloc(), except that it doesn't return %NULL values.
 * If an out-of-memory condition occurs the oom callback function is called (if set).
 * Thereafter the application is terminated by exit(%EXIT_FAILURE);
 *
 * Return: A pointer to the allocated (uninitialized) memory.
 */
void *wget_malloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
		_no_memory();
	return p;
}

/**
 * wget_calloc:
 * @nmemb: Number of elements (each of size @size) to allocate.
 * @size: Size of element.
 *
 * Like the standard calloc(), except that it doesn't return %NULL values.
 * If an out-of-memory condition occurs the oom callback function is called (if set).
 * Thereafter the application is terminated by exit(%EXIT_FAILURE);
 *
 * Return: A pointer to the allocated (initialized) memory.
 */
void *wget_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (!p)
		_no_memory();
	return p;
}

/**
 * wget_realloc:
 * @ptr: Pointer to old memory area.
 * @size: Number of bytes to allocate for the new memory area.
 *
 * Like the standard realloc(), except that it doesn't return %NULL values.
 * If an out-of-memory condition occurs the oom callback function is called (if set).
 * Thereafter the application is terminated by exit(%EXIT_FAILURE);
 *
 * Return: A pointer to the new memory area.
 */
void *wget_realloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p)
		_no_memory();
	return p;
}

/*void wget_free(const void **p)
{
	if (p && *p) {
		free(*p);
		*p = NULL;
	}
}*/

void *rpl_malloc (size_t n)
{
	return malloc (n ? n : 1);
}

void *rpl_realloc (void *ptr, size_t n)
{
	return realloc (ptr, n ? n : 1);
}
