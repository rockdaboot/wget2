/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Memory allocation functions
 * \defgroup libwget-xalloc Memory allocation functions
 * @{
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

static void G_GNUC_WGET_NORETURN _no_memory(void)
{
	if (_oom_callback)
		_oom_callback();

	exit(EXIT_FAILURE);
}

/**
 * \param[in] oom_callback Pointer to your custom out-of-memory function
 *
 * Set a custom out-of-memory function.
 */
void wget_set_oomfunc(void (*oom_callback)(void))
{
	_oom_callback = oom_callback;
}

/**
 * \param[in] size Number of bytes to allocate
 * \return A pointer to the allocated (uninitialized) memory
 *
 * Like the standard malloc(), except that it doesn't return %NULL values.
 * If an out-of-memory condition occurs the oom callback function is called (if set).
 * Thereafter the application is terminated by exit(%EXIT_FAILURE);
 */
void *wget_malloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
		_no_memory();
	return p;
}

/**
 * \param[in] nmemb Number of elements (each of size \p size) to allocate
 * \param[in] size Size of element
 * \return A pointer to the allocated (initialized) memory
 *
 * Like the standard calloc(), except that it doesn't return %NULL values.
 * If an out-of-memory condition occurs the oom callback function is called (if set).
 * Thereafter the application is terminated by exit(%EXIT_FAILURE);
 */
void *wget_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (!p)
		_no_memory();
	return p;
}

/**
 * \param[in] ptr Pointer to old memory area
 * \param[in] size Number of bytes to allocate for the new memory area
 * \return A pointer to the new memory area
 *
 * Like the standard realloc(), except that it doesn't return %NULL values.
 * If an out-of-memory condition occurs *or* size is 0, the oom callback function is called (if set).
 * Thereafter the application is terminated by exit(%EXIT_FAILURE);
 */
void *wget_realloc(void *ptr, size_t size)
{
	void *p;

	if (!size)
		_no_memory();

	if (!(p = realloc(ptr, size)))
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

/**@}*/
