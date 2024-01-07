/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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

#include <string.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Memory functions
 * \defgroup libwget-mem Memory functions
 * @{
 *
 * This is a collections of short memory function not available in standard libraries.
 */

/**
 * \param[in] m Memory to clone
 * \param[in] n Length of memory
 * \return Cloned memory
 *
 * Clone's the memory region \p m with length \p n.
 * Returns NULL if \p m is NULL.
 *
 * You should free() the returned pointer when not needed any more.
 */
void *wget_memdup(const void *m, size_t n)
{
	if (!m) return NULL;

	void *d = wget_malloc(n);
	if (!d)
		return NULL;

	return memcpy(d, m, n);
}

/**
 * \param[in] s String to clone
 * \return Cloned string
 *
 * Clone's the string \p s like strdup() does.
 * Returns NULL if \p s is NULL.
 *
 * You should free() the returned string when not needed any more.
 */
char *wget_strdup(const char *s)
{
	return s ? wget_memdup(s, strlen(s) + 1) : NULL;
}

/**
 * \param[in] m Memory to convert into string
 * \param[in] n Length of memory
 * \return Created string
 *
 * Convert the given memory region \p m with length \p n into a C string.
 * Returns NULL if \p m is NULL.
 *
 * You should free() the returned string when not needed any more.
 */
char *wget_strmemdup(const void *m, size_t n)
{
	if (!m)
		return NULL;

	void *d = wget_malloc(n + 1);
	if (!d)
		return NULL;

	char *ret = memcpy(d, m, n);
	ret[n] = 0;

	return ret;
}

/**
 * \param[out] s Buffer to hold the C string output
 * \param[in] ssize Size of the output buffer
 * \param[in] m Memory to read from
 * \param[in] n Length of memory
 * \return Number of bytes copied, not counting the trailing 0 byte
 *
 * Convert the given memory region \p m with length \p n into a C string at \p s.
 * A max. of \p ssize - 1  is copied into \p s.
 */
size_t wget_strmemcpy(char *s, size_t ssize, const void *m, size_t n)
{
	if (!s || !ssize)
		return 0;

	if (likely(n > 0)) {
		if (n >= ssize)
			n = ssize - 1; // truncate

		if (m)
			memmove(s, m, n);
		else
			n = 0;
	}
	s[n] = 0;

	return n;
}

/**
 * \param[out] s Buffer to hold the C string output
 * \param[in] ssize Size of the output buffer
 * \param[in] m Memory to read from
 * \param[in] n Length of memory
 * \return Pointer to destination (either \p s or a freshly allocated buffer)
 *
 * Convert the given memory region \p m with length \p n into a C string at \p s or at freshly allocated memory,
 * if the space in \p s was not sufficient.
 *
 * If \p s was too small to hold \p n + 1 bytes, the result must be free'd after use, e.g.
 *   if (res != s) wget_free(res);
 */
void *wget_strmemcpy_a(char *s, size_t ssize, const void *m, size_t n)
{
	if (n >= ssize) {
		if (!(s = wget_malloc(n + 1)))
			return NULL;
	}

	memmove(s, m, n);
	s[n] = 0;
	return s;
}

/**@}*/
