/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stddef.h>
#include <string.h>

#include <wget.h>

/**
 * \ingroup libwget-utils
 * \param[out] dst Output string buffer
 * \param[in] src Input string
 * \param[in] size Size of \p dst
 * \return Number of copied bytes (excluding trailing 0) or -1 when \p src doesn't fit into \p dst
 *
 * Copy string \p src into \p dst with overflow checking.
 *
 * If either \p dst is %NULL or \p size is 0, the return value is -1 and nothing is written.
 * If \p src is %NULL and size is 0, the return value is -1.
 * If \p src is %NULL and size is >0, the return value is 0 and \p dst is an empty string.
 *
 * Else the return value is the number of bytes copied to \p dst excluding the terminating 0.
 */
ssize_t wget_strscpy(char *dst, const char *src, size_t size)
{
	if (unlikely(!dst))
		return -1;

	if (unlikely(!src)) {
		if (size) {
			*dst = 0;
			return 0;
		} else
			return -1;
	}

	const char *old = src;

	// Copy as many bytes as will fit
	if (likely(size)) {
		while (--size) {
			if (!(*dst++ = *src++))
				return src - old - 1;
		}

		*dst = 0;
		return src - old;
	}

	return -1;
}
