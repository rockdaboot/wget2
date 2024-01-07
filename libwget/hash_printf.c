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
 * Digest/hash helper routines
 *
 * 21.12.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stddef.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Hash convenience functions
 * \defgroup libwget-hash Hash convenience functions
 * @{
 *
 * Provides Hash helper functions
 */

/**
 * \param[in] algorithm The hash algorithm to use
 * \param[out] out Output string buffer
 * \param[in] outsize Size of output string buffer
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 *
 * Calculate the hash from the string generated via the
 * printf-style \p fmt and the following arguments and place it as hexadecimal string
 * into \p out.
 *
 * The ideal length of \p out would be wget_hash_get_len(type) * 2 + 1.
 */
void wget_hash_printf_hex(wget_digest_algorithm algorithm, char *out, size_t outsize, const char *fmt, ...)
{
	char *plaintext = NULL;
	va_list args;
	size_t len;

	va_start(args, fmt);
	len = wget_vasprintf(&plaintext, fmt, args);
	va_end(args);

	if (!plaintext)
		return;

	unsigned char tmp[256], *digest = tmp;
	size_t digestlen = wget_hash_get_len(algorithm);

	if (digestlen > sizeof(tmp)) {
		digest = wget_malloc(digestlen);
	}

	if (digest) {
		int rc;

		if ((rc = wget_hash_fast(algorithm, plaintext, len, digest)) == 0) {
			wget_memtohex(digest, digestlen, out, outsize);
		} else {
			*out = 0;
			error_printf(_("Failed to hash (%d)\n"), rc);
		}

		if (digest != tmp)
			xfree(digest);
	} else {
		error_printf(_("%s: Failed to malloc %zu bytes\n"), __func__, digestlen);
	}

	xfree(plaintext);
}

/**@}*/
