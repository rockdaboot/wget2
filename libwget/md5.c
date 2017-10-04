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
 * MD5 helper routines
 *
 * Changelog
 * 21.12.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stddef.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief MD5 convenience functions
 * \defgroup libwget-md5 MD5 convenience functions
 * @{
 *
 * Provides MD5 helper functions
 */

/**
 * \param[out] digest_hex Output string buffer
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 *
 * Calculate the hexadecimal MD5 digest from the string generated via the
 * printf-style \p fmt and the following arguments.
 *
 * \p digest_hex must at least have a size of 33 bytes and will be zero terminated.
 * 33 calculates from wget_hash_get_len(WGET_DIGTYPE_MD5) * 2 + 1.
 */
void wget_md5_printf_hex(char *digest_hex, const char *fmt, ...)
{
	char *plaintext;
	va_list args;
	size_t len;

	va_start(args, fmt);
	len = wget_vasprintf(&plaintext, fmt, args);
	va_end(args);

	if (plaintext) {
		unsigned char digest[wget_hash_get_len(WGET_DIGTYPE_MD5)];
		int rc;

		if ((rc = wget_hash_fast(WGET_DIGTYPE_MD5, plaintext, len, digest)) == 0) {
			wget_memtohex(digest, sizeof(digest), digest_hex, sizeof(digest) * 2 + 1);
		} else {
			*digest_hex = 0;
			error_printf(_("Failed to MD5 hash (%d)\n"), rc);
		}

		xfree(plaintext);
	}
}

/**@}*/
