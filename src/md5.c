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
 * MD5 helper routines
 *
 * Changelog
 * 21.12.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <libmget.h>

#include "utils.h"
#include "printf.h"
#include "md5.h"

void md5_printf_hex(char *digest_hex, const char *fmt, ...)
{
	char *plaintext;
	va_list args;
	int size;

	va_start(args, fmt);
	size = vasprintf(&plaintext, fmt, args);
	va_end(args);

	if (plaintext) {
		unsigned char digest[gnutls_hash_get_len(GNUTLS_DIG_MD5)];

		if (gnutls_hash_fast(GNUTLS_DIG_MD5, plaintext, size, digest) == 0) {
			buffer_to_hex(digest, sizeof(digest), digest_hex, sizeof(digest) * 2 +1);
		}

		xfree(plaintext);
	}
}
