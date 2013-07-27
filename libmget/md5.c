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

#ifdef WITH_GNUTLS
#	include <gnutls/gnutls.h>
#	include <gnutls/crypto.h>
#elif HAVE_CRYPT_H
// fallback to glibc crypt_r() extension
#	include <crypt.h>
#else
// no MD5 available
#endif

#include <libmget.h>
#include "private.h"

void mget_md5_printf_hex(char *digest_hex, const char *fmt, ...)
{
	char *plaintext;
	va_list args;
	int size;

	va_start(args, fmt);
	size = vasprintf(&plaintext, fmt, args);
	va_end(args);

	if (plaintext) {
#ifdef WITH_GNUTLS
		unsigned char digest[gnutls_hash_get_len(GNUTLS_DIG_MD5)];

		if (gnutls_hash_fast(GNUTLS_DIG_MD5, plaintext, size, digest) == 0) {
			mget_memtohex(digest, sizeof(digest), digest_hex, sizeof(digest) * 2 +1);
		}
#elif HAVE_CRYPT_H
		const char *digest;
		struct crypt_data data = { .initialized = 0 };

		if ((digest = crypt_r(plaintext, "$1$", &data))) {
			mget_memtohex(digest, 16, digest_hex, 16 * 2 +1);

			xfree(digest);
		}
#else
		*digest_hex = 0;
#endif

		xfree(plaintext);
	}
}
