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
 * Hash routines
 *
 * Changelog
 * 29.07.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <libmget.h>

#include "log.h"

static G_GNUC_MGET_NONNULL((1)) gnutls_digest_algorithm_t _get_algorithm(const char *type)
{
	if (*type == 's' || *type == 'S') {
		if (!strcasecmp(type, "sha-1") || !strcasecmp(type, "sha1"))
			return GNUTLS_DIG_SHA1;
		else if (!strcasecmp(type, "sha-256") || !strcasecmp(type, "sha256"))
			return GNUTLS_DIG_SHA256;
		else if (!strcasecmp(type, "sha-512") || !strcasecmp(type, "sha512"))
			return GNUTLS_DIG_SHA512;
		else if (!strcasecmp(type, "sha-224") || !strcasecmp(type, "sha224"))
			return GNUTLS_DIG_SHA224;
		else if (!strcasecmp(type, "sha-384") || !strcasecmp(type, "sha384"))
			return GNUTLS_DIG_SHA384;
	}
	else if (!strcasecmp(type, "md5"))
		return GNUTLS_DIG_MD5;
	else if (!strcasecmp(type, "md2"))
		return GNUTLS_DIG_MD2;
	else if (!strcasecmp(type, "rmd160"))
		return GNUTLS_DIG_RMD160;

	error_printf(_("Unknown hash type '%s'\n"), type);
	return -1;
}

// return 0 = OK, -1 = failed
int mget_hash_file_fd(const char *type, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length)
{
	int algorithm;
	int ret=-1;
	struct stat st;

	if (digest_hex_size)
		*digest_hex=0;

	if (fstat(fd, &st) != 0)
		return 0;

	if (length == 0)
		length = st.st_size;

	if (offset + length > st.st_size)
		return 0;
	
	debug_printf("%s hashing pos %llu, length %llu...\n", type, (unsigned long long)offset, (unsigned long long)length);

	if ((algorithm = _get_algorithm(type)) >= 0) {
		unsigned char digest[gnutls_hash_get_len(algorithm)];
		char *buf = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);

		if (buf != MAP_FAILED) {
			if (gnutls_hash_fast(algorithm, buf, length, digest) == 0) {
				mget_memtohex(digest, sizeof(digest), digest_hex, digest_hex_size);
				ret = 0;
			}
			munmap(buf, length);
		} else {
			// Fallback to read
			ssize_t nbytes = 0;
			gnutls_hash_hd_t dig;

			buf = alloca(65536);

			gnutls_hash_init(&dig, algorithm);
			while (length > 0 && (nbytes = read(fd, buf, 65536)) > 0) {
				gnutls_hash(dig, buf, nbytes);
				
				if (nbytes <= length)
					length -= nbytes;
				else
					length = 0;
			}
			gnutls_hash_deinit(dig, digest);

			if (nbytes < 0) {
				error_printf("%s: Failed to read %llu bytes\n", __func__, (unsigned long long)length);
				close(fd);
				return -1;
			}
		}
	}
	
	return ret;
}

int mget_hash_file_offset(const char *type, const char *fname, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length)
{
 	int fd, ret;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		if (digest_hex_size)
			*digest_hex=0;
		return 0;
	}

	ret = mget_hash_file_fd(type, fd, digest_hex, digest_hex_size, offset, length);
	close(fd);
	
	return ret;
}

int mget_hash_file(const char *type, const char *fname, char *digest_hex, size_t digest_hex_size)
{
	return mget_hash_file_offset(type, fname, digest_hex, digest_hex_size, 0, 0);
}
