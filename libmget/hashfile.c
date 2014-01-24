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

#include <libmget.h>
#include <private.h>

#include "log.h"

// Interfaces and types inspired by GnuTLS since it was my first used digest/hash interface

mget_digest_algorithm_t mget_hash_get_algorithm(const char *name)
{
	if (name) {
		if (*name == 's' || *name == 'S') {
			if (!strcasecmp(name, "sha-1") || !strcasecmp(name, "sha1"))
				return MGET_DIGTYPE_SHA1;
			else if (!strcasecmp(name, "sha-256") || !strcasecmp(name, "sha256"))
				return MGET_DIGTYPE_SHA256;
			else if (!strcasecmp(name, "sha-512") || !strcasecmp(name, "sha512"))
				return MGET_DIGTYPE_SHA512;
			else if (!strcasecmp(name, "sha-224") || !strcasecmp(name, "sha224"))
				return MGET_DIGTYPE_SHA224;
			else if (!strcasecmp(name, "sha-384") || !strcasecmp(name, "sha384"))
				return MGET_DIGTYPE_SHA384;
		}
		else if (!strcasecmp(name, "md5"))
			return MGET_DIGTYPE_MD5;
		else if (!strcasecmp(name, "md2"))
			return MGET_DIGTYPE_MD2;
		else if (!strcasecmp(name, "rmd160"))
			return MGET_DIGTYPE_RMD160;
	}

	error_printf(_("Unknown hash type '%s'\n"), name);
	return MGET_DIGTYPE_UNKNOWN;
}

#ifdef WITH_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

struct _hash_hd_st {
	gnutls_hash_hd_t
		dig;
};

static const gnutls_digest_algorithm_t
	_gnutls_algorithm[] = {
		[MGET_DIGTYPE_UNKNOWN] = GNUTLS_DIG_UNKNOWN,
		[MGET_DIGTYPE_MD2] = GNUTLS_DIG_MD2,
		[MGET_DIGTYPE_MD5] = GNUTLS_DIG_MD5,
		[MGET_DIGTYPE_RMD160] = GNUTLS_DIG_RMD160,
		[MGET_DIGTYPE_SHA1] = GNUTLS_DIG_SHA1,
		[MGET_DIGTYPE_SHA224] = GNUTLS_DIG_SHA224,
		[MGET_DIGTYPE_SHA256] = GNUTLS_DIG_SHA256,
		[MGET_DIGTYPE_SHA384] = GNUTLS_DIG_SHA384,
		[MGET_DIGTYPE_SHA512] = GNUTLS_DIG_SHA512
};

int mget_hash_fast(mget_digest_algorithm_t algorithm, const void *text, size_t textlen, void *digest)
{
	if (algorithm >= 0 && algorithm < countof(_gnutls_algorithm))
		return gnutls_hash_fast(_gnutls_algorithm[algorithm], text, textlen, digest);
	else
		return -1;
}

int mget_hash_get_len(mget_digest_algorithm_t algorithm)
{
	if (algorithm >= 0 && algorithm < countof(_gnutls_algorithm))
		return gnutls_hash_get_len(_gnutls_algorithm[algorithm]);
	else
		return 0;
}

int mget_hash_init(mget_hash_hd_t *dig, mget_digest_algorithm_t algorithm)
{
	if (algorithm >= 0 && algorithm < countof(_gnutls_algorithm))
		return gnutls_hash_init(&dig->dig, _gnutls_algorithm[algorithm]) == 0 ? 0 : -1;
	else
		return -1;
}

int mget_hash(mget_hash_hd_t *handle, const void *text, size_t textlen)
{
	return gnutls_hash(handle->dig, text, textlen) == 0 ? 0 : -1;
}

void mget_hash_deinit(mget_hash_hd_t *handle, void *digest)
{
	gnutls_hash_deinit(handle->dig, digest);
}
#elif defined (WITH_LIBNETTLE)
#include <nettle/nettle-meta.h>

struct _hash_hd_st {
	const struct nettle_hash
		*hash;
	void
		*context;
};

static const struct nettle_hash *
	_nettle_algorithm[] = {
		[MGET_DIGTYPE_UNKNOWN] = NULL,
		[MGET_DIGTYPE_MD2] = &nettle_md2,
		[MGET_DIGTYPE_MD5] = &nettle_md5,
		[MGET_DIGTYPE_RMD160] = &nettle_ripemd160,
		[MGET_DIGTYPE_SHA1] = &nettle_sha1,
		[MGET_DIGTYPE_SHA224] = &nettle_sha224,
		[MGET_DIGTYPE_SHA256] = &nettle_sha256,
		[MGET_DIGTYPE_SHA384] = &nettle_sha384,
		[MGET_DIGTYPE_SHA512] = &nettle_sha512
};

int mget_hash_fast(mget_digest_algorithm_t algorithm, const void *text, size_t textlen, void *digest)
{
	mget_hash_hd_t dig;

	if (mget_hash_init(&dig, algorithm) == 0) {
		if (mget_hash(&dig, text, textlen) == 0) {
			mget_hash_deinit(&dig, digest);
			return 0;
		}
	}

	return -1;
}

int mget_hash_get_len(mget_digest_algorithm_t algorithm)
{
	if (algorithm >= 0 && algorithm < countof(_nettle_algorithm))
		return _nettle_algorithm[algorithm]->digest_size;
	else
		return 0;
}

int mget_hash_init(mget_hash_hd_t *dig, mget_digest_algorithm_t algorithm)
{
	if (algorithm >= 0 && algorithm < countof(_nettle_algorithm)) {
		dig->hash = _nettle_algorithm[algorithm];
		dig->context = xmalloc(dig->hash->context_size);
		dig->hash->init(dig->context);
		return 0;
	} else {
		dig->hash = NULL;
		dig->context = NULL;
		return -1;
	}
}

int mget_hash(mget_hash_hd_t *handle, const void *text, size_t textlen)
{
	handle->hash->update(handle->context, textlen, text);
	return 0;
}

void mget_hash_deinit(mget_hash_hd_t *handle, void *digest)
{
	handle->hash->update(handle->context, handle->hash->digest_size, digest);
	xfree(handle->context);
}
#else // empty functions which return error
#define _U G_GNUC_MGET_UNUSED

struct _hash_hd_st {
	char dig;
};

int mget_hash_fast(_U mget_digest_algorithm_t algorithm, _U const void *text, _U size_t textlen, _U void *digest)
{
	return -1;
}

int mget_hash_get_len(_U mget_digest_algorithm_t algorithm)
{
	return 0;
}

int mget_hash_init(_U mget_hash_hd_t *dig, _U mget_digest_algorithm_t algorithm)
{
	return -1;
}

int mget_hash(_U mget_hash_hd_t *handle, _U const void *text, _U size_t textlen)
{
	return -1;
}

void mget_hash_deinit(_U mget_hash_hd_t *handle, _U void *digest)
{
}
#undef _U
#endif

// return 0 = OK, -1 = failed
int mget_hash_file_fd(const char *type, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length)
{
	mget_digest_algorithm_t algorithm;
	int ret=-1;
	struct stat st;

	if (digest_hex_size)
		*digest_hex=0;

	if (fd == -1 || fstat(fd, &st) != 0)
		return -1;

	if (length == 0)
		length = st.st_size;

	if (offset + length > st.st_size)
		return -1;
	
	debug_printf("%s hashing pos %llu, length %llu...\n", type, (unsigned long long)offset, (unsigned long long)length);

	if ((algorithm = mget_hash_get_algorithm(type)) != MGET_DIGTYPE_UNKNOWN) {
		unsigned char digest[mget_hash_get_len(algorithm)];
		char *buf = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);

		if (buf != MAP_FAILED) {
			if (mget_hash_fast(algorithm, buf, length, digest) == 0) {
				mget_memtohex(digest, sizeof(digest), digest_hex, digest_hex_size);
				ret = 0;
			}
			munmap(buf, length);
		} else {
			// Fallback to read
			ssize_t nbytes = 0;
			mget_hash_hd_t dig;

			buf = alloca(65536);

			mget_hash_init(&dig, algorithm);
			while (length > 0 && (nbytes = read(fd, buf, 65536)) > 0) {
				mget_hash(&dig, buf, nbytes);
				
				if (nbytes <= length)
					length -= nbytes;
				else
					length = 0;
			}
			mget_hash_deinit(&dig, digest);

			if (nbytes < 0) {
				error_printf("%s: Failed to read %llu bytes\n", __func__, (unsigned long long)length);
				close(fd);
				return -1;
			}

			mget_memtohex(digest, sizeof(digest), digest_hex, digest_hex_size);
			ret = 0;
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
