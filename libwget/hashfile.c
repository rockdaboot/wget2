/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Hash routines
 *
 * Changelog
 * 29.07.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_MMAP
#	include <sys/mman.h>
#endif

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Hashing functions
 * \ingroup libwget-hash
 * @{
 *
 */

/**
 * \param[in] hashname Name of the hashing algorithm (see table below)
 * \return A constant to be used by libwget hashing functions
 *
 * Get the hashing algorithms list item that corresponds to the named hashing algorithm.
 *
 * This function returns a constant that uniquely identifies a known supported hashing algorithm
 * within libwget. All the supported algorithms are listed in the ::wget_digest_algorithm enum.
 *
 * Algorithm name | Constant
 * -------------- | --------
 * sha1 or sha-1|WGET_DIGTYPE_SHA1
 * sha256 or sha-256|WGET_DIGTYPE_SHA256
 * sha512 or sha-512|WGET_DIGTYPE_SHA512
 * sha224 or sha-224|WGET_DIGTYPE_SHA224
 * sha384 or sha-384|WGET_DIGTYPE_SHA384
 * md5|WGET_DIGTYPE_MD5
 * md2|WGET_DIGTYPE_MD2
 * rmd160|WGET_DIGTYPE_RMD160
 */
wget_digest_algorithm wget_hash_get_algorithm(const char *hashname)
{
	if (hashname) {
		if (*hashname == 's' || *hashname == 'S') {
			if (!wget_strcasecmp_ascii(hashname, "sha-1") || !wget_strcasecmp_ascii(hashname, "sha1"))
				return WGET_DIGTYPE_SHA1;
			else if (!wget_strcasecmp_ascii(hashname, "sha-256") || !wget_strcasecmp_ascii(hashname, "sha256"))
				return WGET_DIGTYPE_SHA256;
			else if (!wget_strcasecmp_ascii(hashname, "sha-512") || !wget_strcasecmp_ascii(hashname, "sha512"))
				return WGET_DIGTYPE_SHA512;
			else if (!wget_strcasecmp_ascii(hashname, "sha-224") || !wget_strcasecmp_ascii(hashname, "sha224"))
				return WGET_DIGTYPE_SHA224;
			else if (!wget_strcasecmp_ascii(hashname, "sha-384") || !wget_strcasecmp_ascii(hashname, "sha384"))
				return WGET_DIGTYPE_SHA384;
		}
		else if (!wget_strcasecmp_ascii(hashname, "md5"))
			return WGET_DIGTYPE_MD5;
		else if (!wget_strcasecmp_ascii(hashname, "md2"))
			return WGET_DIGTYPE_MD2;
		else if (!wget_strcasecmp_ascii(hashname, "rmd160"))
			return WGET_DIGTYPE_RMD160;
	}

	error_printf(_("Unknown hash type '%s'\n"), hashname);
	return WGET_DIGTYPE_UNKNOWN;
}

#if defined WITH_GNUTLS && !defined WITH_LIBNETTLE
#include <gnutls/gnutls.h>
#ifdef HAVE_GNUTLS_CRYPTO_H
#  include <gnutls/crypto.h>
#endif

struct wget_hash_hd_st {
	gnutls_hash_hd_t
		dig;
};

static const gnutls_digest_algorithm_t
	algorithms[WGET_DIGTYPE_MAX] = {
//		[WGET_DIGTYPE_UNKNOWN] = GNUTLS_DIG_UNKNOWN, // both values are 0
		[WGET_DIGTYPE_MD2] = GNUTLS_DIG_MD2,
		[WGET_DIGTYPE_MD5] = GNUTLS_DIG_MD5,
		[WGET_DIGTYPE_RMD160] = GNUTLS_DIG_RMD160,
		[WGET_DIGTYPE_SHA1] = GNUTLS_DIG_SHA1,
		[WGET_DIGTYPE_SHA224] = GNUTLS_DIG_SHA224,
		[WGET_DIGTYPE_SHA256] = GNUTLS_DIG_SHA256,
		[WGET_DIGTYPE_SHA384] = GNUTLS_DIG_SHA384,
		[WGET_DIGTYPE_SHA512] = GNUTLS_DIG_SHA512
};

/**
 * \param[in] algorithm One of the hashing algorithms returned by wget_hash_get_algorithm()
 * \param[in] text Input data to hash
 * \param[in] textlen Length of the input data
 * \param[in] digest Caller-supplied buffer where the output hash will be placed
 * \return Zero on success or a negative value on error
 *
 * Convenience function to hash the given data in a single call.
 *
 * The caller must ensure that the provided output buffer \p digest is large enough
 * to store the hash. A particular hash algorithm is guaranteed to always generate
 * the same amount of data (e.g. 512 bits) but different hash algorithms will output
 * different lengths of data. To get the output length of the chosen algorithm \p algorithm,
 * call wget_hash_get_len().
 *
 * \note This function's behavior depends on the underlying cryptographic engine libwget was compiled with.
 */
int wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest)
{
	if ((unsigned) algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	gnutls_digest_algorithm_t hashtype = algorithms[algorithm];
	if (hashtype == GNUTLS_DIG_UNKNOWN)
		return WGET_E_UNSUPPORTED;

	if (gnutls_hash_fast(algorithms[algorithm], text, textlen, digest) != 0)
		return WGET_E_UNKNOWN;

	return WGET_E_SUCCESS;
}

/**
 * \param[in] algorithm One of the hashing algorithms returned by wget_hash_get_algorithm()
 * \return The length of the output data generated by the algorithm
 *
 * Determines the output length of the given hashing algorithm.
 *
 * A particular hash algorithm is guaranteed to always generate
 * the same amount of data (e.g. 512 bits) but different hash algorithms will output
 * different lengths of data.
 */
int wget_hash_get_len(wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm < countof(algorithms))
		return gnutls_hash_get_len(algorithms[algorithm]);
	else
		return 0;
}

/**
 * \param[out] handle Caller-provided pointer to a ::wget_hash_hd structure where the handle to this
 * hashing primitive will be stored, needed in subsequent calls to wget_hash()
 * \param[in] algorithm One of the hashing algorithms returned by wget_hash_get_algorithm()
 * \return Zero on success or a negative value on error
 *
 * Initialize the cryptographic engine to compute hashes with the given hashing algorithm,
 * as well as the hashing algorithm itself.
 *
 * After this function returns, wget_hash() might be called as many times as desired.
 */
int wget_hash_init(wget_hash_hd **handle, wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	gnutls_digest_algorithm_t hashtype = algorithms[algorithm];
	if (hashtype == GNUTLS_DIG_UNKNOWN)
		return WGET_E_UNSUPPORTED;

	if (!(*handle = wget_malloc(sizeof(struct wget_hash_hd_st))))
		return WGET_E_MEMORY;

	if (gnutls_hash_init(&(*handle)->dig, algorithms[algorithm]) != 0) {
		xfree(*handle);
		return WGET_E_UNKNOWN;
	}

	return WGET_E_SUCCESS;
}

/**
 * \param[in] handle Handle to the hashing primitive returned by a subsequent call to wget_hash_init()
 * \param[in] text Input data
 * \param[in] textlen Length of the input data
 * \return Zero on success or a negative value on error
 *
 * Update the digest by adding additional input data to it. This method can be called
 * as many times as desired. Once finished, call wget_hash_deinit() to complete
 * the computation and get the resulting hash.
 */
int wget_hash(wget_hash_hd *handle, const void *text, size_t textlen)
{
	return gnutls_hash(handle->dig, text, textlen) == 0 ? 0 : -1;
}

/**
 * \param[in] handle Handle to the hashing primitive returned by a subsequent call to wget_hash_init()
 * \param[out] digest Caller-supplied buffer where the output hash will be placed.
 * \return 0 on success, < 0 on failure
 *
 * Complete the hash computation by performing final operations, such as padding,
 * and obtain the final result. The result will be placed in the caller-supplied
 * buffer \p digest. The caller must ensure that the provided output buffer \p digest
 * is large enough to store the hash. To get the output length of the chosen algorithm
 * \p algorithm, call wget_hash_get_len().
 */
int wget_hash_deinit(wget_hash_hd **handle, void *digest)
{
	gnutls_hash_deinit((*handle)->dig, digest);

	xfree(*handle);

	return WGET_E_SUCCESS;
}

#elif defined WITH_LIBWOLFCRYPT
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WC_NO_HARDEN
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>

struct wget_hash_hd_st {
	wc_HashAlg
		hash;
	enum wc_HashType
		type;
};

static const enum wc_HashType
	algorithms[] = {
		// [WGET_DIGTYPE_UNKNOWN] = WC_HASH_TYPE_NONE, // both values are 0
		// [WGET_DIGTYPE_MD2] = WC_HASH_TYPE_MD2, // not in wc_hashAlg
		[WGET_DIGTYPE_MD5] = WC_HASH_TYPE_MD5,
		[WGET_DIGTYPE_SHA1] = WC_HASH_TYPE_SHA,
		[WGET_DIGTYPE_SHA224] = WC_HASH_TYPE_SHA224,
		[WGET_DIGTYPE_SHA256] = WC_HASH_TYPE_SHA256,
		[WGET_DIGTYPE_SHA384] = WC_HASH_TYPE_SHA384,
		[WGET_DIGTYPE_SHA512] = WC_HASH_TYPE_SHA512,
};

int wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest)
{
	if ((unsigned) algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	enum wc_HashType hashtype = algorithms[algorithm];
	if (hashtype == WC_HASH_TYPE_NONE)
		return WGET_E_UNSUPPORTED;

	if (wc_Hash(hashtype, text, (unsigned) textlen, digest, wc_HashGetDigestSize(hashtype)) != 0)
		return WGET_E_UNKNOWN;

	return WGET_E_SUCCESS;
}

int wget_hash_get_len(wget_digest_algorithm algorithm)
{
	if ((unsigned) algorithm < countof(algorithms)) {
		int ret = wc_HashGetDigestSize(algorithms[algorithm]);
		if (ret > 0)
			return ret;
	}

	return 0;
}

int wget_hash_init(wget_hash_hd **handle, wget_digest_algorithm algorithm)
{
	if ((unsigned) algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	enum wc_HashType hashtype = algorithms[algorithm];
	if (hashtype == WC_HASH_TYPE_NONE)
		return WGET_E_UNSUPPORTED;

	if (!(*handle = wget_malloc(sizeof(struct wget_hash_hd_st))))
		return WGET_E_MEMORY;

	if (wc_HashInit(&(*handle)->hash, hashtype) != 0) {
		xfree(*handle);
		return WGET_E_UNKNOWN;
	}

	(*handle)->type = hashtype;

	return WGET_E_SUCCESS;
}

int wget_hash(wget_hash_hd *handle, const void *text, size_t textlen)
{
	if (wc_HashUpdate(&handle->hash, handle->type, text, (unsigned) textlen) == 0)
		return WGET_E_SUCCESS;

	return WGET_E_UNKNOWN;
}

int wget_hash_deinit(wget_hash_hd **handle, void *digest)
{
	int rc = wc_HashFinal(&(*handle)->hash, (*handle)->type, digest);

	xfree(*handle);

	return rc == 0 ? rc : WGET_E_UNKNOWN;
}

#elif defined WITH_LIBCRYPTO
#include <openssl/evp.h>

typedef const EVP_MD *evp_md_func(void);

struct wget_hash_hd_st {
	EVP_MD_CTX
		*ctx;
};

static evp_md_func *
	algorithms[] = {
//		[WGET_DIGTYPE_UNKNOWN] = NULL,
//		[WGET_DIGTYPE_MD2]     = EVP_md2,
		[WGET_DIGTYPE_MD5]     = EVP_md5,
		[WGET_DIGTYPE_RMD160]  = EVP_ripemd160,
		[WGET_DIGTYPE_SHA1]    = EVP_sha1,
		[WGET_DIGTYPE_SHA224]  = EVP_sha224,
		[WGET_DIGTYPE_SHA256]  = EVP_sha256,
		[WGET_DIGTYPE_SHA384]  = EVP_sha384,
		[WGET_DIGTYPE_SHA512]  = EVP_sha512,
	};

int wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest)
{
	if ((unsigned) algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	evp_md_func *evp = algorithms[algorithm];
	if (!evp)
		return WGET_E_UNSUPPORTED;

	if (EVP_Digest(text, textlen, digest, NULL, evp(), NULL) == 0)
		return WGET_E_UNKNOWN;

	return WGET_E_SUCCESS;
}

int wget_hash_get_len(wget_digest_algorithm algorithm)
{
	evp_md_func *evp;

	if ((unsigned) algorithm >= countof(algorithms)
		|| (evp = algorithms[algorithm]) == NULL)
		return 0;

	return EVP_MD_size(evp());
}

int wget_hash_init(wget_hash_hd **handle, wget_digest_algorithm algorithm)
{
	evp_md_func *evp;

	if ((unsigned) algorithm >= countof(algorithms))
		return WGET_E_UNSUPPORTED;

	if ((evp = algorithms[algorithm]) == NULL)
		return WGET_E_UNSUPPORTED;

	if (!(*handle = wget_malloc(sizeof(struct wget_hash_hd_st))))
		return WGET_E_MEMORY;

	if (!((*handle)->ctx = EVP_MD_CTX_new())) {
		xfree(*handle);
		return WGET_E_UNKNOWN;
	}

	if (EVP_DigestInit_ex((*handle)->ctx, evp(), NULL))
		return WGET_E_SUCCESS;

	EVP_MD_CTX_free((*handle)->ctx);
	xfree(*handle);

	return WGET_E_UNKNOWN;
}

int wget_hash(wget_hash_hd *handle, const void *text, size_t textlen)
{
	if (EVP_DigestUpdate(handle->ctx, text, textlen))
		return WGET_E_SUCCESS;

	return WGET_E_INVALID;
}

int wget_hash_deinit(wget_hash_hd **handle, void *digest)
{
	EVP_DigestFinal_ex((*handle)->ctx, digest, NULL);

	EVP_MD_CTX_free((*handle)->ctx);
	xfree(*handle);

	return WGET_E_SUCCESS;
}

#elif defined WITH_LIBNETTLE
#include <nettle/nettle-meta.h>
#include <nettle/md2.h>
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/sha2.h>

struct wget_hash_hd_st {
	const struct nettle_hash
		*hash;
	void
		*context;
};

static const struct nettle_hash *
	algorithms[WGET_DIGTYPE_MAX] = {
//		[WGET_DIGTYPE_UNKNOWN] = NULL,
		[WGET_DIGTYPE_MD2] = &nettle_md2,
		[WGET_DIGTYPE_MD5] = &nettle_md5,
#ifdef RIPEMD160_DIGEST_SIZE
		[WGET_DIGTYPE_RMD160] = &nettle_ripemd160,
#endif
		[WGET_DIGTYPE_SHA1] = &nettle_sha1,
#ifdef SHA224_DIGEST_SIZE
		[WGET_DIGTYPE_SHA224] = &nettle_sha224,
#endif
#ifdef SHA256_DIGEST_SIZE
		[WGET_DIGTYPE_SHA256] = &nettle_sha256,
#endif
#ifdef SHA384_DIGEST_SIZE
		[WGET_DIGTYPE_SHA384] = &nettle_sha384,
#endif
#ifdef SHA512_DIGEST_SIZE
		[WGET_DIGTYPE_SHA512] = &nettle_sha512,
#endif
};

int wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest)
{
	wget_hash_hd *dig;
	int rc;

	if ((rc = wget_hash_init(&dig, algorithm)) == 0) {
		rc = wget_hash(dig, text, textlen);
		wget_hash_deinit(&dig, digest);
	}

	return rc;
}

int wget_hash_get_len(wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm < countof(algorithms))
		return algorithms[algorithm]->digest_size;
	else
		return 0;
}

int wget_hash_init(wget_hash_hd **handle, wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	if (!algorithms[algorithm])
		return WGET_E_UNSUPPORTED;

	wget_hash_hd *h;

	if (!(h = wget_malloc(sizeof(struct wget_hash_hd_st))))
		return WGET_E_MEMORY;

	h->hash = algorithms[algorithm];

	if (!(h->context = wget_malloc(h->hash->context_size))) {
		xfree(h);
		return WGET_E_MEMORY;
	}

	h->hash->init(h->context);
	*handle = h;

	return WGET_E_SUCCESS;
}

int wget_hash(wget_hash_hd *handle, const void *text, size_t textlen)
{
	handle->hash->update(handle->context, textlen, text);
	return WGET_E_SUCCESS;
}

int wget_hash_deinit(wget_hash_hd **handle, void *digest)
{
	(*handle)->hash->digest((*handle)->context, (*handle)->hash->digest_size, digest);
	xfree((*handle)->context);
	xfree(*handle);
	return WGET_E_SUCCESS;
}

#elif defined WITH_GCRYPT
#ifdef HAVE_GCRYPT_H
  #include <gcrypt.h>
#endif

struct wget_hash_hd_st {
	int
		algorithm;
	gcry_md_hd_t
		context;
};

static const int algorithms[] = {
//	[WGET_DIGTYPE_UNKNOWN] = GCRY_MD_NONE,
	[WGET_DIGTYPE_MD2] = GCRY_MD_MD2,
	[WGET_DIGTYPE_MD5] = GCRY_MD_MD5,
	[WGET_DIGTYPE_RMD160] = GCRY_MD_RMD160,
	[WGET_DIGTYPE_SHA1] = GCRY_MD_SHA1,
	[WGET_DIGTYPE_SHA224] = GCRY_MD_SHA224,
	[WGET_DIGTYPE_SHA256] = GCRY_MD_SHA256,
	[WGET_DIGTYPE_SHA384] = GCRY_MD_SHA384,
	[WGET_DIGTYPE_SHA512] = GCRY_MD_SHA512
};

int wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest)
{
	wget_hash_hd *dig;
	int rc;

	if ((rc = wget_hash_init(&dig, algorithm)) == 0) {
		rc = wget_hash(dig, text, textlen);
		wget_hash_deinit(&dig, digest);
	}

	return rc;
}

int wget_hash_get_len(wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm < countof(algorithms))
		return gcry_md_get_algo_dlen(algorithms[algorithm]);
	else
		return 0;
}

int wget_hash_init(wget_hash_hd **handle, wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm >= countof(algorithms))
		return WGET_E_INVALID;

	if (!algorithms[algorithm])
		return WGET_E_UNSUPPORTED;

	wget_hash_hd *h;

	if (!(h = wget_malloc(sizeof(struct wget_hash_hd_st))))
		return WGET_E_MEMORY;

	h->algorithm = algorithms[algorithm];
	gcry_md_open(&h->context, h->algorithm, 0);

	*handle = h;

	return WGET_E_SUCCESS;
}

int wget_hash(wget_hash_hd *handle, const void *text, size_t textlen)
{
	gcry_md_write(handle->context, text, textlen);
	return 0;
}

int wget_hash_deinit(wget_hash_hd **handle, void *digest)
{
	gcry_md_final((*handle)->context);
	void *ret = gcry_md_read((*handle)->context, (*handle)->algorithm);
	memcpy(digest, ret, gcry_md_get_algo_dlen((*handle)->algorithm));
	gcry_md_close((*handle)->context);
	xfree(*handle);

	return WGET_E_SUCCESS;
}

#else // use the gnulib functions

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#pragma GCC diagnostic pop

typedef void (*_hash_init_t)(void *);
typedef void (*_hash_process_t)(const void *, size_t, void *);
typedef void (*_hash_finish_t)(void *, void *);
typedef void (*_hash_read_t)(const void *, void *);

static struct _algorithm {
	_hash_init_t init;
	_hash_process_t process;
	_hash_finish_t finish;
	_hash_read_t read;
	size_t ctx_len;
	size_t digest_len;
} _algorithm[WGET_DIGTYPE_MAX] = {
	[WGET_DIGTYPE_MD2] = {
		(_hash_init_t)md2_init_ctx,
		(_hash_process_t)md2_process_bytes,
		(_hash_finish_t)md2_finish_ctx,
		(_hash_read_t)md2_read_ctx,
		sizeof(struct md2_ctx),
		MD2_DIGEST_SIZE
	},
	[WGET_DIGTYPE_MD5] = {
		(_hash_init_t)md5_init_ctx,
		(_hash_process_t)md5_process_bytes,
		(_hash_finish_t)md5_finish_ctx,
		(_hash_read_t)md5_read_ctx,
		sizeof(struct md5_ctx),
		MD5_DIGEST_SIZE
	},
	[WGET_DIGTYPE_SHA1] = {
		(_hash_init_t)sha1_init_ctx,
		(_hash_process_t)sha1_process_bytes,
		(_hash_finish_t)sha1_finish_ctx,
		(_hash_read_t)sha1_read_ctx,
		sizeof(struct sha1_ctx),
		SHA1_DIGEST_SIZE
	},
	[WGET_DIGTYPE_SHA224] = {
		(_hash_init_t)sha224_init_ctx,
		(_hash_process_t)sha256_process_bytes, // sha256 is intentional
		(_hash_finish_t)sha224_finish_ctx,
		(_hash_read_t)sha224_read_ctx,
		sizeof(struct sha256_ctx), // sha256 is intentional
		SHA224_DIGEST_SIZE
	},
	[WGET_DIGTYPE_SHA256] = {
		(_hash_init_t)sha256_init_ctx,
		(_hash_process_t)sha256_process_bytes,
		(_hash_finish_t)sha256_finish_ctx,
		(_hash_read_t)sha256_read_ctx,
		sizeof(struct sha256_ctx),
		SHA256_DIGEST_SIZE
	},
	[WGET_DIGTYPE_SHA384] = {
		(_hash_init_t)sha384_init_ctx,
		(_hash_process_t)sha512_process_bytes, // sha512 is intentional
		(_hash_finish_t)sha384_finish_ctx,
		(_hash_read_t)sha384_read_ctx,
		sizeof(struct sha512_ctx), // sha512 is intentional
		SHA384_DIGEST_SIZE
	},
	[WGET_DIGTYPE_SHA512] = {
		(_hash_init_t)sha512_init_ctx,
		(_hash_process_t)sha512_process_bytes,
		(_hash_finish_t)sha512_finish_ctx,
		(_hash_read_t)sha512_read_ctx,
		sizeof(struct sha512_ctx),
		SHA512_DIGEST_SIZE
	}
};

struct wget_hash_hd_st {
	const struct _algorithm
		*algorithm;
	void
		*context;
};

int wget_hash_fast(wget_digest_algorithm algorithm, const void *text, size_t textlen, void *digest)
{
	wget_hash_hd *dig;
	int rc;

	if ((rc = wget_hash_init(&dig, algorithm)) == WGET_E_SUCCESS) {
		rc = wget_hash(dig, text, textlen);
		wget_hash_deinit(&dig, digest);
	}

	return rc;
}

int wget_hash_get_len(wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm < countof(_algorithm))
		return (int) _algorithm[algorithm].digest_len;
	else
		return 0;
}

int wget_hash_init(wget_hash_hd **handle, wget_digest_algorithm algorithm)
{
	if ((unsigned)algorithm >= countof(_algorithm))
		return WGET_E_INVALID;

	if (!_algorithm[algorithm].ctx_len)
		return WGET_E_UNSUPPORTED;

	wget_hash_hd *h;

	if (!(h = wget_malloc(sizeof(struct wget_hash_hd_st))))
		return WGET_E_MEMORY;

	h->algorithm = &_algorithm[algorithm];

	if (!(h->context = wget_malloc(h->algorithm->ctx_len))) {
		xfree(h);
		return WGET_E_MEMORY;
	}

	h->algorithm->init(h->context);
	*handle = h;

	return WGET_E_SUCCESS;
}

int wget_hash(wget_hash_hd *handle, const void *text, size_t textlen)
{
	handle->algorithm->process(text, textlen, handle->context);
	return 0;
}

int wget_hash_deinit(wget_hash_hd **handle, void *digest)
{
	(*handle)->algorithm->finish((*handle)->context, digest);
	xfree((*handle)->context);
	xfree(*handle);

	return WGET_E_SUCCESS;
}
#endif

/**
 * \param[in] hashname Name of the hashing algorithm. See wget_hash_get_algorithm()
 * \param[in] fd File descriptor for the target file
 * \param[out] digest_hex caller-supplied buffer that will contain the resulting hex string
 * \param[in] digest_hex_size Length of \p digest_hex
 * \param[in] offset File offset to start hashing at
 * \param[in] length Number of bytes to hash, starting from \p offset. Zero will hash up to the end of the file
 * \return 0 on success or -1 in case of failure
 *
 * Compute the hash of the contents of the target file and return its hex representation.
 *
 * This function will encode the resulting hash in a string of hex digits, and
 * place that string in the user-supplied buffer \p digest_hex.
 */
int wget_hash_file_fd(const char *hashname, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length)
{
	wget_digest_algorithm algorithm;
	int ret = WGET_E_UNKNOWN;
	struct stat st;

	if (digest_hex_size)
		*digest_hex=0;

	if (fd == -1 || fstat(fd, &st) != 0)
		return WGET_E_IO;

	if (length == 0)
		length = st.st_size;

	if (offset + length > st.st_size)
		return WGET_E_INVALID;

	debug_printf("%s hashing pos %llu, length %llu...\n", hashname, (unsigned long long)offset, (unsigned long long)length);

	if ((algorithm = wget_hash_get_algorithm(hashname)) != WGET_DIGTYPE_UNKNOWN) {
		unsigned char digest[256];
		size_t digestlen = wget_hash_get_len(algorithm);

		if (digestlen > sizeof(digest)) {
			error_printf(_("%s: Unexpected hash len %zu > %zu\n"), __func__, digestlen, sizeof(digest));
			return ret;
		}

#ifdef HAVE_MMAP
		char *buf = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);

		if (buf != MAP_FAILED) {
			if (wget_hash_fast(algorithm, buf, length, digest) == 0) {
				wget_memtohex(digest, digestlen, digest_hex, digest_hex_size);
				debug_printf("  hash %s", digest_hex);
				ret = WGET_E_SUCCESS;
			}
			munmap(buf, length);
		} else {
#endif
			// Fallback to read
			ssize_t nbytes = 0;
			wget_hash_hd *dig;
			char tmp[65536];

			if ((ret = wget_hash_init(&dig, algorithm))) {
				error_printf(_("%s: Hash init failed for type '%s': %s\n"), __func__, hashname, wget_strerror(ret));
				return ret;
			}

			while (length > 0 && (nbytes = read(fd, tmp, sizeof(tmp))) > 0) {
				if ((ret = wget_hash(dig, tmp, nbytes))) {
					error_printf(_("%s: Hash update failed: %s\n"), __func__, wget_strerror(ret));
					return ret;
				}

				if (nbytes <= length)
					length -= nbytes;
				else
					length = 0;
			}

			if ((ret = wget_hash_deinit(&dig, digest))) {
				error_printf(_("%s: Hash finalization failed: %s\n"), __func__, wget_strerror(ret));
				return ret;
			}

			if (nbytes < 0) {
				error_printf(_("%s: Failed to read %llu bytes\n"), __func__, (unsigned long long)length);
				return WGET_E_IO;
			}

			wget_memtohex(digest, digestlen, digest_hex, digest_hex_size);
			ret = WGET_E_SUCCESS;
#ifdef HAVE_MMAP
		}
#endif
	}

	return ret;
}

/**
 * \param[in] hashname Name of the hashing algorithm. See wget_hash_get_algorithm()
 * \param[in] fname Target file name
 * \param[out] digest_hex Caller-supplied buffer that will contain the resulting hex string
 * \param[in] digest_hex_size Length of \p digest_hex
 * \param[in] offset File offset to start hashing at
 * \param[in] length Number of bytes to hash, starting from \p offset.  Zero will hash up to the end of the file
 * \return 0 on success or -1 in case of failure
 *
 * Compute the hash of the contents of the target file starting from \p offset and up to \p length bytes
 * and return its hex representation.
 *
 * This function will encode the resulting hash in a string of hex digits, and
 * place that string in the user-supplied buffer \p digest_hex.
 */
int wget_hash_file_offset(const char *hashname, const char *fname, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length)
{
	int fd, ret;

	if ((fd = open(fname, O_RDONLY|O_BINARY)) == -1) {
		if (digest_hex_size)
			*digest_hex=0;
		return 0;
	}

	ret = wget_hash_file_fd(hashname, fd, digest_hex, digest_hex_size, offset, length);
	close(fd);

	return ret;
}

/**
 * \param[in] hashname Name of the hashing algorithm. See wget_hash_get_algorithm()
 * \param[in] fname Target file name
 * \param[out] digest_hex Caller-supplied buffer that will contain the resulting hex string
 * \param[in] digest_hex_size Length of \p digest_hex
 * \return 0 on success or -1 in case of failure
 *
 * Compute the hash of the contents of the target file and return its hex representation.
 *
 * This function will encode the resulting hash in a string of hex digits, and
 * place that string in the user-supplied buffer \p digest_hex.
 */
int wget_hash_file(const char *hashname, const char *fname, char *digest_hex, size_t digest_hex_size)
{
	return wget_hash_file_offset(hashname, fname, digest_hex, digest_hex_size, 0, 0);
}

/**@}*/
