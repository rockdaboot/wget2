/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015 Free Software Foundation, Inc.
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
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
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
#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif
#ifdef HAVE_MMAP
# include <sys/mman.h>
#endif

#include <libwget.h>
#include <private.h>

// Interfaces and types inspired by GnuTLS since it was my first used digest/hash interface

wget_digest_algorithm_t
wget_hash_get_algorithm (const char *name)
{
  if (name)
    {
      if (*name == 's' || *name == 'S')
        {
          if (!wget_strcasecmp_ascii (name, "sha-1")
              || !wget_strcasecmp_ascii (name, "sha1"))
            return WGET_DIGTYPE_SHA1;
          else if (!wget_strcasecmp_ascii (name, "sha-256")
                   || !wget_strcasecmp_ascii (name, "sha256"))
            return WGET_DIGTYPE_SHA256;
          else if (!wget_strcasecmp_ascii (name, "sha-512")
                   || !wget_strcasecmp_ascii (name, "sha512"))
            return WGET_DIGTYPE_SHA512;
          else if (!wget_strcasecmp_ascii (name, "sha-224")
                   || !wget_strcasecmp_ascii (name, "sha224"))
            return WGET_DIGTYPE_SHA224;
          else if (!wget_strcasecmp_ascii (name, "sha-384")
                   || !wget_strcasecmp_ascii (name, "sha384"))
            return WGET_DIGTYPE_SHA384;
        }
      else if (!wget_strcasecmp_ascii (name, "md5"))
        return WGET_DIGTYPE_MD5;
      else if (!wget_strcasecmp_ascii (name, "md2"))
        return WGET_DIGTYPE_MD2;
      else if (!wget_strcasecmp_ascii (name, "rmd160"))
        return WGET_DIGTYPE_RMD160;
    }

  error_printf (_("Unknown hash type '%s'\n"), name);
  return WGET_DIGTYPE_UNKNOWN;
}

#if defined(WITH_GNUTLS) && !defined(WITH_LIBNETTLE)
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>

struct _wget_hash_hd_st
{
  gnutls_hash_hd_t dig;
};

static const gnutls_digest_algorithm_t _gnutls_algorithm[] = {
  [WGET_DIGTYPE_UNKNOWN] = GNUTLS_DIG_UNKNOWN,
  [WGET_DIGTYPE_MD2] = GNUTLS_DIG_MD2,
  [WGET_DIGTYPE_MD5] = GNUTLS_DIG_MD5,
  [WGET_DIGTYPE_RMD160] = GNUTLS_DIG_RMD160,
  [WGET_DIGTYPE_SHA1] = GNUTLS_DIG_SHA1,
  [WGET_DIGTYPE_SHA224] = GNUTLS_DIG_SHA224,
  [WGET_DIGTYPE_SHA256] = GNUTLS_DIG_SHA256,
  [WGET_DIGTYPE_SHA384] = GNUTLS_DIG_SHA384,
  [WGET_DIGTYPE_SHA512] = GNUTLS_DIG_SHA512
};

int
wget_hash_fast (wget_digest_algorithm_t algorithm, const void *text,
                size_t textlen, void *digest)
{
  if ((unsigned) algorithm < countof (_gnutls_algorithm))
    return gnutls_hash_fast (_gnutls_algorithm[algorithm], text, textlen,
                             digest);
  else
    return -1;
}

int
wget_hash_get_len (wget_digest_algorithm_t algorithm)
{
  if ((unsigned) algorithm < countof (_gnutls_algorithm))
    return gnutls_hash_get_len (_gnutls_algorithm[algorithm]);
  else
    return 0;
}

int
wget_hash_init (wget_hash_hd_t * dig, wget_digest_algorithm_t algorithm)
{
  if ((unsigned) algorithm < countof (_gnutls_algorithm))
    return gnutls_hash_init (&dig->dig,
                             _gnutls_algorithm[algorithm]) == 0 ? 0 : -1;
  else
    return -1;
}

int
wget_hash (wget_hash_hd_t * handle, const void *text, size_t textlen)
{
  return gnutls_hash (handle->dig, text, textlen) == 0 ? 0 : -1;
}

void
wget_hash_deinit (wget_hash_hd_t * handle, void *digest)
{
  gnutls_hash_deinit (handle->dig, digest);
}
#elif defined (WITH_LIBNETTLE)
# include <nettle/nettle-meta.h>

struct _wget_hash_hd_st
{
  const struct nettle_hash *hash;
  void *context;
};

static const struct nettle_hash *_nettle_algorithm[] = {
  [WGET_DIGTYPE_UNKNOWN] = NULL,
  [WGET_DIGTYPE_MD2] = &nettle_md2,
  [WGET_DIGTYPE_MD5] = &nettle_md5,
# ifdef RIPEMD160_DIGEST_SIZE
  [WGET_DIGTYPE_RMD160] = &nettle_ripemd160,
# endif
  [WGET_DIGTYPE_SHA1] = &nettle_sha1,
# ifdef SHA224_DIGEST_SIZE
  [WGET_DIGTYPE_SHA224] = &nettle_sha224,
# endif
# ifdef SHA256_DIGEST_SIZE
  [WGET_DIGTYPE_SHA256] = &nettle_sha256,
# endif
# ifdef SHA384_DIGEST_SIZE
  [WGET_DIGTYPE_SHA384] = &nettle_sha384,
# endif
# ifdef SHA512_DIGEST_SIZE
  [WGET_DIGTYPE_SHA512] = &nettle_sha512,
# endif
};

int
wget_hash_fast (wget_digest_algorithm_t algorithm, const void *text,
                size_t textlen, void *digest)
{
  wget_hash_hd_t dig;

  if (wget_hash_init (&dig, algorithm) == 0)
    {
      if (wget_hash (&dig, text, textlen) == 0)
        {
          wget_hash_deinit (&dig, digest);
          return 0;
        }
    }

  return -1;
}

int
wget_hash_get_len (wget_digest_algorithm_t algorithm)
{
  if (algorithm >= 0 && algorithm < countof (_nettle_algorithm))
    return _nettle_algorithm[algorithm]->digest_size;
  else
    return 0;
}

int
wget_hash_init (wget_hash_hd_t * dig, wget_digest_algorithm_t algorithm)
{
  if (algorithm >= 0 && algorithm < countof (_nettle_algorithm))
    {
      dig->hash = _nettle_algorithm[algorithm];
      dig->context = xmalloc (dig->hash->context_size);
      dig->hash->init (dig->context);
      return 0;
    }
  else
    {
      dig->hash = NULL;
      dig->context = NULL;
      return -1;
    }
}

int
wget_hash (wget_hash_hd_t * handle, const void *text, size_t textlen)
{
  handle->hash->update (handle->context, textlen, text);
  return 0;
}

void
wget_hash_deinit (wget_hash_hd_t * handle, void *digest)
{
  handle->hash->update (handle->context, handle->hash->digest_size, digest);
  xfree (handle->context);
}
#else // empty functions which return error
# define _U G_GNUC_WGET_UNUSED

struct _wget_hash_hd_st
{
  char dig;
};

int
wget_hash_fast (_U wget_digest_algorithm_t algorithm, _U const void *text,
                _U size_t textlen, _U void *digest)
{
  return -1;
}

int
wget_hash_get_len (_U wget_digest_algorithm_t algorithm)
{
  return 0;
}

int
wget_hash_init (_U wget_hash_hd_t * dig, _U wget_digest_algorithm_t algorithm)
{
  return -1;
}

int
wget_hash (_U wget_hash_hd_t * handle, _U const void *text, _U size_t textlen)
{
  return -1;
}

void
wget_hash_deinit (_U wget_hash_hd_t * handle, _U void *digest)
{
}

# undef _U
#endif

// return 0 = OK, -1 = failed
int
wget_hash_file_fd (const char *type, int fd, char *digest_hex,
                   size_t digest_hex_size, off_t offset, off_t length)
{
  wget_digest_algorithm_t algorithm;
  int ret = -1;
  struct stat st;

  if (digest_hex_size)
    *digest_hex = 0;

  if (fd == -1 || fstat (fd, &st) != 0)
    return -1;

  if (length == 0)
    length = st.st_size;

  if (offset + length > st.st_size)
    return -1;

  debug_printf ("%s hashing pos %llu, length %llu...\n", type,
                (unsigned long long) offset, (unsigned long long) length);

  if ((algorithm = wget_hash_get_algorithm (type)) != WGET_DIGTYPE_UNKNOWN)
    {
      unsigned char digest[wget_hash_get_len (algorithm)];
      char *buf;

#ifdef HAVE_MMAP
      buf = mmap (NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);

      if (buf != MAP_FAILED)
        {
          if (wget_hash_fast (algorithm, buf, length, digest) == 0)
            {
              wget_memtohex (digest, sizeof (digest), digest_hex,
                             digest_hex_size);
              ret = 0;
            }
          munmap (buf, length);
        }
      else
        {
#endif
          // Fallback to read
          ssize_t nbytes = 0;
          wget_hash_hd_t dig;

          buf = alloca (65536);

          wget_hash_init (&dig, algorithm);
          while (length > 0 && (nbytes = read (fd, buf, 65536)) > 0)
            {
              wget_hash (&dig, buf, nbytes);

              if (nbytes <= length)
                length -= nbytes;
              else
                length = 0;
            }
          wget_hash_deinit (&dig, digest);

          if (nbytes < 0)
            {
              error_printf ("%s: Failed to read %llu bytes\n", __func__,
                            (unsigned long long) length);
              close (fd);
              return -1;
            }

          wget_memtohex (digest, sizeof (digest), digest_hex,
                         digest_hex_size);
          ret = 0;
#ifdef HAVE_MMAP
        }
#endif
    }

  return ret;
}

int
wget_hash_file_offset (const char *type, const char *fname, char *digest_hex,
                       size_t digest_hex_size, off_t offset, off_t length)
{
  int fd, ret;

  if ((fd = open (fname, O_RDONLY)) == -1)
    {
      if (digest_hex_size)
        *digest_hex = 0;
      return 0;
    }

  ret =
    wget_hash_file_fd (type, fd, digest_hex, digest_hex_size, offset, length);
  close (fd);

  return ret;
}

int
wget_hash_file (const char *type, const char *fname, char *digest_hex,
                size_t digest_hex_size)
{
  return wget_hash_file_offset (type, fname, digest_hex, digest_hex_size, 0,
                                0);
}
