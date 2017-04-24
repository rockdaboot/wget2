/*
 * Copyright(c) 2012-2015 Tim Ruehsen
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
 * a collection of charset encoding routines
 *
 * Changelog
 * 02.10.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <strings.h>
#include <errno.h>

#ifdef HAVE_ICONV
# include <iconv.h>
#endif

#include <langinfo.h>

#if defined(HAVE_IDN2_H) && defined(WITH_LIBIDN2)
# include <idn2.h>
# if IDN2_VERSION_NUMBER < 0x00140000
#  if defined(HAVE_UNICASE_H) && defined(WITH_LIBUNISTRING)
#   include <unicase.h>
#   include <unistr.h>
#  endif
# endif
#elif defined(HAVE_IDNA_H) && defined(WITH_LIBIDN)
# include <idna.h>
# ifdef _WIN32
#   include <idn-free.h>
# endif
#elif defined(HAVE_IDN_IDNA_H) && defined(WITH_LIBIDN)
// OpenSolaris uses the idn subdir
# include <idn/idna.h>
#endif

#include <wget.h>
#include "private.h"

const char *wget_local_charset_encoding(void)
{
	const char *encoding = nl_langinfo(CODESET);

	if (encoding && *encoding)
		return wget_strdup(encoding);

	return wget_strdup("ASCII");
}

// void *wget_memiconv(const void *src, size_t length, const char *src_encoding, const char *dst_encoding)
int wget_memiconv(const char *src_encoding, const void *src, size_t srclen, const char *dst_encoding, char **out, size_t *outlen)
{
	if (!src)
		return -1;

#ifdef HAVE_ICONV
	if (!src_encoding)
		src_encoding = "iso-8859-1"; // default character-set for most browsers
	if (!dst_encoding)
		dst_encoding = "iso-8859-1"; // default character-set for most browsers

	int ret = -1;

	if (wget_strcasecmp_ascii(src_encoding, dst_encoding)) {
		iconv_t cd = iconv_open(dst_encoding, src_encoding);

		if (cd != (iconv_t)-1) {
			char *tmp = (char *) src; // iconv won't change where src points to, but changes tmp itself
			size_t tmp_len = srclen;
			size_t dst_len = tmp_len * 6, dst_len_tmp = dst_len;
			char *dst = xmalloc(dst_len + 1), *dst_tmp = dst;

			errno = 0;
			if (iconv(cd, (ICONV_CONST char **)&tmp, &tmp_len, &dst_tmp, &dst_len_tmp) == 0
				&& iconv(cd, NULL, NULL, &dst_tmp, &dst_len_tmp) == 0)
			{
				debug_printf("transcoded %zu bytes from '%s' to '%s'\n", srclen, src_encoding, dst_encoding);
				if (out) {
					*out = xrealloc(dst, dst_len - dst_len_tmp + 1);
					(*out)[dst_len - dst_len_tmp] = 0;
				} else
					xfree(dst);
				if (outlen)
					*outlen = dst_len - dst_len_tmp;
				ret = 0; // return OK
			} else {
				// erno == 0 means some codepoints were encoded non-reversible, treat as error
				error_printf(_("Failed to transcode '%s' string into '%s' (%d)\n"), src_encoding, dst_encoding, errno);
				xfree(dst);
				if (out)
					*out = NULL;
				if (outlen)
					*outlen = 0;
			}

			iconv_close(cd);
		} else
			error_printf(_("Failed to prepare transcoding '%s' into '%s' (%d)\n"), src_encoding, dst_encoding, errno);

		return ret;
	}
#endif

	if (out)
		*out = wget_strmemdup(src, srclen);
	if (outlen)
		*outlen = srclen;

	return 0;
}

// src must be a ASCII compatible C string
char *wget_striconv(const char *src, const char *src_encoding, const char *dst_encoding)
{
	if (!src)
		return NULL;

	char *dst;
	if (wget_memiconv(src_encoding, src, strlen(src), dst_encoding, &dst, NULL))
		return NULL;

	return dst;
}

int wget_str_needs_encoding(const char *s)
{
	while (*s && (*s & ~0x7f) == 0) s++;

	return !!*s;
}

int wget_str_is_valid_utf8(const char *utf8)
{
	const unsigned char *s = (const unsigned char *) utf8;

	while (*s) {
		if ((*s & 0x80) == 0) /* 0xxxxxxx ASCII char */
			s++;
		else if ((*s & 0xE0) == 0xC0) /* 110xxxxx 10xxxxxx */ {
			if ((s[1] & 0xC0) != 0x80)
				return 0;
			s += 2;
		} else if ((*s & 0xF0) == 0xE0) /* 1110xxxx 10xxxxxx 10xxxxxx */ {
			if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80)
				return 0;
			s += 3;
		} else if ((*s & 0xF8) == 0xF0) /* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */ {
			if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80)
				return 0;
			s += 4;
		} else
			return 0;
	}

	return 1;
}

char *wget_str_to_utf8(const char *src, const char *encoding)
{
	return wget_striconv(src, encoding, "utf-8");
}

char *wget_utf8_to_str(const char *src, const char *encoding)
{
	return wget_striconv(src, "utf-8", encoding);
}

#ifdef WITH_LIBIDN
/*
 * Work around a libidn <= 1.30 vulnerability.
 *
 * The function checks for a valid UTF-8 character sequence before
 * passing it to idna_to_ascii_8z().
 *
 * [1] https://lists.gnu.org/archive/html/help-libidn/2015-05/msg00002.html
 * [2] https://lists.gnu.org/archive/html/bug-wget/2015-06/msg00002.html
 * [3] https://curl.haxx.se/mail/lib-2015-06/0143.html
 */
static int G_GNUC_WGET_PURE _utf8_is_valid(const char *utf8)
{
	const unsigned char *s = (const unsigned char *) utf8;

	while (*s) {
		if ((*s & 0x80) == 0) /* 0xxxxxxx ASCII char */
			s++;
		else if ((*s & 0xE0) == 0xC0) /* 110xxxxx 10xxxxxx */ {
			if ((s[1] & 0xC0) != 0x80)
				return 0;
			s += 2;
		} else if ((*s & 0xF0) == 0xE0) /* 1110xxxx 10xxxxxx 10xxxxxx */ {
			if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80)
				return 0;
			s += 3;
		} else if ((*s & 0xF8) == 0xF0) /* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */ {
			if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80)
				return 0;
			s += 4;
		} else
			return 0;
	}

	return 1;
}
#endif

const char *wget_str_to_ascii(const char *src)
{
#ifdef WITH_LIBIDN2
	if (wget_str_needs_encoding(src)) {
		char *asc = NULL;
		int rc;
# if defined WITH_LIBUNISTRING && IDN2_VERSION_NUMBER < 0x00140000
		uint8_t *lower, resbuf[256];
		size_t len = sizeof(resbuf) - 1; // leave space for additional \0 byte

		// we need a conversion to lowercase
		lower = u8_tolower((uint8_t *)src, u8_strlen((uint8_t *)src), 0, UNINORM_NFKC, resbuf, &len);
		if (!lower) {
			error_printf("u8_tolower(%s) failed (%d)\n", src, errno);
			return src;
		}

		// u8_tolower() does not terminate the result string
		if (lower == resbuf) {
			lower[len]=0;
		} else {
			uint8_t *tmp = lower;
			lower = (uint8_t *)wget_strmemdup((char *)lower, len);
			xfree(tmp);
		}

		if ((rc = idn2_lookup_u8(lower, (uint8_t **)&asc, 0)) == IDN2_OK) {
			debug_printf("idn2 '%s' -> '%s'\n", src, asc);
			src = asc;
		} else
			error_printf(_("toASCII(%s) failed (%d): %s\n"), lower, rc, idn2_strerror(rc));

		if (lower != resbuf)
			xfree(lower);
# else
#  if IDN2_VERSION_NUMBER < 0x00140000
		if ((rc = idn2_lookup_u8((uint8_t *)src, (uint8_t **)&asc, 0)) == IDN2_OK)
#  else
		if ((rc = idn2_lookup_u8((uint8_t *)src, (uint8_t **)&asc, IDN2_NONTRANSITIONAL)) != IDN2_OK)
			rc = idn2_lookup_u8((uint8_t *)src, (uint8_t **)&asc, IDN2_TRANSITIONAL);
		if (rc == IDN2_OK)
#  endif
		{
			debug_printf("idn2 '%s' -> '%s'\n", src, asc);
#  ifdef _WIN32
				src = wget_strdup(asc);
				idn2_free(asc);
#  else
				src = asc;
#  endif
		} else
			error_printf(_("toASCII(%s) failed (%d): %s\n"), src, rc, idn2_strerror(rc));
# endif
	}
#elif defined WITH_LIBIDN
	if (wget_str_needs_encoding(src)) {
		char *asc = NULL;
		int rc;

		if (_utf8_is_valid(src)) {
			// idna_to_ascii_8z() automatically converts UTF-8 to lowercase

			if ((rc = idna_to_ascii_8z(src, &asc, IDNA_USE_STD3_ASCII_RULES)) == IDNA_SUCCESS) {
				// debug_printf("toASCII '%s' -> '%s'\n", src, asc);
# ifdef _WIN32
				src = wget_strdup(asc);
				idn_free(asc);
# else
				src = asc;
# endif
			} else
				error_printf(_("toASCII failed (%d): %s\n"), rc, idna_strerror(rc));
		}
		else
			error_printf(_("Invalid UTF-8 sequence not converted: '%s'\n"), src);
	}
#else
	if (wget_str_needs_encoding(src)) {
		error_printf(_("toASCII not available: '%s'\n"), src);
	}
#endif

	return src;
}
