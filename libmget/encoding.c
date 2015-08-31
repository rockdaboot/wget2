/*
 * Copyright(c) 2012-2015 Tim Ruehsen
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

#if defined(HAVE_STRINGPREP_H) && defined(WITH_LIBIDN)
# include <stringprep.h>
#elif defined(HAVE_LANGINFO_H)
# include <langinfo.h>
#endif

#if defined(HAVE_IDN2_H) && defined(WITH_LIBIDN2)
# include <idn2.h>
#elif defined(HAVE_IDNA_H) && defined(WITH_LIBIDN)
# include <idna.h>
#endif

#if defined(HAVE_UNICASE_H) && defined(WITH_LIBUNISTRING)
#include <unicase.h>
#include <unistr.h>
#endif

#include <libmget.h>
#include "private.h"

const char *mget_local_charset_encoding(void)
{
#if defined(HAVE_STRINGPREP_H) && defined(WITH_LIBIDN)
	const char *encoding = stringprep_locale_charset();

	// Solaris: unknown encoding '646' when locale is set to C or POSIX
	if (strcmp(encoding, "646"))
		return strdup(stringprep_locale_charset());
#elif defined(HAVE_NL_LANGINFO)
	const char *encoding = nl_langinfo(CODESET);

	// Solaris: unknown encoding '646' when locale is set to C or POSIX
	if (encoding && *encoding && strcmp(encoding, "646"))
		return strdup(encoding);
#elif defined(_WIN32) || defined(__WIN32__) || defined(_WIN64) || defined(__WIN64__)
	static char buf[16];

	 // GetACP() returns the codepage.
	 snprintf(buf, sizeof(buf), "CP%u", GetACP ());
	 return buf;
#endif
	return strdup("ASCII");
}

char *mget_charset_transcode(const char *src, const char *src_encoding, const char *dst_encoding)
{
	if (!src)
		return NULL;

#ifdef HAVE_ICONV
	if (!src_encoding)
		src_encoding = "iso-8859-1"; // default character-set for most browsers
	if (!dst_encoding)
		dst_encoding = "iso-8859-1"; // default character-set for most browsers

	if (mget_strcasecmp_ascii(src_encoding, dst_encoding)) {
		char *ret = NULL;

		iconv_t cd=iconv_open(dst_encoding, src_encoding);

		if (cd != (iconv_t)-1) {
			char *tmp = (char *) src; // iconv won't change where src points to, but changes tmp itself
			size_t tmp_len = strlen(src);
			size_t dst_len = tmp_len * 6, dst_len_tmp = dst_len;
			char *dst = xmalloc(dst_len + 1), *dst_tmp = dst;

			if (iconv(cd, &tmp, &tmp_len, &dst_tmp, &dst_len_tmp) != (size_t)-1) {
				ret = strndup(dst, dst_len - dst_len_tmp);
				debug_printf("converted '%s' (%s) -> '%s' (%s)\n", src, src_encoding, ret, dst_encoding);
			} else
				error_printf(_("Failed to convert '%s' string into '%s' (%d)\n"), src_encoding, dst_encoding, errno);

			xfree(dst);
			iconv_close(cd);
		} else
			error_printf(_("Failed to prepare encoding '%s' into '%s' (%d)\n"), src_encoding, dst_encoding, errno);

		return ret;
	}
#endif

	return strdup(src);
}

int mget_str_needs_encoding(const char *s)
{
	while (*s && (*s & ~0x7f) == 0) s++;

	return !!*s;
}

int mget_str_is_valid_utf8(const char *utf8)
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

char *mget_str_to_utf8(const char *src, const char *encoding)
{
	return mget_charset_transcode(src, encoding, "utf-8");
}

char *mget_utf8_to_str(const char *src, const char *encoding)
{
	return mget_charset_transcode(src, "utf-8", encoding);
}

#if WITH_LIBIDN
/*
 * Work around a libidn <= 1.30 vulnerability.
 *
 * The function checks for a valid UTF-8 character sequence before
 * passing it to idna_to_ascii_8z().
 *
 * [1] http://lists.gnu.org/archive/html/help-libidn/2015-05/msg00002.html
 * [2] https://lists.gnu.org/archive/html/bug-wget/2015-06/msg00002.html
 * [3] http://curl.haxx.se/mail/lib-2015-06/0143.html
 */
static int _utf8_is_valid(const char *utf8)
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

const char *mget_str_to_ascii(const char *src)
{
#ifdef WITH_LIBIDN2
	if (mget_str_needs_encoding(src)) {
		char *asc = NULL;
		int rc;
#ifdef WITH_LIBUNISTRING
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
			lower = (uint8_t *)strndup((char *)lower, len);
			xfree(tmp);
		}

		if ((rc = idn2_lookup_u8(lower, (uint8_t **)&asc, 0)) == IDN2_OK) {
			debug_printf("idn2 '%s' -> '%s'\n", src, asc);
			src = asc;
		} else
			error_printf(_("toASCII(%s) failed (%d): %s\n"), lower, rc, idn2_strerror(rc));

		if (lower != resbuf)
			xfree(lower);
#else
		if ((rc = idn2_lookup_u8((uint8_t *)src, (uint8_t **)&asc, 0)) == IDN2_OK) {
			debug_printf("idn2 '%s' -> '%s'\n", src, asc);
			src = asc;
		} else
			error_printf(_("toASCII(%s) failed (%d): %s\n"), src, rc, idn2_strerror(rc));
#endif
	}
#elif WITH_LIBIDN
	if (mget_str_needs_encoding(src)) {
		char *asc = NULL;
		int rc;

		if (_utf8_is_valid(src)) {
			// idna_to_ascii_8z() automatically converts UTF-8 to lowercase

			if ((rc = idna_to_ascii_8z(src, &asc, IDNA_USE_STD3_ASCII_RULES)) == IDNA_SUCCESS) {
				// debug_printf("toASCII '%s' -> '%s'\n", src, asc);
				src = asc;
			} else
				error_printf(_("toASCII failed (%d): %s\n"), rc, idna_strerror(rc));
		}
		else
			error_printf(_("Invalid UTF-8 sequence not converted: '%s'\n"), src);
	}
#else
	if (mget_str_needs_encoding(src)) {
		error_printf(_("toASCII not available: '%s'\n"), src);
	}
#endif

	return src;
}
