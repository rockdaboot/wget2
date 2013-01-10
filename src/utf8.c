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
 * utf-8 conversion routines
 *
 * Changelog
 * 10.12.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <iconv.h>

#include <libmget.h>

#include "utils.h"
#include "log.h"
#include "utf8.h"

char *str_to_utf8(const char *src, const char *encoding)
{
	const char *p;

	if (!src)
		return NULL;

	// see if conversion is needed
	for (p = src; *p > 0; p++);
	if (!*p) return NULL;

	if (!encoding)
		encoding = "iso-8859-1"; // default character-set for most browsers

	if (strcasecmp(encoding, "utf-8")) {
		char *dst = NULL;

		// host needs encoding to utf-8
		iconv_t cd=iconv_open("utf-8", encoding);

		if (cd != (iconv_t)-1) {
			char *tmp = (char *)src; // iconv won't change where src points to, but changes tmp itself
			size_t tmp_len = strlen(src);
			size_t utf_len = tmp_len * 6, utf_len_tmp = utf_len;
			char *utf = xmalloc(utf_len + 1), *utf_tmp = utf;

			if (iconv(cd, &tmp, &tmp_len, &utf_tmp, &utf_len_tmp) != (size_t)-1) {
				dst = strndup(utf, utf_len - utf_len_tmp);
				debug_printf("converted '%s' (%s) -> '%s' (utf-8)\n", src, encoding, dst);
			} else
				error_printf(_("Failed to convert %s string into utf-8 (%d)\n"), encoding, errno);

			xfree(utf);
			iconv_close(cd);
		} else
			error_printf(_("Failed to prepare encoding %s into utf-8 (%d)\n"), encoding, errno);

		return dst;
	} else
		return strdup(src);
}
