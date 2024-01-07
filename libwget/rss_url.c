/*
 * Copyright (c) 2013 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Extracting URLs from RSS feeds (https://cyber.harvard.edu/rss/rss.html)
 *
 * Changelog
 * 21.12.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>

#include <wget.h>
#include "private.h"

struct rss_context {
	wget_vector
		*urls;
};

static void rss_get_url(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos WGET_GCC_UNUSED)
{
	struct rss_context *ctx = context;
	wget_string * url;

	if (!val || !len)
		return;

	if ((flags & XML_FLG_ATTRIBUTE)) {
		if (!wget_strcasecmp_ascii(attr, "url") || !wget_strcasecmp_ascii(attr, "href")
			|| !wget_strcasecmp_ascii(attr, "src") || !wget_strcasecmp_ascii(attr, "domain")
			|| !wget_strcasecmp_ascii(attr, "xmlns") || !wget_strncasecmp_ascii(attr, "xmlns:", 6))
		{
			for (;len && c_isspace(*val); val++, len--); // skip leading spaces
			for (;len && c_isspace(val[len - 1]); len--);  // skip trailing spaces

			if (!(url = wget_malloc(sizeof(wget_string))))
				return;

			url->p = val;
			url->len = len;

			if (!ctx->urls)
				ctx->urls = wget_vector_create(32, NULL);

			wget_vector_add(ctx->urls, url);
		}
	}
	else if ((flags & XML_FLG_CONTENT)) {
		const char *elem = strrchr(dir, '/');

		if (elem) {
			elem++;

			if (!wget_strcasecmp_ascii(elem, "guid") || !wget_strcasecmp_ascii(elem, "link")
				 || !wget_strcasecmp_ascii(elem, "comments") || !wget_strcasecmp_ascii(elem, "docs"))
			{
				for (;len && c_isspace(*val); val++, len--); // skip leading spaces
				for (;len && c_isspace(val[len - 1]); len--);  // skip trailing spaces

				// debug_printf("#2 %02X %s %s '%.*s' %zd\n", flags, dir, attr, (int) len, val, len);

				if (!(url = wget_malloc(sizeof(wget_string))))
					return;

				url->p = val;
				url->len = len;

				if (!ctx->urls)
					ctx->urls = wget_vector_create(32, NULL);

				wget_vector_add(ctx->urls, url);
			}
		}
	}
}

void wget_rss_get_urls_inline(const char *rss, wget_vector **urls)
{
	struct rss_context context = { .urls = NULL };

	wget_xml_parse_buffer(rss, rss_get_url, &context, XML_HINT_REMOVE_EMPTY_CONTENT);

	*urls = context.urls;
}
