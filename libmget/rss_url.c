/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * Extracting URLs from RSS feeds (http://cyber.law.harvard.edu/rss/rss.html)
 *
 * Changelog
 * 21.12.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libmget.h>
#include "private.h"

struct rss_context {
	mget_vector_t
		*urls;
};

static void _rss_get_url(void *context, int flags, const char *dir, const char *attr G_GNUC_MGET_UNUSED, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	struct rss_context *ctx = context;
	mget_string_t url;

	if (!val || !len)
		return;

	url.p = NULL;

	if ((flags & XML_FLG_ATTRIBUTE)) {
		if (!strcasecmp(attr, "url") || !strcasecmp(attr, "href")
			|| !strcasecmp(attr, "src") || !strcasecmp(attr, "domain")
			|| !strcasecmp(attr, "xmlns") || !strncasecmp(attr, "xmlns:", 6))
		{
			for (;len && isspace(*val); val++, len--); // skip leading spaces
			for (;len && isspace(val[len - 1]); len--);  // skip trailing spaces

			url.p = val;
			url.len = len;

			if (!ctx->urls)
				ctx->urls = mget_vector_create(32, -2, NULL);

			mget_vector_add(ctx->urls, &url, sizeof(url));
		}
	}
	else if ((flags & XML_FLG_CONTENT)) {
		const char *elem = strrchr(dir, '/');

		if (elem) {
			elem++;

			if (!strcasecmp(elem, "guid") || !strcasecmp(elem, "link")
				 || !strcasecmp(elem, "comments") || !strcasecmp(elem, "docs"))
			{
				for (;len && isspace(*val); val++, len--); // skip leading spaces
				for (;len && isspace(val[len - 1]); len--);  // skip trailing spaces

				// debug_printf("#2 %02X %s %s '%.*s' %zd\n", flags, dir, attr, (int) len, val, len);

				url.p = val;
				url.len = len;

				if (!ctx->urls)
					ctx->urls = mget_vector_create(32, -2, NULL);

				mget_vector_add(ctx->urls, &url, sizeof(url));
			}
		}
	}
}

void mget_rss_get_urls_inline(const char *rss, mget_vector_t **urls)
{
	struct rss_context context = { .urls = NULL };

	mget_xml_parse_buffer(rss, _rss_get_url, &context, XML_HINT_REMOVE_EMPTY_CONTENT);

	*urls = context.urls;
}
