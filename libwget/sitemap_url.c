/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Extracting URLs from Sitemap (XML)
 *
 * Changelog
 * 14.12.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libwget.h>
#include "private.h"

struct sitemap_context {
	wget_vector_t
		*sitemap_urls,
		*urls;
};

static void _sitemap_get_url(void *context, int flags, const char *dir, const char *attr G_GNUC_WGET_UNUSED, const char *val, size_t len, size_t pos G_GNUC_WGET_UNUSED)
{
	struct sitemap_context *ctx = context;
	wget_string_t url;
	int type = 0;

	if ((flags & XML_FLG_CONTENT) && len) {
		if (!wget_strcasecmp_ascii(dir, "/sitemapindex/sitemap/loc"))
			type = 1;
		else if (!wget_strcasecmp_ascii(dir, "/urlset/url/loc"))
			type = 2;

		if (type) {
			for (;len && isspace(*val); val++, len--); // skip leading spaces
			for (;len && isspace(val[len - 1]); len--);  // skip trailing spaces

			// info_printf("%02X %s %s '%.*s' %zd %zd\n", flags, dir, attr, (int) len, val, len, pos);
			url.p = val;
			url.len = len;

			if (type == 1) {
				if (!ctx->sitemap_urls)
					ctx->sitemap_urls = wget_vector_create(32, -2, NULL);

				wget_vector_add(ctx->sitemap_urls, &url, sizeof(url));
			} else {
				if (!ctx->urls)
					ctx->urls = wget_vector_create(32, -2, NULL);

				wget_vector_add(ctx->urls, &url, sizeof(url));

			}
		}
	}
}

void wget_sitemap_get_urls_inline(const char *sitemap, wget_vector_t **urls, wget_vector_t **sitemap_urls)
{
	struct sitemap_context context = { .urls = NULL, .sitemap_urls = NULL };

	wget_xml_parse_buffer(sitemap, _sitemap_get_url, &context, XML_HINT_REMOVE_EMPTY_CONTENT);

	*urls = context.urls;
	*sitemap_urls = context.sitemap_urls;
}
