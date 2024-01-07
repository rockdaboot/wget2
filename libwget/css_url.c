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
 * Higher level CSS parsing routines
 *
 * Changelog
 * 15.01.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <wget.h>
#include "private.h"

typedef struct {
	const char
		**encoding;
	wget_vector
		*uris;
} css_context;

static void url_free(void *url)
{
	wget_css_parsed_url *u = url;

	xfree(u->url);
	xfree(u->abs_url);
	xfree(u);
}

// Callback function, called from CSS parser for each @charset found.
static void get_encoding(void *context, const char *encoding, size_t len)
{
	css_context *ctx = context;

	// take only the first @charset rule
	if (!*ctx->encoding) {
		*ctx->encoding = wget_strmemdup(encoding, len);
		debug_printf("URI content encoding = '%s'\n", *ctx->encoding);
	}
}

// Callback function, called from CSS parser for each URI found.
static void get_url(void *context, const char *url, size_t len, size_t pos)
{
	css_context *ctx = context;
	wget_css_parsed_url *parsed_url;

	if (!(parsed_url = wget_calloc(1, sizeof(wget_css_parsed_url))))
		return;

	if (!(parsed_url->url = wget_strmemdup(url, len))) {
		xfree(parsed_url);
		return;
	}

	parsed_url->len = len;
	parsed_url->pos = pos;

	if (!ctx->uris) {
		ctx->uris = wget_vector_create(16, NULL);
		wget_vector_set_destructor(ctx->uris, url_free);
	}

	wget_vector_add(ctx->uris, parsed_url);
}

static void urls_to_absolute(wget_vector *urls, wget_iri *base)
{
	if (base && urls) {
		wget_buffer buf;
		wget_buffer_init(&buf, NULL, 1024);

		for (int it = 0; it < wget_vector_size(urls); it++) {
			wget_css_parsed_url *url = wget_vector_get(urls, it);
			assert(url != NULL);

			if (wget_iri_relative_to_abs(base, url->url, url->len, &buf))
				url->abs_url = wget_strmemdup(buf.data, buf.length);
			else
				error_printf(_("Cannot resolve relative URI '%s'\n"), url->url);
		}

		wget_buffer_deinit(&buf);
	}
}

wget_vector *wget_css_get_urls(const char *css, size_t len, wget_iri *base, const char **encoding)
{
	css_context context = { .encoding = encoding };

	wget_css_parse_buffer(css, len, get_url, encoding ? get_encoding : NULL, &context);
	urls_to_absolute(context.uris, base);

	return context.uris;
}

wget_vector *wget_css_get_urls_from_localfile(const char *fname, wget_iri *base, const char **encoding)
{
	css_context context = { .encoding = encoding };

	wget_css_parse_file(fname, get_url, encoding ? get_encoding : NULL, &context);
	urls_to_absolute(context.uris, base);

	return context.uris;
}
