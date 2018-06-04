/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015-2018 Free Software Foundation, Inc.
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

#include <wget.h>
#include "private.h"

typedef struct {
	const char
		**encoding;
	wget_vector_t
		*uris;
} _CSS_CONTEXT;

static void _free_url(wget_css_parsed_url_t *url)
{
	xfree(url->url);
	xfree(url->abs_url);
}

// Callback function, called from CSS parser for each @charset found.
static void _css_get_encoding(void *context, const char *encoding, size_t len)
{
	_CSS_CONTEXT *ctx = context;

	// take only the first @charset rule
	if (!*ctx->encoding) {
		*ctx->encoding = wget_strmemdup(encoding, len);
		debug_printf("URI content encoding = '%s'\n", *ctx->encoding);
	}
}

// Callback function, called from CSS parser for each URI found.
static void _css_get_url(void *context, const char *url, size_t len, size_t pos)
{
	_CSS_CONTEXT *ctx = context;
	wget_css_parsed_url_t parsed_url = { .len = len, .pos = pos, .url = wget_strmemdup(url, len), .abs_url = NULL };

	if (!ctx->uris) {
		ctx->uris = wget_vector_create(16, NULL);
		wget_vector_set_destructor(ctx->uris, (wget_vector_destructor_t)_free_url);
	}

	wget_vector_add(ctx->uris, &parsed_url, sizeof(parsed_url));
}

static void _urls_to_absolute(wget_vector_t *urls, wget_iri_t *base)
{
	if (base && urls) {
		wget_buffer_t buf;
		wget_buffer_init(&buf, NULL, 1024);

		for (int it = 0; it < wget_vector_size(urls); it++) {
			wget_css_parsed_url_t *url = wget_vector_get(urls, it);

			if (wget_iri_relative_to_abs(base, url->url, url->len, &buf))
				url->abs_url = wget_strmemdup(buf.data, buf.length);
			else
				error_printf(_("Cannot resolve relative URI '%s'\n"), url->url);
		}

		wget_buffer_deinit(&buf);
	}
}

wget_vector_t *wget_css_get_urls(const char *css, size_t len, wget_iri_t *base, const char **encoding)
{
	_CSS_CONTEXT context = { .encoding = encoding };

	wget_css_parse_buffer(css, len, _css_get_url, encoding ? _css_get_encoding : NULL, &context);
	_urls_to_absolute(context.uris, base);

	return context.uris;
}

wget_vector_t *wget_css_get_urls_from_localfile(const char *fname, wget_iri_t *base, const char **encoding)
{
	_CSS_CONTEXT context = { .encoding = encoding };

	wget_css_parse_file(fname, _css_get_url, encoding ? _css_get_encoding : NULL, &context);
	_urls_to_absolute(context.uris, base);

	return context.uris;
}
