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
 * Higher level CSS parsing routines
 *
 * Changelog
 * 15.01.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libmget.h>
#include "private.h"

typedef struct {
	const char
		**encoding;
	mget_vector_t
		*uris;
} _CSS_CONTEXT;

static void _free_url(MGET_PARSED_URL *url)
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
		debug_printf(_("URI content encoding = '%.*s'\n"), (int)len, encoding);
		*ctx->encoding = strndup(encoding, len);
	}
}

// Callback function, called from CSS parser for each URI found.
static void _css_get_url(void *context, const char *url, size_t len, size_t pos)
{
	_CSS_CONTEXT *ctx = context;
	MGET_PARSED_URL parsed_url = { .len = len, .pos = pos, .url = strndup(url, len), .abs_url = NULL };

	if (!ctx->uris) {
		ctx->uris = mget_vector_create(16, -2, NULL);
		mget_vector_set_destructor(ctx->uris, (void(*)(void *))_free_url);
	}

	mget_vector_add(ctx->uris, &parsed_url, sizeof(parsed_url));
}

static void _urls_to_absolute(mget_vector_t *urls, mget_iri_t *base)
{
	if (base && urls) {
		mget_buffer_t buf;
		mget_buffer_init(&buf, NULL, 1024);

		for (int it = 0; it < mget_vector_size(urls); it++) {
			MGET_PARSED_URL *url = mget_vector_get(urls, it);

			if (mget_iri_relative_to_abs(base, url->url, url->len, &buf))
				url->abs_url = strndup(buf.data, buf.length + 1);
			else
				error_printf("Cannot resolve relative URI '%s'\n", url->url);
		}

		mget_buffer_deinit(&buf);
	}
}

mget_vector_t *mget_css_get_urls(const char *css, mget_iri_t *base, const char **encoding)
{
	_CSS_CONTEXT context = { .encoding = encoding };

	mget_css_parse_buffer(css, _css_get_url, encoding ? _css_get_encoding : NULL, &context);
	_urls_to_absolute(context.uris, base);

	return context.uris;
}

mget_vector_t *mget_css_get_urls_from_localfile(const char *fname, mget_iri_t *base, const char **encoding)
{
	_CSS_CONTEXT context = { .encoding = encoding };

	mget_css_parse_file(fname, _css_get_url, encoding ? _css_get_encoding : NULL, &context);
	_urls_to_absolute(context.uris, base);

	return context.uris;
}
