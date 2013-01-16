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
	MGET_IRI
		*base;
	const char
		**encoding;
	MGET_VECTOR
		*uris;
	mget_buffer_t
		uri_buf;
	char
		encoding_allocated;
} _CSS_CONTEXT;

// Callback function, called from CSS parser for each @charset found.
static void _css_get_encoding(void *context G_GNUC_MGET_UNUSED, const char *encoding, size_t len)
{
	_CSS_CONTEXT *ctx = context;

	// take only the first @charset rule
	if (!*ctx->encoding) {
		info_printf(_("URI content encoding = '%.*s'\n"), (int)len, encoding);
		*ctx->encoding = strndup(encoding, len);
	}
}

// Callback function, called from CSS parser for each URI found.
static void _css_get_url(void *context G_GNUC_MGET_UNUSED, const char *url, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	_CSS_CONTEXT *ctx = context;

	// ignore e.g. href='#'
	if (len > 1 || (len == 1 && *url != '#')) {
		MGET_CSS_URL css_url = { .org_len = len, .pos = pos };

		if (!ctx->base) {
//			mget_info_printf("  %.*s\n", (int)len, url);
			css_url.org_url = strndup(url, len);
			mget_vector_add(ctx->uris, &css_url, sizeof(css_url));
		} else if (mget_iri_relative_to_abs(ctx->base, url, len, &ctx->uri_buf)) {
//			mget_info_printf("  %.*s -> %s\n", (int)len, url, ctx->uri_buf.data);
			css_url.org_url = strndup(url, len);
			css_url.url = strndup(ctx->uri_buf.data, ctx->uri_buf.length + 1);
			mget_vector_add(ctx->uris, &css_url, sizeof(css_url));
		} else {
			error_printf("Cannot resolve relative URI %.*s\n", (int)len, url);
		}
	}
}

MGET_VECTOR *css_get_urls_from_localfile(const char *fname, MGET_IRI *base, const char **encoding)
{
	_CSS_CONTEXT context = { .base = base, .encoding = encoding };

	context.uris = mget_vector_create(32, -2, NULL);
	mget_buffer_init(&context.uri_buf, NULL, 128);

	mget_css_parse_file(fname, _css_get_url, encoding ? _css_get_encoding : NULL, &context);

	mget_buffer_deinit(&context.uri_buf);

	if (context.encoding_allocated)
		xfree(context.encoding);

	return context.uris;
}
