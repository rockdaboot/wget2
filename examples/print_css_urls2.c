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
 * Advanced example for CSS parsing using libmget
 *
 * Changelog
 * 15.01.2013  Tim Ruehsen  created
 *
 * Demonstrate how to extract URIs from CSS files, converting them to UTF-8
 * if needed, converting relative URIs to absolute.
 *
 * We ignore the BOM (Byte Order Mark) here.
 * BOM see: http://www.w3.org/International/questions/qa-byte-order-mark
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libmget.h>

// use the helper routines provided by libmget
#define info_printf        mget_info_printf
#define error_printf       mget_error_printf
#define error_printf_exit  mget_error_printf_exit

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

struct css_context {
	MGET_IRI
		*base;
	const char
		*encoding;
	mget_buffer_t
		uri_buf;
	char
		encoding_allocated;
};

static void G_GNUC_MGET_NORETURN usage(const char *myname)
{
	error_printf_exit(
		"\nUsage: %s [options] file...\n"\
		"  --base <URI>          Default base for relative URIs, default: http://www.example.com\n"\
		"  --encoding <Encoding> Default file character encoding, default: iso-8859-1\n"\
		"\n"\
		"  Examples:\n"\
		"    %s --base http://www.mydomain.com x.css\n"\
		"    cat x.css | %s --base http://www.mydomain.com -\n"\
		"\n"\
		"  Print URIs as found (without a base):\n"\
		"    %s --base \"\" x.css\n\n",
		myname, myname, myname, myname);
}

// Callback function, called from CSS parser for each @charset found.
static void css_parse_encoding(void *context G_GNUC_MGET_UNUSED, const char *encoding, size_t len)
{
	struct css_context *ctx = context;

	// take only the first @charset rule
	if (!ctx->encoding_allocated && mget_strncasecmp(ctx->encoding, encoding, len)) {
		if (ctx->encoding)
			info_printf("Encoding changed from '%s' to '%.*s'\n", ctx->encoding, (int)len, encoding);
		else
			info_printf("Encoding set to '%.*s'\n", (int)len, encoding);

		ctx->encoding = strndup(encoding, len);
		ctx->encoding_allocated = 1;
	}
}

// Callback function, called from CSS parser for each URI found.
static void css_parse_uri(void *context G_GNUC_MGET_UNUSED, const char *url, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	struct css_context *ctx = context;

	if (len > 1 || (len == 1 && *url != '#')) {
		// ignore e.g. href='#'
		if (!ctx->base) {
			mget_info_printf("  %.*s\n", (int)len, url);
		} else if (mget_iri_relative_to_abs(ctx->base, url, len, &ctx->uri_buf)) {
			mget_info_printf("  %.*s -> %s\n", (int)len, url, ctx->uri_buf.data);
		} else {
			error_printf("Cannot resolve relative URI %.*s\n", (int)len, url);
		}
	}
}

static void css_parse_localfile(const char *fname, MGET_IRI *base, const char *encoding)
{
	struct css_context context = { .base = base, .encoding = encoding };

	mget_buffer_init(&context.uri_buf, NULL, 128);

	mget_css_parse_file(fname, css_parse_uri, css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	mget_buffer_deinit(&context.uri_buf);
}

int main(int argc, const char *const *argv)
{
	// Base URI for converting relative to absolute URIs
	const char *
		base = "http://www.example.com";

	// We assume that base is encoded in the local charset.
	const char *
		local_encoding = mget_local_charset_encoding();

	// parsed 'base'
	MGET_IRI
		*base_uri;

	// Character encoding of CSS file content
	// An HTTP response may contain the encoding in the Content-Type header,
	// but if
	// see http://stackoverflow.com/questions/2526033/why-specify-charset-utf-8-in-your-css-file
	const char *
		css_encoding = NULL;

	int
		argpos;

	// We want the libmget error messages be printed to STDERR.
	// From here on, we can call mget_error_printf, etc.
	mget_logger_set_stream(mget_get_logger(MGET_LOGGER_ERROR), stderr);

	// We want the libmget info messages be printed to STDOUT.
	// From here on, we can call mget_info_printf, etc.
	mget_logger_set_stream(mget_get_logger(MGET_LOGGER_INFO), stdout);

	// parse options
	for (argpos = 1; argpos < argc; argpos++) {
		if (!strcmp(argv[argpos], "--base") && argc - argpos > 1) {
			base = argv[++argpos];
			info_printf("Base URL encoding = '%s'\n", local_encoding);
		} else if (!strcmp(argv[argpos], "--encoding") && argc - argpos > 1) {
			css_encoding = argv[++argpos];
		} else if (!strcmp(argv[argpos], "--")) {
			argpos++;
			break;
		} else if (argv[argpos][0] == '-') {
			usage(argv[0]);
		} else
			break;
	}

	// All URIs are converted into UTF-8 charset.
	// That's why we need the local encoding (aka 'encoding of base URI') here.
	base_uri = mget_iri_parse(base, local_encoding);

	for (;argpos < argc; argpos++) {
		// use '-' as filename for STDIN
		css_parse_localfile(argv[argpos], base_uri, css_encoding);
	}

	mget_iri_free(&base_uri);

	return 0;
}
