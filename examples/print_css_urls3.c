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
 * Demonstrate how to extract URIs from CSS files into a vector.
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stringprep.h> // from libidn

#include <libmget.h>

// use the helper routines provided by libmget
#define info_printf        mget_info_printf
#define error_printf       mget_error_printf
#define error_printf_exit  mget_error_printf_exit

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

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

static int _print_url(MGET_CSS_URL *css_url)
{
	info_printf("  %s -> %s\n", css_url->org_url, css_url->url);
	xfree(css_url->org_url);
	xfree(css_url->url);
	return 0;
}

int main(int argc, const char *const *argv)
{
	// Base URI for converting relative to absolute URIs
	const char *
		base = "http://www.example.com";

	// Encoding of 'base'
	// We assume that this file (and base) is encoded in iso-8859-1 or compatible.
	// Changing the base with --base option will determine the local charset.
	const char *
		local_encoding = "iso-8859-1";

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
	mget_logger_set_file(mget_get_logger(MGET_LOGGER_ERROR), stderr);

	// We want the libmget info messages be printed to STDOUT.
	// From here on, we can call mget_info_printf, etc.
	mget_logger_set_file(mget_get_logger(MGET_LOGGER_INFO), stdout);

	// parse options
	for (argpos = 1; argpos < argc; argpos++) {
		if (!strcmp(argv[argpos], "--base") && argc - argpos > 1) {
			base = argv[++argpos];
			local_encoding = stringprep_locale_charset();
			info_printf("Local URI encoding = '%s'\n", local_encoding);
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
		MGET_VECTOR *css_urls = css_get_uris_from_localfile(argv[argpos], base_uri, &css_encoding);

		if (mget_vector_size(css_urls) > 0) {
			info_printf("URL encoding for %s is '%s':\n", argv[argpos], css_encoding ? css_encoding : "UTF-8");
			mget_vector_browse(css_urls, (int (*)(void *))_print_url);
			info_printf("\n");
		}
		mget_vector_free(&css_urls);
	}

	mget_iri_free(&base_uri);

	return 0;
}
