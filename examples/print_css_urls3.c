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
 * Advanced example for CSS parsing using libwget
 *
 * Changelog
 * 15.01.2013  Tim Ruehsen  created
 *
 * Demonstrate how to extract URIs from CSS files into a vector.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <wget.h>

// use the helper routines provided by libwget
#define info_printf        wget_info_printf
// #define error_printf       wget_error_printf
#define error_printf_exit  wget_error_printf_exit

static void WGET_GCC_NORETURN usage(const char *myname)
{
	error_printf_exit(
		"\nUsage: %s [options] file...\n"\
		"  --base <URI>          Default base for relative URIs, default: http://www.example.com\n"\
		"  --encoding <Encoding> Default file character encoding, default: iso-8859-1\n"\
		"\n"\
		"  Examples:\n"\
		"    %s --base http://www.mydomain.com x.css\n"\
		"    cat x.css | %s --base http://www.mydomain.com -\n"\
		"    %s http://www.example.com\n"\
		"\n"\
		"  Print URIs as found (without a base):\n"\
		"    %s --base \"\" x.css\n\n",
		myname, myname, myname, myname, myname);
}

int main(int argc, const char **argv)
{
	// Base URI for converting relative to absolute URIs
	const char *
		base = NULL;

	// We assume that base is encoded in the local charset.
	const char *
		local_encoding = wget_local_charset_encoding();

	// parsed 'base'
	wget_iri
		*base_uri;

	// Character encoding of CSS file content
	// An HTTP response may contain the encoding in the Content-Type header,
	// see https://stackoverflow.com/questions/2526033/why-specify-charset-utf-8-in-your-css-file
	const char *
		css_encoding = NULL;

	int
		argpos;

	// We want the libwget error messages be printed to STDERR.
	// From here on, we can call wget_error_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);

	// We want the libwget info messages be printed to STDOUT.
	// From here on, we can call wget_info_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);

	// parse options
	for (argpos = 1; argpos < argc; argpos++) {
		if (!strcmp(argv[argpos], "--base") && argc - argpos > 1) {
			base = argv[++argpos];
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
	base_uri = base ? wget_iri_parse(base, local_encoding) : NULL;

	for (;argpos < argc; argpos++) {
		// use '-' as filename for STDIN
		wget_vector *css_urls = wget_css_get_urls_from_localfile(argv[argpos], base_uri, &css_encoding);

		if (wget_vector_size(css_urls) > 0) {
			info_printf("URL encoding for %s is '%s':\n", argv[argpos], css_encoding ? css_encoding : "UTF-8");

			for (int it = 0; it < wget_vector_size(css_urls); it++) {
				wget_css_parsed_url *css_url = wget_vector_get(css_urls, it);
				if (css_url->abs_url)
					info_printf("  %s -> %s\n", css_url->url, css_url->abs_url);
				else
					info_printf("  %s\n", css_url->url);
			}

			info_printf("\n");
		}

		wget_vector_free(&css_urls);
	}

	wget_iri_free(&base_uri);

	return 0;
}
