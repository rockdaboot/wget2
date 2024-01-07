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
 * Example for CSS parsing using libwget
 *
 * Changelog
 * 14.01.2013  Tim Ruehsen  created
 *
 * Demonstrate how to extract URIs from CSS files using callback functions.
 * We don't care about character encoding in this example.
 *
 */

#include <unistd.h>
#include <wget.h>

static void _css_parse_encoding(void *context WGET_GCC_UNUSED, const char *encoding, size_t len)
{
	printf("URI encoding '%.*s'\n", (int)len, encoding);
}

static void _css_parse_uri(void *context WGET_GCC_UNUSED, const char *url, size_t len, size_t pos WGET_GCC_UNUSED)
{
	printf("  %.*s\n", (int)len, url);
}

static void css_parse_localfile(const char *fname)
{
	wget_css_parse_file(fname, _css_parse_uri, _css_parse_encoding, NULL);
}

int main(int argc, const char *const *argv)
{
	if (!isatty(STDIN_FILENO)) {
		// read CSS data from STDIN
		css_parse_localfile("-");
	} else {
		// parse CSS files given as arguments
		int argpos;

		for (argpos = 1; argpos < argc; argpos++) {
			printf("%s:\n", argv[argpos]);

			// use '-' as filename for STDIN
			css_parse_localfile(argv[argpos]);
		}
	}

	return 0;
}
