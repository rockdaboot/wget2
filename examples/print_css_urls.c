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
 * Example for CSS parsing using libmget
 *
 * Changelog
 * 14.01.2013  Tim Ruehsen  created
 *
 * Demonstrate how to extract URIs from CSS files.
 * We don't care about character encoding in this example.
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <libmget.h>

static void _css_parse_encoding(void *context G_GNUC_MGET_UNUSED, const char *encoding, size_t len)
{
	printf("URI encoding '%.*s'\n", (int)len, encoding);
}

static void _css_parse_uri(void *context G_GNUC_MGET_UNUSED, const char *url, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	printf("  %.*s\n", (int)len, url);
}

static void css_parse_localfile(const char *fname)
{
	mget_css_parse_file(fname, _css_parse_uri, _css_parse_encoding, NULL);
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
