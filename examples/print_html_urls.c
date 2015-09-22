/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015 Free Software Foundation, Inc.
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
 * Example for HTML parsing using libwget
 *
 * Changelog
 * 03.01.2014  Tim Ruehsen  created
 *
 * Demonstrate how to extract URIs from HTML files using callback functions.
 * We don't care about character encoding in this example.
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <libwget.h>

static void html_parse_localfile(const char *fname)
{
	char *data;

	if ((data = wget_read_file(fname, NULL))) {
		WGET_HTML_PARSED_RESULT *res  = wget_html_get_urls_inline(data, NULL, NULL);

		if (res->encoding)
			printf("URI encoding '%s'\n", res->encoding);

		for (int it = 0; it < wget_vector_size(res->uris); it++) {
			WGET_HTML_PARSED_URL *html_url = wget_vector_get(res->uris, it);
			wget_string_t *url = &html_url->url;

			printf("  %s.%s '%.*s'\n", html_url->dir, html_url->attr, (int) url->len, url->p);
		}

		wget_xfree(data);
		wget_html_free_urls_inline(&res);
	}
}

int main(int argc, const char *const *argv)
{
/*
	wget_global_init(
		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stderr,
		WGET_INFO_STREAM, stdout,
		NULL);
*/

	if (!isatty(STDIN_FILENO)) {
		// read HTML data from STDIN
		html_parse_localfile("-");
	} else {
		// parse CSS files given as arguments
		int argpos;

		for (argpos = 1; argpos < argc; argpos++) {
			printf("%s:\n", argv[argpos]);

			// use '-' as filename for STDIN
			html_parse_localfile(argv[argpos]);
		}
	}

	return 0;
}
