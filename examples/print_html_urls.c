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
 * Example for HTML parsing using libmget
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
#include <libmget.h>

static void html_parse_localfile(const char *fname)
{
	char *data;

	if ((data = mget_read_file(fname, NULL))) {
		MGET_HTML_PARSED_RESULT *res  = mget_html_get_urls_inline(data, NULL, NULL);

		if (res->encoding)
			printf("URI encoding '%s'\n", res->encoding);

		for (int it = 0; it < mget_vector_size(res->uris); it++) {
			MGET_HTML_PARSED_URL *html_url = mget_vector_get(res->uris, it);
			mget_string_t *url = &html_url->url;

			printf("  %s.%s '%.*s'\n", html_url->dir, html_url->attr, (int) url->len, url->p);
		}

		mget_xfree(data);
		mget_html_free_urls_inline(&res);
	}
}

int main(int argc, const char *const *argv)
{
/*
	mget_global_init(
		MGET_DEBUG_STREAM, stderr,
		MGET_ERROR_STREAM, stderr,
		MGET_INFO_STREAM, stdout,
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
