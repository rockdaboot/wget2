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
 * Example for HTML parsing using libwget
 *
 * Changelog
 * 03.01.2014  Tim Ruehsen  created
 *
 * Demonstrate how to extract URIs from HTML files using callback functions.
 * We don't care about character encoding in this example.
 *
 */

#include <unistd.h>
#include <wget.h>

static void html_parse_localfile(const char *fname)
{
	char *data, *data_allocated;
	size_t len;

	if ((data_allocated = data = wget_read_file(fname, &len))) {
		const char *encoding = NULL;

		if ((unsigned char)data[0] == 0xFE && (unsigned char)data[1] == 0xFF) {
			// Big-endian UTF-16
			encoding = "UTF-16BE";

			// adjust behind BOM, ignore trailing single byte
			data += 2;
			len -= 2;
		} else if ((unsigned char)data[0] == 0xFF && (unsigned char)data[1] == 0xFE) {
			// Little-endian UTF-16
			encoding = "UTF-16LE";

			// adjust behind BOM
			data += 2;
			len -= 2;
		} else if ((unsigned char)data[0] == 0xEF && (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF) {
			// UTF-8
			encoding = "UTF-8";

			// adjust behind BOM
			data += 3;
			len -= 3;
		}

		if (encoding)
			printf("URI encoding '%s' set by BOM\n", encoding);

		if (!wget_strncasecmp_ascii(encoding, "UTF-16", 6)) {
			size_t n;
			char *utf8;

			len -= len & 1; // ignore single trailing byte, else charset conversion fails

			if (wget_memiconv(encoding, data, len, "UTF-8", &utf8, &n) == 0) {
				printf("Convert non-ASCII encoding '%s' to UTF-8\n", encoding);
				wget_xfree(data_allocated);
				data_allocated = data = utf8;
			} else {
				printf("Failed to convert non-ASCII encoding '%s' to UTF-8, skip parsing\n", encoding);
				return;
			}
		}

		wget_html_parsed_result *res  = wget_html_get_urls_inline(data, NULL, NULL);

		if (encoding) {
			if (res->encoding && wget_strcasecmp_ascii(encoding, res->encoding))
				printf("Encoding '%s' as stated in document has been ignored\n", encoding);
		}

		for (int it = 0; it < wget_vector_size(res->uris); it++) {
			wget_html_parsed_url *html_url = wget_vector_get(res->uris, it);
			wget_string *url = &html_url->url;

			printf("  %s.%s '%.*s'", html_url->tag, html_url->attr, (int) url->len, url->p);
			if (html_url->download.p)
				printf(" (save as '%.*s')", (int) html_url->download.len, html_url->download.p);
			printf("\n");
		}

		wget_xfree(data_allocated);
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
