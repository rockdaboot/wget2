/*
 * Copyright (c) 2026 Free Software Foundation, Inc.
 *
 * This file is part of Wget
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Testing non-ASCII URLs in CSS files that are not UTF-8:
 * the charset comes from the HTTP header or from @charset,
 * the URLs have to be downloaded and converted (-k).
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

// "primer" in Cyrillic, as windows-1251 bytes and as percent-encoded UTF-8
#define RU_CP1251 "\xEF\xF0\xE8\xEC\xE5\xF0"
#define RU_UTF8_PCT "%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80"
// with --restrict-file-names=ascii the files are saved as RU_UTF8_PCT,
// so the converted links have to escape that '%'
#define RU_FILE_LINK "%25D0%25BF%25D1%2580%25D0%25B8%25D0%25BC%25D0%25B5%25D1%2580"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head>" \
				"<link rel=\"stylesheet\" href=\"header.css\">" \
				"<link rel=\"stylesheet\" href=\"atcharset.css\">" \
				"</head><body></body></html>",
			.headers = {
				"Content-Type: text/html; charset=utf-8",
			}
		},
		{	.name = "/header.css",
			.code = "200 Dontcare",
			.body = "body { background: url(" RU_CP1251 "1.png); }",
			.headers = {
				"Content-Type: text/css; charset=windows-1251",
			}
		},
		{	.name = "/atcharset.css",
			.code = "200 Dontcare",
			.body = "@charset \"windows-1251\";\nbody { background: url(" RU_CP1251 "2.png); }",
			.headers = {
				"Content-Type: text/css",
			}
		},
		{	.name = "/" RU_UTF8_PCT "1.png",
			.code = "200 Dontcare",
			.body = "PNG1",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/" RU_UTF8_PCT "2.png",
			.code = "200 Dontcare",
			.body = "PNG2",
			.headers = {
				"Content-Type: image/png",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-k -r -nH --local-encoding=utf-8 --restrict-file-names=ascii",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "header.css", "body { background: url(" RU_FILE_LINK "1.png); }" },
			{ "atcharset.css", "@charset \"windows-1251\";\nbody { background: url(" RU_FILE_LINK "2.png); }" },
			{ RU_UTF8_PCT "1.png", urls[3].body },
			{ RU_UTF8_PCT "2.png", urls[4].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
