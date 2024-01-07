/*
 * Copyright (c) 2013 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Testing Wget
 *
 * Changelog
 * 15.07.2013  Tim Ruehsen  created
 * 19.02.2022  Tim Ruehsen  add test for query part including escaped chars
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title>" \
				"<style> html { background: url(htTp://localhost:{{port}}/second.html); }</style>" \
				"<style> div { background: url(htTp://localhost:{{port}}/second.html); }</style>" \
				"</head><body><p>A link to a" \
				" <a href=\"second.html\">second page</a>." \
				" <a href=\"htTp://localhost:{{port}}/second.html\">second page</a>." \
				" <a href=\"htTp://localhost:{{port}}/subdir/third.html\">third page</a>." \
				" <a href=\"subdir/third.html?x&h=http%3A%2F%2Fexample.com#frag\">third page</a>." \
				" <SCRIPT LANGUAGE=\"JavaScript\">document.write(\"<img src=\\\"rw1\\\"\");</SCRIPT>" \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/second.html",
			.code = "200 Dontcare",
			.body = "<html><head><title>Site</title></head><body>Second</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/third.html",
			.code = "200 Dontcare",
			.body = "<html><head><title>Site</title></head><body>Third</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/third.html?x&h=http%3A%2F%2Fexample.com",
			.code = "200 Dontcare",
			.body = "<html><head><title>Site</title></head><body>Third2</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
	};

	const char *converted =
		"<html><head><title>Main Page</title>" \
		"<style> html { background: url(second.html); }</style>" \
		"<style> div { background: url(second.html); }</style>" \
		"</head><body><p>A link to a" \
		" <a href=\"second.html\">second page</a>." \
		" <a href=\"second.html\">second page</a>." \
		" <a href=\"subdir/third.html\">third page</a>." \
		" <a href=\"subdir/third.html%3Fx&h=http%253A%252F%252Fexample.com#frag\">third page</a>." \
		" <SCRIPT LANGUAGE=\"JavaScript\">document.write(\"<img src=\\\"rw1\\\"\");</SCRIPT>" \
		"</p></body></html>";

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-k, links in <script> shouldn't be converted
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-k -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, converted },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
