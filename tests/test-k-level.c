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
 * Testing -k (convert-links) on documents that are not followed:
 * HTML and CSS on the last level of -r -l, and a download without -r.
 * Wget 1.x converts them too.
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
				"<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head><body>" \
				"<img src=\"/img/pic.png\"> <a href=\"/sub/page.html\">page</a>" \
				"</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/sub/page.html",
			.code = "200 Dontcare",
			.body =
				"<html><body>" \
				"<a href=\"/index.html\">index</a> <a href=\"/sub/deep.html\">deep</a> <img src=\"/img/pic.png\">" \
				"</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/sub/deep.html",
			.code = "200 Dontcare",
			.body = "<html><body>deep</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/style.css",
			.code = "200 Dontcare",
			.body = "body { background: url(/img/pic.png); }",
			.headers = {
				"Content-Type: text/css",
			}
		},
		{	.name = "/img/pic.png",
			.code = "200 Dontcare",
			.body = "PNG",
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

	// sub/page.html and style.css are on the last level: not followed, but converted
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-k -r -l1 -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html",
				"<html><head><link rel=\"stylesheet\" href=\"style.css\"></head><body>" \
				"<img src=\"img/pic.png\"> <a href=\"sub/page.html\">page</a>" \
				"</body></html>" },
			{ "sub/page.html",
				"<html><body>" \
				"<a href=\"../index.html\">index</a> <a href=\"http://localhost:{{port}}/sub/deep.html\">deep</a> <img src=\"../img/pic.png\">" \
				"</body></html>" },
			{ "style.css", "body { background: url(img/pic.png); }" },
			{ "img/pic.png", urls[4].body },
			{	NULL } },
		0);

	// without -r, nothing is downloaded besides the page itself: its links become absolute
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-k",
		WGET_TEST_REQUEST_URL, "sub/page.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "page.html",
				"<html><body>" \
				"<a href=\"http://localhost:{{port}}/index.html\">index</a> <a href=\"http://localhost:{{port}}/sub/deep.html\">deep</a> <img src=\"http://localhost:{{port}}/img/pic.png\">" \
				"</body></html>" },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
