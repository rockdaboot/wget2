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
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				" Also, a <a href=\"http://localhost:{{port}}/nonexistent\">broken link</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/thirdpage.html\">third page</a>." \
				" Also, a <a href=\"http://localhost:{{port}}/nonexistent\">broken link</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Disposition: attachment; filename=\"filename.html\"",
			}
		},
		{	.name = "/thirdpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Third Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/dummy.txt\">text file</a>." \
				" Also, a <a href=\"http://localhost:{{port}}/againnonexistent\">broken link</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/dummy.txt",
			.code = "200 Dontcare",
			.body = "What ever",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{
			.name = "/redirect.html",
			.code = "302 Found",
			.headers = {
				"Location: http://localhost:{{port}}/index.html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test--spider-r-HTTP-Content-Disposition
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--spider -r",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		0);

	// test--spider-r
	urls[1].headers[1] = NULL;
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--spider -r",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		0);

	urls[0].expected_method = "HEAD";
	wget_test(
		WGET_TEST_OPTIONS, "--spider",
		WGET_TEST_REQUEST_URL, "redirect.html",
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		0
	);


	exit(EXIT_SUCCESS);
}
