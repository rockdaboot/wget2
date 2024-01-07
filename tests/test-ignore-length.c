/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * Testing --ignore-length
 *
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
				"<html><head><title>Main Page</title><body><p>A link to a" \
				" <A href=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				" <a href=\"/subdir1/subpage1.html?query&param#frag\">page in subdir1</a>." \
				" <a href=\"./subdir1/subpage2.html\">page in subdir1</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Length: 140",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title><base href=\"/subdir2/\"></head><body><p>A link to a" \
				" <A href=\"../secondpage.html\">second page</a>." \
				" <a href=\"subpage1.html?query&param#frag\">page in subdir2</a>." \
				" <a href=\"./subpage2.html\">page in subdir2</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Length: 300",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// with --ignore-length no warning should pop up in log and return should be 0
	// without --ignore-length return 10
	wget_test(
		WGET_TEST_OPTIONS, "--ignore-length",
		WGET_TEST_REQUEST_URLS, "index.html", "secondpage.html", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
