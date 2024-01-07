/*
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
 * Testing basic robots.txt functionality
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/robots.txt",
			.code = "200 Dontcare",
			.body =
				"User-agent: Badboy\n"\
				"Disallow: /\n"\
				"\n"
				"# a simple comment\n"\
				"User-agent: *\n"\
				"Disallow: /subdir2/\n"\
			,
			.headers = {
				"Content-Type: text/plain",
			}
		},
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
			}
		},
		{	.name = "/subdir1/subpage1.html?query&param",
			.code = "200 Dontcare",
			.body = "sub1_1"
		},
		{	.name = "/subdir1/subpage2.html",
			.code = "200 Dontcare",
			.body = "sub1_2"
		},
		{	.name = "/subdir2/subpage1.html?query&param",
			.code = "200 Dontcare",
			.body = "sub2_1"
		},
		{	.name = "/subdir2/subpage2.html",
			.code = "200 Dontcare",
			.body = "sub2_2"
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// with robots=off must download robots.txt and /subdir2/ should not be forbidden
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --robots=off",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
