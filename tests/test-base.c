/*
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
 * Testing 'base' html tag
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
				"<html><head><title>Main Page</title><base href=\"/subdir1/\"></head><body><p>A link to a" \
				" <A hreF=\"http://localhost:{{port}}/second\r\npage.html\">second page</a>." \
				" <a  HreF=\"subpage1.h&#116;ml?qu&#x65;ry&amp;param#frag\">page in subdir1</a>." \
				" <a href=\"./subpage2.html\">page in subdir1</a>." \
				" <a href=\"http://localhost:{{port}}/page+with&#32spaces.html\">page with spaces</a>." \
				" <a href=\"http://localhost:{{port}}/css?query+with+spaces&param=bla+blubb\">query with spaces</a>." \
				" <a href=\"../subdir3%3A/\">subdir3 with colon</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title><base href=\"/subdir2/\"></head><body><p>A link to a" \
				" <A hreF=\"../secondpage.html\">second page</a>." \
				" <a  HreF=\"subpage1.html?query&param#frag\">page in subdir2</a>." \
				" <a href=./subpage2.html>page in subdir2</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir1/subpage1.html?query&param",
			.code = "200 Dontcare",
			.body = "sub1_1"
		},
		{	.name = "/subdir2/subpage1.html?query&param",
			.code = "200 Dontcare",
			.body = "sub2_1"
		},
		{	.name = "/subdir1/subpage2.html",
			.code = "200 Dontcare",
			.body = "sub1_2"
		},
		{	.name = "/subdir2/subpage2.html",
			.code = "200 Dontcare",
			.body = "sub2_2"
		},
		{
			.name = "/page%2Bwith%2Bspaces.html",
			.code = "200 Dontcare",
			.body = "page with spaces"
		},
		{
			.name = "/css?query+with+spaces&param=bla+blubb",
			.code = "200 Dontcare",
			.body = "query with spaces"
		},
		{	.name = "/index2.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><base href=\"http://\"></head><body><p>A link to a" \
				" <A href=\"http://localhost:{{port}}/subdir2/subpage2.html\">page2 in subdir2</a>." \
				" <a href=\"//localhost:{{port}}/subdir1/subpage1.html?query&param#frag\">page1 in subdir1</a>." \
				" <a href=\"/subdir1/subpage2.html\">page2 in subdir1</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir3%3A/index.html",
			.code = "200 Dontcare",
			.body = "subdir3 index"
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-i
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --no-robots",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ "page+with+spaces.html", urls[6].body },
			{ "css?query with spaces&param=bla blubb", urls[7].body },
			{ "subdir3:/index.html", urls[9].body },
			{	NULL } },
		0);

	// test-O/dev/null
	wget_test(
		WGET_TEST_OPTIONS, "-O/dev/null",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// test with incomplete base
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --no-robots",
		WGET_TEST_REQUEST_URL, urls[8].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[8].name + 1, urls[8].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
