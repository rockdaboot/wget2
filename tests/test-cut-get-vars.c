/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * Tests the --cut-get-vars setting.
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/page1.html",
			.code = "200 Dontcare",
			.body = "<html>hello1<head></head>"\
					"<a href=\"/page2.html?cut=1\">test1</a>"\
					"<a href=\"/page2.html?cut=2\">test2</a>"\
					"<a href=\"/page2.html?cut=2\">test3</a>"\
					"<a href=\"/subdir/page3.html?cut=3\">test4</a>"\
					"<body></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page2.html",
			.code = "200 Dontcare",
			.body = "<html>hello2</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page2.html?cut=1",
			.code = "200 Dontcare",
			.body = "<html>hello2 cut</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page2.html?cut=2",
			.code = "200 Dontcare",
			.body = "<html>hello2 cut2</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/page3.html",
			.code = "200 Dontcare",
			.body = "<html>hello3</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/page3.html?cut=3",
			.code = "200 Dontcare",
			.body = "<html>hello3 cut</html>",
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test recursive --cut-url-get-vars
	wget_test(
		WGET_TEST_OPTIONS, "-nH -r --cut-url-get-vars",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ "subdir/page3.html", urls[4].body },
			{	NULL } },
		0);

	// test recursive --cut-file-get-vars without directories
	wget_test(
		WGET_TEST_OPTIONS, "-nH -r --cut-file-get-vars --no-directories",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "page2.html", urls[2].body },
			{ "page2.html.1", urls[3].body },
			{ "page3.html", urls[5].body },
			{	NULL } },
		0);

	/* test recursive --cut-file-get-vars with directories
	 *
	 * There is only *one* page2.html though 'page2.html?cut=1' and 'page2.html?cut=2'
	 * have been downloaded. This is inherited behavior from --recursive and might be
	 * unexpected.
	 */
	wget_test(
		WGET_TEST_OPTIONS, "-nH -r --cut-file-get-vars",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "page2.html", urls[3].body },
			{ "subdir/page3.html", urls[5].body },
			{	NULL } },
		0);

	/* test recursive --cut-file-get-vars --cut-url-get-vars with directories
	 *
	 * There ? query part is cut before downloading. So we see only see downloads of
	 * 'page2.html' and 'subdir/page3.html'.
	 */
	wget_test(
		WGET_TEST_OPTIONS, "-nH -r --cut-file-get-vars --cut-url-get-vars",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "page2.html", urls[1].body },
			{ "subdir/page3.html", urls[4].body },
			{	NULL } },
		0);

	// test simple --cut-file-get-vars
	wget_test(
		WGET_TEST_OPTIONS, "-nH --cut-file-get-vars",
		WGET_TEST_REQUEST_URL, "subdir/page3.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "page3.html", urls[4].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
