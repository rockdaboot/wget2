/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
				" <A hreF=\"200_a\">200 a</a>." \
				" <a href=\"404_a\">404 a</a>." \
				" <a href=\"501_a\">501 a</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/200_a",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>A link to a" \
				" <A hreF=\"200_b\">200 b</a>." \
				" <a href=\"404_b\">404 b</a>." \
				" <a href=\"501_b\">501 b</a>." \
				"</p></body></html>",
			.headers = { "Content-Type: text/html" }
		},
		{	.name = "/200_b",
			.code = "200 Dontcare",
			.body = "content of 200_b",
			.headers = { "Content-Type: text/plain" }
		},
		{	.name = "/404_a",
			.code = "404 Not found",
			.body = "content of 404_a",
			.headers = { "Content-Type: text/plain" }
		},
		{	.name = "/501_a",
			.code = "501 Dontcare",
			.body = "content of 501_a",
			.headers = { "Content-Type: text/plain" }
		},
		{	.name = "/404_b",
			.code = "404 Dontcare",
			.body = "content of 404_b",
			.headers = { "Content-Type: text/plain" }
		},
		{	.name = "/501_b",
			.code = "501 Dontcare",
			.body = "content of 501_b",
			.headers = { "Content-Type: text/plain" }
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// only want 200 OK
	wget_test(
		WGET_TEST_OPTIONS, "-nH --save-content-on \"200\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// only want 200 OK, recursive
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --save-content-on \"200\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	// want non-200 status only, recursive
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --save-content-on \"*,!200\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ "robots.txt", "" },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
