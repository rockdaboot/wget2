/*
 * Copyright (c) 2022-2024 Free Software Foundation, Inc.
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
 * Testing --level
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
				" <a href=\"http://localhost:{{port}}/level0.txt\">level0</a>." \
				" <a href=\"http://localhost:{{port}}/sub1/page.html\">sub1 page</a>." \
			"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/sub1/page.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/level1.txt\">level1</a>." \
				" <a href=\"http://localhost:{{port}}/sub1/sub2/page.html\">sub2 page</a>." \
			"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/sub1/sub2/page.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/level2.txt\">level2</a>." \
				" <a href=\"http://localhost:{{port}}/sub1/sub2/sub3/page.html\">sub3 page</a>." \
			"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/sub1/sub2/sub3/page.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/level3.txt\">level3</a>." \
				" <a href=\"http://localhost:{{port}}/sub1/sub2/sub3/sub4/page.html\">sub4 page</a>." \
			"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/sub1/sub2/sub3/sub4/page.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>No links</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/level0.txt",
			.code = "200 Dontcare",
			.body = "level0",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/level1.txt",
			.code = "200 Dontcare",
			.body = "level0",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/level2.txt",
			.code = "200 Dontcare",
			.body = "level0",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/level3.txt",
			.code = "200 Dontcare",
			.body = "level0",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test --level 0 = indefinitely
	wget_test(
		WGET_TEST_OPTIONS, "-r --level 0 -nH",
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
			{ urls[7].name + 1, urls[7].body },
			{ urls[8].name + 1, urls[8].body },
			{	NULL } },
		0);

	// test --level inf = indefinitely
	wget_test(
		WGET_TEST_OPTIONS, "-r --level inf -nH",
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
			{ urls[7].name + 1, urls[7].body },
			{ urls[8].name + 1, urls[8].body },
			{	NULL } },
		0);

	// test level 1
	wget_test(
		WGET_TEST_OPTIONS, "-r --level 1 -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// test level 2
	wget_test(
		WGET_TEST_OPTIONS, "-r --level 2 -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// test level 3
	wget_test(
		WGET_TEST_OPTIONS, "-r --level 3 -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ urls[7].name + 1, urls[7].body },
			{	NULL } },
		0);

	// test level 4
	wget_test(
		WGET_TEST_OPTIONS, "-r --level 4 -nH",
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
			{ urls[7].name + 1, urls[7].body },
			{ urls[8].name + 1, urls[8].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
