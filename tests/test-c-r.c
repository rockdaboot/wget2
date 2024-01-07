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
 * Testing recursive downloads with partial content
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

static const char *mainpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>.\n\
    <a href=\"http://localhost:{{port}}/thirdpage.html\">third page</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *subpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *mainpage_partial = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>.\n";

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = mainpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/thirdpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/index_partial.html",
			.code = "200 Dontcare",
			.body = mainpage_partial,
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	wget_test_start_server(
			WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
			WGET_TEST_FEATURE_MHD,
			0);

	// test-c-r with no existing files
	wget_test(
		WGET_TEST_OPTIONS, "--continue --recursive --no-host-directories",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{	NULL } },
		0);

	// test-c-r with existing file
	wget_test(
		WGET_TEST_OPTIONS, "--continue --recursive --no-host-directories",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{	NULL } },
		0);

	// test-c-r with existing partial file
	wget_test(
		WGET_TEST_OPTIONS, "--continue --recursive --no-host-directories",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[3].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
