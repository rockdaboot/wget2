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
		{	.name = "/1.bad.txt",
			.code = "200 Dontcare",
			.body = "FFFFFFF4\nGarbage",
			.headers = {
				"Content-Type: text/plain",
				"Transfer-Encoding: chunked",
			}
		},
		{	.name = "/2.bad.txt",
			.code = "200 Dontcare",
			.body = "FFFFFFFE\r\nGarbage",
			.headers = {
				"Content-Type: text/plain",
				"Transfer-Encoding: chunked",
			}
		},
		{	.name = "/3.bad.txt",
			.code = "200 Dontcare",
			.body = "FFFFFFFFFFFFFFF4\r\nGarbage",
			.headers = {
				"Content-Type: text/plain",
				"Transfer-Encoding: chunked",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_SKIP_H2,
		0);

	// test negative chunk size (32bit system only)
	wget_test(
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URLS, "1.bad.txt", "2.bad.txt", "3.bad.txt", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, NULL }, // do not check content
			{ urls[1].name + 1, NULL }, // do not check content
			{ urls[2].name + 1, NULL }, // do not check content
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
