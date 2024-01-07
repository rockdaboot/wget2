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
		{	.name = "/1.bad.txt", // ?.bad.txt switches off MHD handling of chunked transfer
			.code = "200 Dontcare",
			.body = "5\r\nhello\r\n0\r\n\r\n",
			.headers = {
				"Content-Type: text/plain",
				"Transfer-Encoding: chunked",
			}
		},
		{	.name = "/2.bad.txt", // ?.bad.txt switches off MHD handling of chunked transfer
			.code = "200 Dontcare",
			.body = "1\r\nh\r\n2\r\nel\r\n2\r\nlo\r\n0\r\n\r\n",
			.headers = {
				"Content-Type: text/plain",
				"Transfer-Encoding: chunked",
			}
		},
		{	.name = "/3.bad.txt", // ?.bad.txt switches off MHD handling of chunked transfer
			.code = "200 Dontcare",
			.body = "1\r\nh\r\n2\r\nel\r\n2\r\nlo\r\n0\r\ntrailer\r\n\r\n",
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

	// simple test
	wget_test(
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URLS, urls[0].name + 1, urls[1].name + 1, urls[2].name + 1, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, "hello"},
			{ urls[1].name + 1, "hello"},
			{ urls[2].name + 1, "hello"},
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
