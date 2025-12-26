/*
 * Copyright (c) 2024 Free Software Foundation, Inc.
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
 * Testing HTTP/2 stream error handling
 * Verifies that stream-level errors (RST_STREAM) don't affect other streams
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strcmp()
#include "libtest.h"

int main(void)
{
	// Test 1: One stream fails, others succeed
	// In HTTP/2, individual stream errors should not affect the connection
	// or other streams
	wget_test_url_t urls[]={
		{	.name = "/file1.txt",
			.code = "200 OK",
			.body = "Content of file 1",
			.headers = {
				"Content-Type: text/plain",
				NULL
			}
		},
		{	.name = "/error.txt",
			.code = "404 Not Found",
			.body = "Not Found",
			.headers = {
				"Content-Type: text/plain",
				NULL
			}
		},
		{	.name = "/file3.txt",
			.code = "200 OK",
			.body = "Content of file 3",
			.headers = {
				"Content-Type: text/plain",
				NULL
			}
		},
	};

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	// Download 3 files where the middle one returns 404
	// With --force-html or multiple URLs, wget2 should continue
	// and successfully download the other files
	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URLS, "file1.txt", "error.txt", "file3.txt", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 8,  // Exit code 8 for server errors
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file1.txt", "Content of file 1" },
			{ "file3.txt", "Content of file 3" },
			// error.txt should not be saved
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 stream error isolation test passed\n");

	// Test 2: Multiple errors with successful downloads
	wget_test_url_t mixed_urls[]={
		{	.name = "/ok1.txt",
			.code = "200 OK",
			.body = "OK 1",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/err1.txt",
			.code = "500 Internal Server Error",
			.body = "Error 1",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/ok2.txt",
			.code = "200 OK",
			.body = "OK 2",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/err2.txt",
			.code = "403 Forbidden",
			.body = "Error 2",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/ok3.txt",
			.code = "200 OK",
			.body = "OK 3",
			.headers = { "Content-Type: text/plain", NULL }
		},
	};

	wget_test_stop_server();
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &mixed_urls, countof(mixed_urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URLS, "ok1.txt", "err1.txt", "ok2.txt",
		                        "err2.txt", "ok3.txt", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 8,  // Exit code 8 for server errors
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "ok1.txt", "OK 1" },
			{ "ok2.txt", "OK 2" },
			{ "ok3.txt", "OK 3" },
			// Error files should not be saved
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 multiple stream errors test passed\n");

	exit(EXIT_SUCCESS);
}
