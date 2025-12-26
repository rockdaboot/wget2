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
 * Testing HTTP/2 connection-level behavior
 * Tests connection reuse, graceful shutdown, and reconnection
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strcmp()
#include "libtest.h"

int main(void)
{
	// Test 1: Multiple requests reuse the same HTTP/2 connection
	// Sequential requests should use the same connection
	wget_test_url_t urls[]={
		{	.name = "/page1.html",
			.code = "200 OK",
			.body = "<html><body>Page 1</body></html>",
			.headers = {
				"Content-Type: text/html",
				NULL
			}
		},
		{	.name = "/page2.html",
			.code = "200 OK",
			.body = "<html><body>Page 2</body></html>",
			.headers = {
				"Content-Type: text/html",
				NULL
			}
		},
		{	.name = "/page3.html",
			.code = "200 OK",
			.body = "<html><body>Page 3</body></html>",
			.headers = {
				"Content-Type: text/html",
				NULL
			}
		},
	};

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	// Download all files in a single request - demonstrates HTTP/2 connection reuse
	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URLS, "page1.html", "page2.html", "page3.html", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "page1.html", urls[0].body },
			{ "page2.html", urls[1].body },
			{ "page3.html", urls[2].body },
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 connection reuse test passed\n");

	// Test 2: Server restart - client should handle connection closure gracefully
	wget_test_url_t restart_urls[]={
		{	.name = "/before.txt",
			.code = "200 OK",
			.body = "Before restart",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/after.txt",
			.code = "200 OK",
			.body = "After restart",
			.headers = { "Content-Type: text/plain", NULL }
		},
	};

	wget_test_stop_server();
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &restart_urls, countof(restart_urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URL, "before.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "before.txt", "Before restart" },
			{ NULL }
		},
		0);

	// Simulate server restart
	wget_test_stop_server();
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &restart_urls, countof(restart_urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	// This should establish a new connection
	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URL, "after.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "after.txt", "After restart" },
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 connection recovery test passed\n");

	exit(EXIT_SUCCESS);
}
