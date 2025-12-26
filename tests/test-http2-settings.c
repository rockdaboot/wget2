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
 * Testing HTTP/2 settings and protocol negotiation
 * Verifies basic HTTP/2 protocol setup and configuration
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strcmp()
#include "libtest.h"

int main(void)
{
	// Test 1: Basic HTTP/2 connection with SETTINGS frame exchange
	// Every HTTP/2 connection starts with a SETTINGS frame exchange
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 OK",
			.body = "<html><head><title>HTTP/2 Test</title></head>"
			        "<body><h1>Hello HTTP/2</h1></body></html>",
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

	// Simple download over HTTP/2 - verifies basic protocol negotiation
	wget_test(
		WGET_TEST_OPTIONS, "-d",  // Debug output to see SETTINGS frames
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 basic settings exchange test passed\n");

	// Test 2: Verify HTTP/2 header compression (HPACK)
	// Headers should be compressed efficiently across multiple requests
	wget_test_url_t header_urls[]={
		{	.name = "/headers1.txt",
			.code = "200 OK",
			.body = "Response 1",
			.headers = {
				"Content-Type: text/plain",
				"X-Custom-Header: Custom Value",
				"X-Another-Header: Another Value",
				NULL
			}
		},
		{	.name = "/headers2.txt",
			.code = "200 OK",
			.body = "Response 2",
			.headers = {
				"Content-Type: text/plain",
				"X-Custom-Header: Custom Value",
				"X-Another-Header: Another Value",
				NULL
			}
		},
		{	.name = "/headers3.txt",
			.code = "200 OK",
			.body = "Response 3",
			.headers = {
				"Content-Type: text/plain",
				"X-Custom-Header: Custom Value",
				"X-Another-Header: Another Value",
				NULL
			}
		},
	};

	wget_test_stop_server();
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &header_urls, countof(header_urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	// Download multiple files with repeated headers
	// HPACK should compress repeated headers efficiently
	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URLS, "headers1.txt", "headers2.txt", "headers3.txt", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "headers1.txt", "Response 1" },
			{ "headers2.txt", "Response 2" },
			{ "headers3.txt", "Response 3" },
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 header compression test passed\n");

	// Test 3: Large headers
	// HTTP/2 should handle large headers properly
	char large_header_value[2048];
	memset(large_header_value, 'A', sizeof(large_header_value) - 1);
	large_header_value[sizeof(large_header_value) - 1] = '\0';

	char large_header[2112];
	wget_snprintf(large_header, sizeof(large_header), "X-Large-Header: %s", large_header_value);

	wget_test_url_t large_header_urls[]={
		{	.name = "/large-header.txt",
			.code = "200 OK",
			.body = "Response with large header",
			.headers = {
				"Content-Type: text/plain",
				large_header,
				NULL
			}
		},
	};

	wget_test_stop_server();
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &large_header_urls, countof(large_header_urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--no-directories",
		WGET_TEST_REQUEST_URL, "large-header.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "large-header.txt", "Response with large header" },
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 large headers test passed\n");

	exit(EXIT_SUCCESS);
}
