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
 * Testing HTTP/2 multiplexing - concurrent streams over single connection
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strcmp(), memset()
#include "libtest.h"

// 1MB file for testing multiplexing with substantial data transfer
static char large_file[1 * 1024 * 1024];

int main(void)
{
	memset(large_file, 'X', sizeof(large_file) - 1);
	large_file[sizeof(large_file) - 1] = '\0';

	wget_test_url_t urls[]={
		{	.name = "/file1.bin",
			.code = "200 OK",
			.body = large_file,
			.headers = {
				"Content-Type: application/octet-stream",
				NULL
			}
		},
		{	.name = "/file2.bin",
			.code = "200 OK",
			.body = large_file,
			.headers = {
				"Content-Type: application/octet-stream",
				NULL
			}
		},
		{	.name = "/file3.bin",
			.code = "200 OK",
			.body = large_file,
			.headers = {
				"Content-Type: application/octet-stream",
				NULL
			}
		},
	};

	// Start HTTP/2-only server
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	// Test 1: Download 3 files concurrently
	// HTTP/2 multiplexing should download all 3 files over a single connection
	// with concurrent streams, which should be faster than sequential
	long long start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_REQUEST_URLS, "file1.bin", "file2.bin", "file3.bin", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_H2_MIN_CONCURRENT_STREAMS, 2,  // Expect at least 2 concurrent
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file1.bin", large_file },
			{ "file2.bin", large_file },
			{ "file3.bin", large_file },
			{ NULL }
		},
		0);
	long long elapsed_ms = wget_get_timemillis() - start_ms;

	// Sanity check: 3MB over HTTP/2 should complete reasonably quickly
	// This is not a strict performance test, just ensuring multiplexing works
	if (elapsed_ms > 30000) {  // 30 seconds is very generous
		wget_error_printf_exit("HTTP/2 multiplexing took too long: %lld ms "
		                       "(expected < 30000 ms)\n", elapsed_ms);
	}

	wget_info_printf("HTTP/2 multiplexing test passed (%lld ms for 3MB)\n", elapsed_ms);

	// Test 2: Download many small files
	// This tests connection reuse and stream ID management
	wget_test_url_t small_urls[]={
		{	.name = "/small1.txt",
			.code = "200 OK",
			.body = "Content 1",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/small2.txt",
			.code = "200 OK",
			.body = "Content 2",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/small3.txt",
			.code = "200 OK",
			.body = "Content 3",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/small4.txt",
			.code = "200 OK",
			.body = "Content 4",
			.headers = { "Content-Type: text/plain", NULL }
		},
		{	.name = "/small5.txt",
			.code = "200 OK",
			.body = "Content 5",
			.headers = { "Content-Type: text/plain", NULL }
		},
	};

	wget_test_stop_server();
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &small_urls, countof(small_urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	wget_test(
		WGET_TEST_REQUEST_URLS, "small1.txt", "small2.txt", "small3.txt",
		                        "small4.txt", "small5.txt", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "small1.txt", "Content 1" },
			{ "small2.txt", "Content 2" },
			{ "small3.txt", "Content 3" },
			{ "small4.txt", "Content 4" },
			{ "small5.txt", "Content 5" },
			{ NULL }
		},
		0);

	wget_info_printf("HTTP/2 small files test passed\n");

	exit(EXIT_SUCCESS);
}
