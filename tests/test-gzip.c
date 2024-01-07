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
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

// gzipp'ed content 'x'
#define compressed_body "\x1f\x8b\x08\x08\x48\x5d\x91\x5a\x00\x03\x78\x00\xab\x00\x00\x83\x16\xdc\x8c\x01\x00\x00\x00"
#ifdef WITH_ZLIB
#  define uncompressed_body "x"
#endif

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = compressed_body,
			.body_len = sizeof(compressed_body) - 1,
			.headers = {
				"Content-Type: application/gzip",
				"Content-Encoding: gzip",
			},
		},
		{	.name = "/index2.html",
			.code = "200 Dontcare",
			.body = compressed_body,
			.body_len = sizeof(compressed_body) - 1,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: gzip",
			},
		},
		{	.name = "/ball.tgz",
			.code = "200 Dontcare",
			.body = compressed_body,
			.body_len = sizeof(compressed_body) - 1,
			.headers = {
				"Content-Type: application/x-tar",
				"Content-Encoding: gzip",
			},
		},
		{	.name = "/ball.tar.gz",
			.code = "200 Dontcare",
			.body = compressed_body,
			.body_len = sizeof(compressed_body) - 1,
			.headers = {
				"Content-Type: application/x-tar",
				"Content-Encoding: gzip",
			},
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// wget2 should not decompress application/gzip
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
#ifdef WITH_ZLIB
			{ urls[0].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#else
			{ urls[0].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#endif
			{	NULL } },
		0);

	// wget2 should decompress gzipped'ed text/html
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, urls[1].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
#ifdef WITH_ZLIB
			{ urls[1].name + 1, uncompressed_body, .content_length = sizeof(uncompressed_body) - 1 },
#else
			{ urls[1].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#endif
			{	NULL } },
		0);

	// wget2 should *not* decompress if name ends with .tgz
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, urls[2].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
#ifdef WITH_ZLIB
			{ urls[2].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#else
			{ urls[2].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#endif
			{	NULL } },
		0);

	// wget2 should *not* decompress if name ends with .gz
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, urls[3].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
#ifdef WITH_ZLIB
			{ urls[3].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#else
			{ urls[3].name + 1, compressed_body, .content_length = sizeof(compressed_body) - 1 },
#endif
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
