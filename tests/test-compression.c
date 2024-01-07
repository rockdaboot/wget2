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
#include <string.h>
#include <stdlib.h> // exit()
#include "libtest.h"

#define uncompressed_body "x"

#define GZIP "\x1f\x8b\x08\x08\x48\x5d\x91\x5a\x00\x03\x78\x00\xab\x00\x00\x83\x16\xdc\x8c\x01\x00\x00\x00"	// gzip
#define DEFLATE "\x78\x9c\xab\x00\x00\x00\x79\x00\x79"	// deflate
#define BZIP2 "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x77\x4b\xb0\x14\x00\x00\x00\x00\x80\x00\x40\x20\x00\x21\x18\x46\x82\xee\x48\xa7\x0a\x12\x0e\xe9\x76\x02\x80"	// bzip2
#define XZ "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\x01\x00\x00\x78\x00\x00\x00\x00\x45\xae\xef\x83\xf8\xee\x16\x0a\x00\x01\x19\x01\xa5\x2c\x81\xcc\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a"	// xz
#define LZMA "\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x3c\x41\xfb\xff\xff\xff\xe0\x00\x00\x00"	// lzma
#define BR "\x21\x00\x00\x04\x78\x03"	// br
#define ZSTD "\x28\xb5\x2f\xfd\x24\x01\x09\x00\x00\x78\x23\x11\x04\x83"
#define LZIP "\x4c\x5a\x49\x50\x01\x0c\x00\x3c\x41\xfb\xff\xff\xff\xe0\x00\x00\x00\x83\x16\xdc\x8c\x01\x00\x00\x00\x00\x00\x00\x00\x25\x00\x00\x00\x00\x00\x00\x00"

typedef struct  {
	const char* body;
	size_t body_len;
	const char* type;
	bool with_lib;
} compression_test_t;

#define KNOWN_TYPES countof(compressions)

int main(void)
{
	compression_test_t compressions[] = {
		{	.body = GZIP,
			.body_len = sizeof(GZIP) - 1,
			.type = "gzip",
			.with_lib =
#ifdef WITH_ZLIB
		true,
#else
		false,
#endif
		},
		{	.body = DEFLATE,
			.body_len = sizeof(DEFLATE) - 1,
			.type = "deflate",
			.with_lib =
#ifdef WITH_ZLIB
		true,
#else
		false,
#endif
		},
		{	.body = BZIP2,
			.body_len = sizeof(BZIP2) - 1,
			.type = "bzip2",
			.with_lib =
#ifdef WITH_BZIP2
		true,
#else
		false,
#endif
		},
		{	.body = XZ,
			.body_len = sizeof(XZ) - 1,
			.type = "xz",
			.with_lib =
#ifdef WITH_LZMA
		true,
#else
		false,
#endif
		},
		{	.body = LZMA,
			.body_len = sizeof(LZMA) - 1,
			.type = "lzma",
			.with_lib =
#ifdef WITH_LZMA
		true,
#else
		false,
#endif
		},
		{	.body = BR,
			.body_len = sizeof(BR) - 1,
			.type = "br",
			.with_lib =
#ifdef WITH_BROTLIDEC
		true,
#else
		false,
#endif
		},
		{	.body = ZSTD,
			.body_len = sizeof(ZSTD) - 1,
			.type = "zstd",
			.with_lib =
#ifdef WITH_ZSTD
		true,
#else
		false,
#endif
		},
		{	.body = LZIP,
			.body_len = sizeof(LZIP) - 1,
			.type = "lzip",
			.with_lib =
#ifdef WITH_LZIP
		true,
#else
		false,
#endif
		},
	};

	wget_test_url_t urls[] = {
		{	.name = "/gzip.html",
			.code = "200 Dontcare",
			.body = compressions[0].body,
			.body_len = compressions[0].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: gzip",
			},
			.expected_req_headers = {
				"Accept-Encoding: gzip"
			}
		},
		{	.name = "/deflate.html",
			.code = "200 Dontcare",
			.body = compressions[1].body,
			.body_len = compressions[1].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: deflate",
			},
			.expected_req_headers = {
				"Accept-Encoding: deflate"
			}
		},
		{	.name = "/bzip2.html",
			.code = "200 Dontcare",
			.body = compressions[2].body,
			.body_len =  compressions[2].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: bzip2",
			},
			.expected_req_headers = {
				"Accept-Encoding: bzip2"
			}
		},
		{	.name = "/xz.html",
			.code = "200 Dontcare",
			.body = compressions[3].body,
			.body_len =  compressions[3].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: xz",
			},
			.expected_req_headers = {
				"Accept-Encoding: xz"
			}
		},
		{	.name = "/lzma.html",
			.code = "200 Dontcare",
			.body = compressions[4].body,
			.body_len =  compressions[4].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: lzma",
			},
			.expected_req_headers = {
				"Accept-Encoding: lzma"
			}
		},
		{	.name = "/br.html",
			.code = "200 Dontcare",
			.body = compressions[5].body,
			.body_len =  compressions[5].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: br",
			},
			.expected_req_headers = {
				"Accept-Encoding: br"
			}
		},
		{	.name = "/zstd.html",
			.code = "200 Dontcare",
			.body = compressions[6].body,
			.body_len =  compressions[6].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: zstd",
			},
			.expected_req_headers = {
				"Accept-Encoding: zstd"
			}
		},
		{	.name = "/lzip.html",
			.code = "200 Dontcare",
			.body = compressions[7].body,
			.body_len =  compressions[7].body_len,
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: lzip",
			},
			.expected_req_headers = {
				"Accept-Encoding: lzip"
			}
		},
		{	.name = "/identity.html",
			.code = "200 Dontcare",
			.body = uncompressed_body,
			.body_len = sizeof(uncompressed_body) - 1,
			.headers = {
				"Content-Type: text/html",
			},
			.expected_req_headers = {
				"Accept-Encoding: identity"
			}
		},
		{	.name = "/no_compression.html",
			.code = "200 Dontcare",
			.body = uncompressed_body,
			.body_len = sizeof(uncompressed_body) - 1,
			.headers = {
				"Content-Type: text/html",
			},
			.unexpected_req_headers = {
				"Accept-Encoding"
			}
		},
		{	.name = "/combination.html",
			.code = "200 Dontcare",
			.body = uncompressed_body,
			.body_len = sizeof(uncompressed_body) - 1,
			.headers = {
				"Content-Type: text/html",
			},
			.expected_req_headers = {
#if defined WITH_BROTLIDEC && defined WITH_LZMA && defined WITH_ZLIB
				"Accept-Encoding: identity, br, lzma, gzip"
#else
				"Accept-Encoding: identity"
#endif
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test all compression types
	for (unsigned int i = 0; i < KNOWN_TYPES; i++) {
		char test_option[64];
		wget_snprintf(test_option, sizeof(test_option), "--compression=%s", compressions[i].type);

		if (compressions[i].with_lib)
			wget_test(
				// WGET_TEST_KEEP_TMPFILES, 1,
				WGET_TEST_OPTIONS, test_option,
				WGET_TEST_REQUEST_URL, urls[i].name + 1,
				WGET_TEST_EXPECTED_ERROR_CODE, 0,
				WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
					{ urls[i].name + 1, uncompressed_body },
					{   NULL } },
				0);
		else
			wget_test(
				// WGET_TEST_KEEP_TMPFILES, 1,
				WGET_TEST_OPTIONS, test_option,
				WGET_TEST_REQUEST_URL, urls[i].name + 1,
				WGET_TEST_EXPECTED_ERROR_CODE, 2,
				0);
	}

	// test none
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--compression=none",
		WGET_TEST_REQUEST_URL, urls[8].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[8].name + 1, uncompressed_body },
			{	NULL } },
		0);

	// test identity
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--compression=identity",
		WGET_TEST_REQUEST_URL, urls[8].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[8].name + 1, uncompressed_body },
			{	NULL } },
		0);

	// test no "Accept-Encoding"
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--no-compression",
		WGET_TEST_REQUEST_URL, urls[9].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[9].name + 1, uncompressed_body },
			{	NULL } },
		0);

    // test invalid type
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--compression=identity,something",
		WGET_TEST_REQUEST_URL, urls[1].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 2,
		0);

	// test set Accept-Encoding to a custom/unknown value
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--no-compression --header=\"Accept-Encoding: identity\"",
		WGET_TEST_REQUEST_URL, urls[8].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[8].name + 1, uncompressed_body },
			{	NULL } },
		0);

	// test --compression override
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--no-compression --compression=identity",
		WGET_TEST_REQUEST_URL, urls[8].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[8].name + 1, uncompressed_body },
			{	NULL } },
		0);

	// test --no-compression override
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--compression=identity --no-compression",
		WGET_TEST_REQUEST_URL, urls[9].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[9].name + 1, uncompressed_body },
			{	NULL } },
		0);

	// test combination
	wget_test(
        // WGET_TEST_KEEP_TMPFILES, 1,
        WGET_TEST_OPTIONS, "--compression=identity,br,lzma,gzip",
        WGET_TEST_REQUEST_URL, urls[10].name + 1,
#if defined WITH_BROTLIDEC && defined WITH_LZMA && defined WITH_ZLIB
        WGET_TEST_EXPECTED_ERROR_CODE, 0,
        WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
            { urls[10].name + 1, uncompressed_body },
            {   NULL } },
#else
        WGET_TEST_EXPECTED_ERROR_CODE, 2,
#endif
		0);

	// test override
	wget_test(
        // WGET_TEST_KEEP_TMPFILES, 1,
        WGET_TEST_OPTIONS, "--compression=br --compression=gzip",
        WGET_TEST_REQUEST_URL, urls[0].name + 1,
#if defined WITH_BROTLIDEC && defined WITH_ZLIB
        WGET_TEST_EXPECTED_ERROR_CODE, 0,
        WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
            { urls[0].name + 1, uncompressed_body },
            {   NULL } },
#else
		WGET_TEST_EXPECTED_ERROR_CODE, 2,
#endif
		0);

	// test duplication
	wget_test(
        // WGET_TEST_KEEP_TMPFILES, 1,
        WGET_TEST_OPTIONS, "--compression=identity,identity",
        WGET_TEST_REQUEST_URL, urls[10].name + 1,
        WGET_TEST_EXPECTED_ERROR_CODE, 2,
		0);

	exit(EXIT_SUCCESS);
}
