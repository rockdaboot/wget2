/*
 * Copyright (c) 2016-2024 Free Software Foundation, Inc.
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
 * Test Metalink functionality
 * - --no-metalink
 * - Metalink V3 (single file & pieces)
 * - Metalink V4 (single file & pieces)
 * - Metalink HTTP (direct & via metalink xml)
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h>
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/archive.meta",
			.code = "200 Dontcare",
			.headers = {
				"Content-Type: application/metalink+xml",
			}
		},
		{	.name = "/archive.gz",
			.code = "200 Dontcare",
			.body = "1234567890",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/archive.meta4",
			.code = "200 Dontcare",
			.headers = {
				"Content-Type: application/metalink4+xml",
			}
		},
		{	.name = "/archive4.gz",
			.code = "200 Dontcare",
			.body = "0987654321",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/archiveP.meta4",
			.code = "200 Dontcare",
			.headers = {
				"Content-Type: application/metalink4+xml",
			}
		},
		{	.name = "/archiveP.gz",
			.code = "200 Dontcare",
			.body = "1122334455",
			.headers = {
				"Content-Type: text/plain",
			}
		},

		/**** RFC 6249 Metalink/HTTP: Mirrors and Hashes  - with metalink description ****/
		{	.name = "/archiveH1.gz",
			.code = "302 Not found",
			.body = "",
			.headers = {
				"Content-Type: text/plain",
				"Link: <http://localhost:{{port}}/archiveH1.meta4>; rel=describedby; type=\"application/metalink4+xml\"",
				"Link: <http://localhost:{{port}}/download/archiveH1.gz>; rel=duplicate; pri=1; geo=de",
				"Location: http://localhost:{{port}}/download/archiveH1.gz",
//				"Digest: MD5=/sr/WFcZH1MKTyt3JHL2tA==",
			}
		},
		{	.name = "/archiveH1.meta4",
			.code = "200 Dontcare",
			.headers = {
				"Content-Type: application/metalink4+xml",
			}
		},
		{	.name = "/download/archiveH1.gz",
			.code = "200 Dontcare",
			.body = "1112223334",
			.headers = {
				"Content-Type: text/plain",
			}
		},

		/**** RFC 6249 Metalink/HTTP: Mirrors and Hashes  - without metalink description ****/
		{	.name = "/archiveH2.gz",
			.code = "302 Not found",
			.body = "",
			.headers = {
				"Content-Type: text/plain",
				"Link: <http://localhost:{{port}}/download/archiveH2.gz>; rel=duplicate; pri=1; geo=de",
				"Location: http://localhost:{{port}}/download/archiveH2.gz",
//				"Digest: MD5=/sr/WFcZH1MKTyt3JHL2tA==",
			}
		},
		{	.name = "/download/archiveH2.gz",
			.code = "200 Dontcare",
			.body = "1115553334",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	// int hashlen = wget_hash_get_len(WGET_DIGTYPE_MD5); // 20
	char md5hex[20 * 2 + 1], md5hex_p1[20 * 2 + 1], md5hex_p2[20 * 2 + 1];
	unsigned char digest[20];
	char *body0, *body2, *body4, *body7; // to be freed later

	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex, sizeof(md5hex), "%s", urls[1].body);
	urls[0].body = body0 = wget_aprintf(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<metalink version=\"3.0\">"
		"<files>"
		"<file name=\"%s\">"
		"<size>%zu</size>"
		"<verification>"
		"<hash type=\"md5\">%s</hash>"
		"</verification>"
		"<resources>"
		"<url protocol=\"rsync\" type=\"rsync\" location=\"DE\" preference=\"100\">rsync://host/fake.gz</url>"
		"<url protocol=\"http\" type=\"http\" location=\"DE\" preference=\"99\">http://localhost:{{port}}/%s</url>"
		"</resources>"
		"</file>"
		"</files>"
		"</metalink>",
		urls[1].name + 1, strlen(urls[1].body), md5hex, urls[1].name + 1);

	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex, sizeof(md5hex), "%s", urls[3].body);
	urls[2].body = body2 = wget_aprintf(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<metalink version=\"3.0\">"
		"<file name=\"%s\">"
		"<size>%zu</size>"
		"<hash type=\"md5\">%s</hash>"
		"<url location=\"DE\" preference=\"100\">rsync://host/fake.gz</url>"
		"<url location=\"DE\" preference=\"99\">http://localhost:{{port}}/%s</url>"
		"</file>"
		"</metalink>",
		urls[3].name + 1, strlen(urls[3].body), md5hex, urls[3].name + 1);

	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex, sizeof(md5hex), "%s", urls[5].body);
	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex_p1, sizeof(md5hex_p1), "%.5s", urls[5].body);
	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex_p2, sizeof(md5hex_p2), "%.5s", urls[5].body + 5);
	urls[4].body = body4 = wget_aprintf(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<metalink version=\"3.0\">"
		"<file name=\"%s\">"
		"<size>%zu</size>"
		"<hash type=\"md5\">%s</hash>"
		"<pieces length=\"%zu\" type=\"md5\">"
		"<hash>%s</hash>"
		"<hash>%s</hash>"
		"</pieces>"
		"<url location=\"DE\" preference=\"100\">rsync://host/fake.gz</url>"
		"<url location=\"DE\" preference=\"99\">http://localhost:{{port}}/%s</url>"
		"</file>"
		"</metalink>",
		urls[5].name + 1, strlen(urls[5].body), md5hex, strlen(urls[5].body) / 2,
		md5hex_p1, md5hex_p2, urls[5].name + 1);

	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex, sizeof(md5hex), "%s", urls[8].body);
	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex_p1, sizeof(md5hex_p1), "%.5s", urls[8].body);
	wget_hash_printf_hex(WGET_DIGTYPE_MD5, md5hex_p2, sizeof(md5hex_p2), "%.5s", urls[8].body + 5);
	urls[7].body = body7 = wget_aprintf(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<metalink version=\"3.0\">"
		"<file name=\"%s\">"
		"<size>%zu</size>"
		"<hash type=\"md5\">%s</hash>"
		"<pieces length=\"%zu\" type=\"md5\">"
		"<hash>%s</hash>"
		"<hash>%s</hash>"
		"</pieces>"
		"<url location=\"DE\" preference=\"100\">rsync://host/fake.gz</url>"
		"<url location=\"DE\" preference=\"99\">http://localhost:{{port}}/%s</url>"
		"</file>"
		"</metalink>",
		urls[6].name + 1, strlen(urls[8].body), md5hex, strlen(urls[8].body) / 2,
		md5hex_p1, md5hex_p2, urls[8].name + 1);

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_SKIP_H2,
		0);

	// --no-metalink
	wget_test(
		WGET_TEST_OPTIONS, "--no-metalink",
		WGET_TEST_REQUEST_URL, "archive.meta",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ NULL } },
		0);

	// metalink V3, no pieces
	wget_test(
		WGET_TEST_REQUEST_URL, "archive.meta",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
		0);

	// metalink V3, no pieces, as input file
	wget_test(
		WGET_TEST_OPTIONS, "--force-metalink -i archive.meta",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "archive.meta", urls[0].body },
			{ NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "archive.meta", urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
		0);

	// metalink V4, no pieces
	wget_test(
		WGET_TEST_REQUEST_URL, "archive.meta4",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[3].name + 1, urls[3].body },
			{ NULL } },
		0);

	// metalink V4, two pieces
	wget_test(
		WGET_TEST_REQUEST_URL, "archiveP.meta4",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[5].name + 1, urls[5].body },
			{ NULL } },
		0);

	// metalink V4, two pieces, as input file
	wget_test(
		WGET_TEST_OPTIONS, "--force-metalink -i archiveP.meta4",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "archiveP.meta4", urls[4].body },
			{ NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "archiveP.meta4", urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ NULL } },
		0);

	char *digest_str = NULL;
	/**** RFC 6249 Metalink/HTTP: Mirrors and Hashes  - with metalink description ****/
	wget_hash_fast(WGET_DIGTYPE_MD5, urls[8].body, strlen(urls[8].body), digest);
	digest_str = wget_base64_encode_alloc((const char *)digest, sizeof(digest));
	urls[6].headers[4] = wget_aprintf("Digest: MD5=%s", digest_str);

	wget_test(
//		WGET_TEST_OPTIONS, "--tries=1",
		WGET_TEST_REQUEST_URL, urls[6].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[6].name + 1, urls[8].body },
			{ NULL } },
		0);

	wget_free(digest_str);

	/**** RFC 6249 Metalink/HTTP: Mirrors and Hashes  - without metalink description ****/
	wget_hash_fast(WGET_DIGTYPE_MD5, urls[10].body, strlen(urls[10].body), digest);
	digest_str = wget_base64_encode_alloc((const char *)digest, sizeof(digest));
	urls[9].headers[3] = wget_aprintf("Digest: MD5=%s", digest_str);

	wget_test(
		WGET_TEST_OPTIONS, "--tries=1",
		WGET_TEST_REQUEST_URL, urls[9].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[9].name + 1, urls[10].body },
			{ NULL } },
		0);

	wget_free(digest_str);

	wget_free(body0);
	wget_free(body2);
	wget_free(body4);
	wget_free(body7);
	wget_free((void *)urls[6].headers[4]);
	wget_free((void *)urls[9].headers[3]);

	exit(EXIT_SUCCESS);
}
