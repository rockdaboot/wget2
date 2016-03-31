/*
 * Copyright(c) 2016 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Test Metalink functionality
 * - --no-follow-metalink
 * - Metalink V3
 * - Metalink V4
 * - Metalink HTTP
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
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
	};

	char md5hex[32 + 1], md5hex_p1[32 + 1], md5hex_p2[32 + 1];

	wget_md5_printf_hex(md5hex, "%s", urls[1].body);
	urls[0].body = wget_str_asprintf(
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

	wget_md5_printf_hex(md5hex, "%s", urls[3].body);
	urls[2].body = wget_str_asprintf(
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

	wget_md5_printf_hex(md5hex, "%s", urls[5].body);
	wget_md5_printf_hex(md5hex_p1, "%.5s", urls[5].body);
	wget_md5_printf_hex(md5hex_p2, "%.5s", urls[5].body + 5);
	urls[4].body = wget_str_asprintf(
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

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// --no-follow-metalink
	wget_test(
		WGET_TEST_OPTIONS, "--no-follow-metalink",
		WGET_TEST_REQUEST_URL, "archive.meta",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ NULL } },
		0);

	// metalink V3, no pieces
	wget_test(
		// WGET_TEST_OPTIONS, "-d",
		WGET_TEST_REQUEST_URL, "archive.meta",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
		0);

	// metalink V4, no pieces
	wget_test(
		// WGET_TEST_OPTIONS, "-d",
		WGET_TEST_REQUEST_URL, "archive.meta4",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[3].name + 1, urls[3].body },
			{ NULL } },
		0);

	// metalink V4, two pieces
	wget_test(
		// WGET_TEST_OPTIONS, "-d",
		WGET_TEST_REQUEST_URL, "archiveP.meta4",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[5].name + 1, urls[5].body },
			{ NULL } },
		0);
	exit(0);
}
