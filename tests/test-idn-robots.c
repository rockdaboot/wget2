/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Testing Wget
 *
 * Changelog
 * 15.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

// Kon'nichiwa <dot> Japan
#define euc_jp_hostname "\272\243\306\374\244\317.\306\374\313\334"
#define utf8_hostname "\344\273\212\346\227\245\343\201\257.\346\227\245\346\234\254"
#define punycoded_hostname "xn--v9ju72g90p.xn--wgv71a"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "http://" punycoded_hostname "/index.html",
			.code = "200 Dontcare",
			.body = "<a href=\"http://" euc_jp_hostname "/foo.txt\">The link</a>",
			.headers = {
				"Content-Type: text/html; charset=EUC-JP",
			}
		},
		{	.name = "http://" punycoded_hostname "/foo.txt",
			.code = "200 Dontcare",
			.body = "What ever",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "http://" punycoded_hostname "/robots.txt",
			.code = "200 Dontcare",
			.body = "",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	char options[256];

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_IDN,
		0);

	// test-idn-robots
	snprintf(options, sizeof(options),
		"--iri -e robots=on -rH -e http_proxy=localhost:%d --local-encoding=EUC-JP http://" euc_jp_hostname "/",
		wget_test_get_http_server_port());

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ punycoded_hostname "/index.html", urls[0].body },
			{ punycoded_hostname "/foo.txt", urls[1].body },
			{ punycoded_hostname "/robots.txt", urls[2].body },
			{	NULL } },
		0);

	// test-idn-robots-utf8
	snprintf(options, sizeof(options),
		"--iri -e robots=on -rH -e http_proxy=localhost:%d --local-encoding=UTF-8 http://" utf8_hostname "/",
		wget_test_get_http_server_port());

	urls[0].body = "<a href=\"http://" utf8_hostname "/foo.txt\">The link</a>";
	urls[0].headers[0] = "Content-Type: text/html; charset=UTF-8";

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ punycoded_hostname "/index.html", urls[0].body },
			{ punycoded_hostname "/foo.txt", urls[1].body },
			{ punycoded_hostname "/robots.txt", urls[2].body },
			{	NULL } },
		0);

	exit(0);
}
