/*
 * Copyright (c) 2013 Tim Ruehsen
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
 * Testing Wget
 *
 * Changelog
 * 17.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

// Kon'nichiwa <dot> Japan
#define euc_jp_hostname "\272\243\306\374\244\317.\306\374\313\334"
#define punycoded_hostname "xn--v9ju72g90p.xn--wgv71a"

// The charset in the document's META tag is stated wrong by purpose (UTF-8).
// The charset in the response header has priority and is correct (EUC-JP)

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "http://start-here.com/start.html",
			.code = "200 Dontcare",
			.body =
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />" \
				"<a href=\"http://" euc_jp_hostname "/\">The link</a>",
			.headers = {
				"Content-Type: text/html; charset=EUC-JP",
			}
		},
		// HTML5 version with meta charset
		{	.name = "http://start-here.com/start2.html",
			.code = "200 Dontcare",
			.body =
				"<meta http-equiv=\"Content-Type\" content=\"text/html\" />" \
				"<meta charset=\"UTF-8\" />" \
				"<a href=\"http://" euc_jp_hostname "/\">The link</a>",
			.headers = {
				"Content-Type: text/html; charset=EUC-JP",
			}
		},
		{	.name = "http://" punycoded_hostname "/index.html",
			.code = "200 Dontcare",
			.body = "What ever",
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

	// test-idn-meta
	wget_snprintf(options, sizeof(options),
		"--iri -rH -e http_proxy=localhost:{{port}} -e https_proxy=localhost:{{sslport}} http://start-here.com/start.html");

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "start-here.com/start.html", urls[0].body },
			{ punycoded_hostname "/index.html", urls[2].body },
			{	NULL } },
		0);

	// test-idn-headers
	urls[0].body = "<a href=\"http://" euc_jp_hostname "/\">The link</a>";
	urls[0].headers[0] = "Content-Type: text/html; charset=EUC-JP";

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "start-here.com/start.html", urls[0].body },
			{ punycoded_hostname "/index.html", urls[2].body },
			{	NULL } },
		0);

	// test-idn-meta with HTML5 meta charset
	wget_snprintf(options, sizeof(options),
		"--iri -rH -e http_proxy=localhost:{{port}} -e https_proxy=localhost:{{sslport}} http://start-here.com/start2.html");
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "start-here.com/start2.html", urls[1].body },
			{ punycoded_hostname "/index.html", urls[2].body },
			{	NULL } },
		0);

	// test-idn-headers
	urls[1].body = "<a href=\"http://" euc_jp_hostname "/\">The link</a>";
	urls[1].headers[0] = "Content-Type: text/html; charset=EUC-JP";

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "start-here.com/start2.html", urls[1].body },
			{ punycoded_hostname "/index.html", urls[2].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
