/*
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
 * Testing Redirections
 *
 * Changelog
 * 20.10.2015  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "301 Redirect",
			.headers = {
				"Location: http://localhost:{{port}}/index2.html",
			}
		},
		{	.name = "/index2.html",
			.code = "200 Dontcare",
			.body = "<html>hello1</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/301.html",
			.code = "301 Redirect",
			.headers = {
				"Location: /with spaces .html",
			}
		},
		{	.name = "/with spaces .html",
			.code = "200 Dontcare",
			.body = "<html>hello2</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/302.html",
			.code = "302 Redirect",
			.headers = {
				"Location: 302_2.html",
			}
		},
		{	.name = "/302_2.html",
			.code = "200 Dontcare",
			.body = "<html>302</html",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/307.html",
			.code = "307 Temporary Redirect",
			.headers = {
				"Location: http://localhost:{{port}}/307_2.html",
			}
		},
		{	.name = "/307_2.html",
			.code = "200 Dontcare",
			.body = "<html>307</html>",
			.headers = {
				"Content-Type: text/html",
			},
			.expected_method = "POST"
		},
		{	.name = "/robots.txt",
			.code = "302 Redirect",
			.headers = {
				"Location: http://localhost:{{port}}/robots2.txt",
			}
		},
		{	.name = "/robots2.txt",
			.code = "404 Not exist",
			.headers = {
				"Location: http://localhost:{{port}}/robots2.txt",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[1].body },
			{	NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--method=POST",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[1].body },
			{	NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--trust-server-names",
		WGET_TEST_REQUEST_URL, "301.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[3].name + 1, urls[3].body },
			{	NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--method=POST",
		WGET_TEST_REQUEST_URLS, "index.html", "302.html", "307.html", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[1].body },
			{ urls[4].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[7].body },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--retry-on-http-error=301",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[1].body },
			{	NULL } },
		0);

	urls[0].code = "501 Not implemented";
	wget_test(
		WGET_TEST_OPTIONS, "--tries=2 --retry-on-http-error=501",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 4,
		0);

	// Check if we really retried exactly 1x.
	if (system("if [ \"$(grep -c 'HTTP ERROR response 501' ../test-redirection.log)\" != 2 ]; then exit 1; fi"))
		wget_error_printf_exit("Expected exactly 2x 'HTTP ERROR response 501'\n");

	wget_test(
	WGET_TEST_OPTIONS, "--recursive --no-directories",
	WGET_TEST_REQUEST_URL, "index2.html",
	WGET_TEST_EXPECTED_ERROR_CODE, 0,
	WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
		{ urls[1].name + 1, urls[1].body },
		{	NULL } },
	0);

	//for a POST request:
	//	upon receiving 301 response code, redirection request must be GET request
	//	upon receiving 307 response code, redirection request can be POST request

	exit(EXIT_SUCCESS);
}
