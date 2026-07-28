/*
 * Copyright (c) 2024-2026 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <errno.h>
#include "libtest.h"

static bool has_ipv4(void)
{
#ifdef __linux__
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		close (sock);
		return true;
	}
	return false;
#else
	return false;
#endif
}

int main(void)
{
	// This test uses 127.0.0.2 and 127.0.0.3 as test "domains"
	// which all resolve to localhost on Linux, if IPv4 is enabled.
	// Skip on other platforms.
	if (!has_ipv4()) {
		printf("Test skipped: requires Linux and IPv4 (127/8 IP range for localhost)\n");
		exit(WGET_TEST_EXIT_SKIP);
	}

	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body>" \
				"<p>Image from allowed domain: <img src=\"http://127.0.0.2:{{port}}/allowed/image.jpg\"/></p>" \
				"<p>Link to allowed domain: <a href=\"http://127.0.0.2:{{port}}/allowed/page.html\">Allowed Page</a></p>" \
				"<p>Image from NOT allowed domain: <img src=\"http://127.0.0.3:{{port}}/notallowed/image.jpg\"/></p>" \
				"<p>Link to NOT allowed domain: <a href=\"http://127.0.0.3:{{port}}/notallowed/page.html\">Not Allowed Page</a></p>" \
				"</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/allowed/page.html",
			.code = "200 Dontcare",
			.body = "ALLOWED PAGE CONTENT",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/allowed/image.jpg",
			.code = "200 Dontcare",
			.body = "ALLOWED IMAGE DATA",
			.headers = {
				"Content-Type: image/jpeg",
			}
		},
		{	.name = "/notallowed/page.html",
			.code = "200 Dontcare",
			.body = "NOT ALLOWED PAGE CONTENT",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/notallowed/image.jpg",
			.code = "200 Dontcare",
			.body = "NOT ALLOWED IMAGE DATA",
			.headers = {
				"Content-Type: image/jpeg",
			}
		},
	};

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// Test 1: download from all
	wget_test(
		WGET_TEST_OPTIONS, "-r --span-hosts -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body }, // main page (127.0.0.1)
			{ urls[1].name + 1, urls[1].body }, // allowed/page.html from 127.0.0.2
			{ urls[2].name + 1, urls[2].body }, // allowed/image.jpg from 127.0.0.2
			{ urls[3].name + 1, urls[3].body }, // notallowed/page.html from 127.0.0.3
			{ urls[4].name + 1, urls[4].body }, // notallowed/image.jpg from 127.0.0.3
			{ NULL } },
		0);

	// Test 2: explicitly not download from 127.0.0.3
	wget_test(
		WGET_TEST_OPTIONS, "-r --span-hosts --exclude-domains=127.0.0.3 -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body }, // main page (127.0.0.1)
			{ urls[1].name + 1, urls[1].body }, // allowed/page.html from 127.0.0.2
			{ urls[2].name + 1, urls[2].body }, // allowed/image.jpg from 127.0.0.2
			{ NULL } },
		0);

	// Test 4: explicitly not download from both
	wget_test(
		WGET_TEST_OPTIONS, "-r --span-hosts ----exclude-domains=127.0.0.2,127.0.0.3 -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body }, // main page (127.0.0.1)
			{ NULL } },
		0);

	// Test 5: download only from 127.0.0.1
	wget_test(
		WGET_TEST_OPTIONS, "-r --no-span-hosts -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body }, // main page (127.0.0.1)
			// NOT downloaded: anything from 127.0.0.2 or 127.0.0.3
			{ NULL } },
		0);

	// Test 6: also download from 127.0.0.2
	wget_test(
		WGET_TEST_OPTIONS, "-r --no-span-hosts --domains=127.0.0.2 -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body }, // main page (127.0.0.1)
			{ urls[1].name + 1, urls[1].body }, // allowed/page.html from 127.0.0.2
			{ urls[2].name + 1, urls[2].body }, // allowed/image.jpg from 127.0.0.2
			// NOT downloaded: anything from 127.0.0.3
			{ NULL } },
		0);

	// Test  7: also download from both
	wget_test(
		WGET_TEST_OPTIONS, "-r --no-span-hosts --domains=127.0.0.2,127.0.0.3 -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body }, // main page (127.0.0.1)
			{ urls[1].name + 1, urls[1].body }, // allowed/page.html from 127.0.0.2
			{ urls[2].name + 1, urls[2].body }, // allowed/image.jpg from 127.0.0.2
			{ urls[3].name + 1, urls[3].body }, // notallowed/page.html from 127.0.0.3
			{ urls[4].name + 1, urls[4].body }, // notallowed/image.jpg from 127.0.0.3
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
}
