/*
 * Copyright (c) 2025 Free Software Foundation, Inc.
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
 * Testing -k (convert-links) with percent-encoded characters in query strings
 * This test reproduces the bug where URLs with %2C (comma) and %7C (pipe)
 * in the query string fail to be converted because of preprocessing mismatch.
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/home.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Home Page</title>" \
				"<link href=\"http://localhost:{{port}}/css?family=Montserrat%3A400%2C700%7CBitter%3A400%2C700&display=swap\" rel=\"stylesheet\">" \
				"</head><body><p>Main page with external font link.</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/css?family=Montserrat%3A400%2C700%7CBitter%3A400%2C700&display=swap",
			.code = "200 Dontcare",
			.body = "/* Mock CSS file */ body { font-family: Montserrat; }",
			.headers = {
				"Content-Type: text/css",
			}
		},
	};

	// After conversion, the link should be converted to a relative path
	// The query string with %2C and %7C should be decoded to , and | in the filename
	// during both initial parsing and link conversion, so the final converted link should reference
	// the actual downloaded filename. Since the filename contains special characters (?, |, ,, %),
	// these need to be percent-encoded in the HTML link to properly reference the file.
	// Since we use -nH (no host directories), files from different hosts are in the same directory
	const char *converted =
		"<html><head><title>Home Page</title>" \
		"<link href=\"css%3Ffamily=Montserrat%253A400,700%7CBitter%253A400,700&display=swap\" rel=\"stylesheet\">" \
		"</head><body><p>Main page with external font link.</p></body></html>";

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-k with percent-encoded commas and pipes in query string
	// The link should be converted to relative path pointing to downloaded file
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-k -r -nH -p",
		WGET_TEST_REQUEST_URL, "home.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "home.html", converted },
			{ "css?family=Montserrat%3A400,700|Bitter%3A400,700&display=swap", urls[1].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
