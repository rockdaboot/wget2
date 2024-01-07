/*
 * Copyright (c) 2022-2024 Free Software Foundation, Inc.
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
 * Testing --directory-prefix
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

#define PREFIX "prefix"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body>secondpage</body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Disposition: attachment; filename=\"filename.html\"",
			}
		},
		{	.name = "/escape.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body>escape</body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Disposition: attachment; filename=\"../filename.html\"",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// Single download
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
//		WGET_TEST_EXECUTABLE, "wget",
		WGET_TEST_OPTIONS, "--directory-prefix=" PREFIX " -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ PREFIX "/index.html", urls[0].body },
			{	NULL } },
		0);

	// Single download with Content-Disposition
	wget_test(
		WGET_TEST_OPTIONS, "--directory-prefix=" PREFIX " --content-disposition -nH",
		WGET_TEST_REQUEST_URL, "secondpage.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ PREFIX "/filename.html", urls[1].body },
			{	NULL } },
		0);

	// Single download with Content-Disposition, trying to escape the directory
	wget_test(
		WGET_TEST_OPTIONS, "--directory-prefix=" PREFIX " --content-disposition -nH",
		WGET_TEST_REQUEST_URL, "escape.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ PREFIX "/filename.html", urls[2].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
