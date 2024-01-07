/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * Testing for --cut-dirs=x
 *
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/page1.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Page 1</title></head><body>"
				"<p>Hello 1</p><a href=\"subdir/page2.html\">page in subdir</a>"
				"</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/page2.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Page 2</title></head><body><p>Hello 2</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --cut-dirs=1",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "page2.html", urls[1].body },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --cut-dirs=0",
		WGET_TEST_REQUEST_URL, "subdir/page2.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r --cut-dirs=1",
		WGET_TEST_REQUEST_URL, "subdir/page2.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "localhost/page2.html", urls[1].body },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --cut-dirs=1",
		WGET_TEST_REQUEST_URL, "subdir/page2.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "page2.html", urls[1].body },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --cut-dirs=2",
		WGET_TEST_REQUEST_URL, "subdir/page2.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "page2.html", urls[1].body },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r --cut-dirs=2",
		WGET_TEST_REQUEST_URL, "subdir/page2.html",
		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "localhost/page2.html", urls[1].body },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --cut-dirs=-1",
		WGET_TEST_REQUEST_URL, "subdir/page2.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
}
