/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * Testing --convert-file-only
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.php",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"//localhost:{{port}}/subpage.php\">second page</a>." \
				" <a href=\"//localhost:{{port}}/thirdpage\">third page</a>." \
				" <a href=\"http://localhost:{{port}}/page4\">page4</a>." \
				" <a href=\"/page5\">page5</a>." \
				" <a href=\"page6\">page6</a>." \
				" <a href=\"/subdir/page7\">page7</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subpage.php",
			.code = "200 Dontcare",
			.body = "<html><head><title>Sub Page</title></head><body>Some Text</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page5",
			.code = "200 Dontcare",
			.body = "<html><head><title>Page 5</title></head><body>Some Text</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/page7",
			.code = "200 Dontcare",
			.body = "<html><head><title>Page 7</title></head><body>Some Text</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},

	};

	const char *mainpagemangled =
		"<html><head><title>Main Page</title></head><body><p>A link to a" \
		" <a href=\"//localhost:{{port}}/subpage.php.html\">second page</a>." \
		" <a href=\"//localhost:{{port}}/thirdpage\">third page</a>." \
		" <a href=\"http://localhost:{{port}}/page4\">page4</a>." \
		" <a href=\"/page5.html\">page5</a>." \
		" <a href=\"page6\">page6</a>." \
		" <a href=\"/subdir/page7.html\">page7</a>." \
		"</p></body></html>";

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// href should get updated for subpage
	// href should not get updated for thirdpage
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-r -nH -E --convert-file-only",
		WGET_TEST_REQUEST_URL, "index.php",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.php.html", mainpagemangled },
			{ "subpage.php.html", urls[1].body },
			{ "page5.html", urls[2].body },
			{ "subdir/page7.html", urls[3].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
