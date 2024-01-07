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
 * 15.07.2013  Tim Ruehsen  created
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
	};

	const char *mainpagemangled =
		"<html><head><title>Main Page</title></head><body><p>A link to a" \
		" <a href=\"subpage.php.html\">second page</a>." \
		"</p></body></html>";

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-E-k
	wget_test(
		WGET_TEST_OPTIONS, "-r -nd -E -k",
		WGET_TEST_REQUEST_URL, "index.php",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.php.html", mainpagemangled },
			{ "subpage.php.html", urls[1].body },
			{	NULL } },
		0);

/*
	// test-E-k-K
	wget_test(
		WGET_TEST_OPTIONS, "-r -nd -E -k -K",
		WGET_TEST_REQUEST_URL, "index.php",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.php.html", mainpagemangled },
			{ "index.php.orig", urls[0].body },
			{ "subpage.php.html", urls[1].body },
			{	NULL } },
		0);
*/

	exit(EXIT_SUCCESS);
}
