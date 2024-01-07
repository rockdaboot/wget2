/*
 * Copyright (c) 2014 Tim Ruehsen
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
 * 02.07.2014  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/firstlevel/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <A hreF=\"http://localhost:{{port}}/firstlevel/secondpage.html\">second page</a>." \
				" <a href=\"file://path/file_to_be_ignored.txt\">Unsupported file scheme</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/firstlevel/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>A link to a" \
				" <a hRef=\"http://localhost:{{port}}/firstlevel/lowerlevel/thirdpage.html\">third page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/firstlevel/lowerlevel/thirdpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Third Page</title></head><body><p>A link to a" \
				" <A href=\"http://localhost:{{port}}/index.html\">higher level page</a>." \
				" <A href=\"http://localhost:{{port}}\">higher level page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/firstlevel/fourthpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Fourth Page</title></head><body><p>" \
				"This page is only linked by the higher level page. Therefore, it should not be downloaded." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Higher Level Page</title></head><body><p>" \
				"This page is on a higher level in the URL path hierarchy. Therefore, it" \
				"should not be downloaded. Wget should not visit the following link to a" \
				" <a Href=\"http://localhost:{{port}}/firstlevel/fourthpage.html\">fourth page</a>." \
				"</p></body></html>",
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

	// test-i
	wget_test(
		WGET_TEST_OPTIONS, "-np -nH -r",
		WGET_TEST_REQUEST_URL, "firstlevel/",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
