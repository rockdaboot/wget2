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
 * Testing data-src and data-srcset attribute parsing in HTML
 *
 * Regression test for https://github.com/rockdaboot/wget2/issues/374
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/lazy.html",
			.code = "200 Dontcare",
			.body =
				"<html>\n"\
				"<body>\n"\
				"  <img data-src=\"/lazy1.png\">\n"\
				"  <img data-src=\"/lazy2.png\">\n"\
				"  <img data-src=\"/lazy3.png\">\n"\
				"  <img data-srcset=\"/lazy4.png 100w, /lazy5.png 200w\">\n"\
				"  <img data-src=\"/lazy6.png\" src=\"/normal.jpg\">\n"\
				"</body>\n"\
				"</html>\n",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/lazy1.png",
			.code = "200 Dontcare",
			.body = "LAZY1",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/lazy2.png",
			.code = "200 Dontcare",
			.body = "LAZY2",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/lazy3.png",
			.code = "200 Dontcare",
			.body = "LAZY3",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/lazy4.png",
			.code = "200 Dontcare",
			.body = "LAZY4",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/lazy5.png",
			.code = "200 Dontcare",
			.body = "LAZY5",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/lazy6.png",
			.code = "200 Dontcare",
			.body = "LAZY6",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/normal.jpg",
			.code = "200 Dontcare",
			.body = "NORMAL",
			.headers = {
				"Content-Type: image/jpeg",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test data-src attribute parsing (issue #374)
	wget_test(
		WGET_TEST_OPTIONS, "-nH --no-robots -p -r",
		WGET_TEST_REQUEST_URL, "lazy.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ urls[7].name + 1, urls[7].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
