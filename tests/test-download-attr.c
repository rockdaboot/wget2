/*
 * Copyright (c) 2020-2024 Free Software Foundation, Inc.
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
 * Testing the HTML5 download tag and --download-attr
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/page1.html",
			.code = "200 Dontcare",
			.body =
				"<html><head></head>\n"\
				"<body>\n"\
				" <a href=\"image1\" download>image 1</a>." \
				" <a href=\"image2\" download=\"/tmp/sleepingcat.png\">image 2</a>." \
				" <a href=\"image3\">image 3</a>." \
				" <img href=\"image4\" download>image 4</img>." \
				" <img href=\"image5\" download=\"sleepingcat2.png\">image 5</img>." \
				" <img href=\"image6\">image 6</img>." \
				" <a href=\"subdir/image1\" download>image 1</a>." \
				" <a href=\"subdir/image2\" download=\"sleepingcat.png\">image 2</a>." \
				" <a href=\"subdir/image3\">image 3</a>." \
				"</body>\n"\
				"</html>\n",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/image1",
			.code = "200 Dontcare",
			.body = "Image 1",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/image2",
			.code = "200 Dontcare",
			.body = "Image 2",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/image3",
			.code = "200 Dontcare",
			.body = "Image 3",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/image4",
			.code = "200 Dontcare",
			.body = "Image 4",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/image5",
			.code = "200 Dontcare",
			.body = "Image 5",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/image6",
			.code = "200 Dontcare",
			.body = "Image 6",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/subdir/image1",
			.code = "200 Dontcare",
			.body = "Image 7",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/subdir/image2",
			.code = "200 Dontcare",
			.body = "Image 8",
			.headers = {
				"Content-Type: image/png",
			}
		},
		{	.name = "/subdir/image3",
			.code = "200 Dontcare",
			.body = "Image 9",
			.headers = {
				"Content-Type: image/png",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// Download everything as named in href attribute
	wget_test(
		WGET_TEST_OPTIONS, "-nH --no-robots -r",
		WGET_TEST_REQUEST_URL, "page1.html",
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
			{ urls[8].name + 1, urls[8].body },
			{ urls[9].name + 1, urls[9].body },
			{	NULL } },
		0);

	// --download-attr: File names amended by download attribute (only in <a> and <area> tags)
	// check if default is working
	wget_test(
		WGET_TEST_OPTIONS, "-nH --no-robots -r --download-attr",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ "sleepingcat.png", urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ urls[7].name + 1, urls[7].body },
			{ "subdir/sleepingcat.png", urls[8].body },
			{ urls[9].name + 1, urls[9].body },
			{	NULL } },
		0);

	// --download-attr=strippath: File names amended by download attribute (only in <a> and <area> tags)
	// check if 'strippath' default is working
	wget_test(
		WGET_TEST_OPTIONS, "-nH --no-robots -r --download-attr=strippath",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ "sleepingcat.png", urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ urls[7].name + 1, urls[7].body },
			{ "subdir/sleepingcat.png", urls[8].body },
			{ urls[9].name + 1, urls[9].body },
			{	NULL } },
		0);

	// --download-attr=strippath: File names amended by download attribute (only in <a> and <area> tags)
	// check if 'usepath' default is working with paths
	wget_test(
		WGET_TEST_OPTIONS, "-nH --no-robots -r --download-attr=usepath",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ "/tmp/sleepingcat.png", urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ urls[7].name + 1, urls[7].body },
			{ "subdir/sleepingcat.png", urls[8].body },
			{ urls[9].name + 1, urls[9].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
