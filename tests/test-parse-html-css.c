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
 * Testing HTML CSS parsing
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
				"<html>\n"\
				"<head>\n"\
				"  <style> #test1{background:url(/page2.html) no-repeat center} </style>\n"\
				"  <style> #test2{background:url(\"/page3.html\") no-repeat center} </style>\n"\
				"</head>\n"\
				"<body>\n"\
				"  <div style=\"background:url(/page4.html) no-repeat center; \"></div>\n"\
				"</body>\n"\
				"</html>\n",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page2.html",
			.code = "200 Dontcare",
			.body = "<html>hello2</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page3.html",
			.code = "200 Dontcare",
			.body = "<html>hello3</html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/page4.html",
			.code = "200 Dontcare",
			.body = "<html>hello4</html>",
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test--parse-html-css
	wget_test(
		WGET_TEST_OPTIONS, "-nH --no-robots -r",
		WGET_TEST_REQUEST_URL, "page1.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{	NULL } },
		0);

	char options[128];
	wget_snprintf(options, sizeof(options),
		"--force-html --base http://localhost:{{port}} -i page1.html");

	// test--parse-html-css from file
	wget_test(
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	urls[0].name + 1, urls[0].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
