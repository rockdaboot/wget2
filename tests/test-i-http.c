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
 * 08.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/urls.txt",
			.code = "200 Dontcare",
			.body = "http://localhost:{{port}}/page1.html\nhttp://localhost:{{port}}/page2.html\n",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/page1.html",
			.code = "200 Dontcare",
			.body = "<html>hello1</html>",
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
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-i
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "-i urls.txt",
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"urls.txt", urls[0].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);
/*
	// test-i-http (expands to -i http://localhost:{{port}}/urls.txt)
	wget_test(
		WGET_TEST_OPTIONS, "-i",
		WGET_TEST_REQUEST_URL, "urls.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);
*/
	exit(EXIT_SUCCESS);
}
