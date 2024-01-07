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
		{	.name = "/start.html",
			.code = "200 Dontcare",
			.body =
				"<meta name= \"roBoTS\" content=\"noFolLow ,  foo, bar \">" \
				"<a href=\"/bombshell.html\">Don't follow me!</a>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/mid.html",
			.code = "200 Dontcare",
			.body =
				"<meta name=\"rObOts\" content=\" foo  ,  NOfOllow ,  bar \">" \
				"<a href=\"/bombshell.html\">Don't follow me!</a>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/end.html",
			.code = "200 Dontcare",
			.body =
				"<meta name=\"RoBotS\" content=\"foo,BAr,   nofOLLOw    \">" \
				"<a href=\"/bombshell.html\">Don't follow me!</a>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/solo.html",
			.code = "200 Dontcare",
			.body =
				"<meta name=\"robots\" content=\"nofollow\">" \
				"<a href=\" /bombshell.html\">Don't follow me!</a>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/bombshell.html",
			.code = "200 Dontcare",
			.body = "What ever",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/follow1.html",
			.code = "200 Dontcare",
			.body =
				"<meta name=\"robots\" content=\"follow\">" \
				"<a href=\"/followed1.txt\">Follow me!</a>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/followed1.txt",
			.code = "200 Dontcare",
			.body = "OK1",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/follow2.html",
			.code = "200 Dontcare",
			.body =
				"<meta name=\"robots\" content=\"all\">" \
				"<a href=\"/followed2.txt\">Follow me!</a>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/followed2.txt",
			.code = "200 Dontcare",
			.body = "OK2",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-meta-robots
	wget_test(
		WGET_TEST_OPTIONS, "-r -e robots=on -nd",
		WGET_TEST_REQUEST_URLS, "start.html", "mid.html", "end.html", "solo.html", "follow1.html", "follow2.html", NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{ urls[7].name + 1, urls[7].body },
			{ urls[8].name + 1, urls[8].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
