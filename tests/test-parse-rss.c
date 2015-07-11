/*
 * Copyright(c) 2013 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Testing Mget
 *
 * Changelog
 * 25.12.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

int main(void)
{
	mget_test_url_t urls[]={
		{	.name = "/main.rss",
			.body =
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"\
"<channel>"\
"<title>Da title</title>"\
"<link>http://localhost:{{port}}/page1.html</link>"\
"<description>Nice article</description>"\
"<item>"\
"<title>Item title</title>"\
"<link>http://localhost:{{port}}/page2.html</link>"\
"<pubDate>Sun, 01 Sep 2013 18:41:05 -0700</pubDate>"\
"<guid isPermaLink=\"true\">http://localhost:{{port}}/page3.html</guid>"\
"<description>item description</description>"\
"</item></channel></rss>",
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
		},
		{	.name = "/page3.html",
			.code = "200 Dontcare",
			.body = "<html>hello3</html>",
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// test--parse-rss
	mget_test(
		// MGET_TEST_KEEP_TMPFILES, 1,
		MGET_TEST_OPTIONS, "--force-rss -i main.rss",
		MGET_TEST_REQUEST_URL, NULL,
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXISTING_FILES, &(mget_test_file_t []) {
			{	"main.rss", urls[0].body },
			{	NULL } },
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{	NULL } },
		0);

	exit(0);
}
