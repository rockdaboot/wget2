/*
 * Copyright(c) 2015 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Testing 'base' html tag
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title><base href=\"/subdir/\"></head><body><p>A link to a" \
				" <A hreF=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				" <a  HreF=\"thirdpage.html?query&param#frag\">third page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body = "second"
		},
		{	.name = "/subdir/thirdpage.html?query&param",
			.code = "200 Dontcare",
			.body = "third"
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// test-i
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --no-robots",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	// test-O/dev/null
	wget_test(
		WGET_TEST_OPTIONS, "-O/dev/null",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	exit(0);
}
