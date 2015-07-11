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
 * 15.07.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	mget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"second.html\">second page</a>." \
				" <a href=\"htTp://localhost:{{port}}/second.html\">second page</a>." \
				" <a href=\"subdir/third.html\">third page</a>." \
				" <a href=\"htTp://localhost:{{port}}/subdir/third.html\">third page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/second.html",
			.code = "200 Dontcare",
			.body = "<html><head><title>Site</title></head><body>Some Text</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/third.html",
			.code = "200 Dontcare",
			.body = "<html><head><title>Site</title></head><body>Some Text</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
	};

	const char *converted =
		"<html><head><title>Main Page</title></head><body><p>A link to a" \
		" <a href=\"second.html\">second page</a>." \
		" <a href=\"second.html\">second page</a>." \
		" <a href=\"subdir/third.html\">third page</a>." \
		" <a href=\"subdir/third.html\">third page</a>." \
		"</p></body></html>";

	// functions won't come back if an error occurs
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// test-k
	mget_test(
		MGET_TEST_OPTIONS, "-k -r -nH",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, converted },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	exit(0);
}
