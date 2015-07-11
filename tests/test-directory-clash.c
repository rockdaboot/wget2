/*
 * Copyright(c) 2014 Tim Ruehsen
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
 * Testing file/directory ambiguity
 *
 * Changelog
 * 19.09.2014  Tim Ruehsen  created
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
				"<html><head><title>Main Page</title></head><body><p>Moin" \
				" <a href=\"http://localhost:{{port}}/subdir\">File with same name as directory</a>." \
				" <a href=\"subdir/\">Directory again</a>." \
				" <a href=\"subdir/index.html\">File in directory</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/index2.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>Moin" \
				" <a href=\"subdir/\">Directory</a>." \
				" <a href=\"subdir/index.html\">File in directory</a>." \
				" <a href=\"http://localhost:{{port}}/subdir\">File with same name as directory</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Subdir Page 1</title></head><body><p>Hello 1</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/subdir/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>Hello 2</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
	};

	// functions won't come back if an error occurs
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	mget_test(
		MGET_TEST_OPTIONS, "-r -nH",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[3].name + 1, urls[3].body },
			{ "subdir.1", urls[2].body, 0 }, // filename / directory clash appends .x to the file
			{	NULL } },
		0);

	mget_test(
		MGET_TEST_OPTIONS, "-r -nH",
		MGET_TEST_REQUEST_URL, "index2.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ urls[3].name + 1, urls[3].body },
			{ "subdir.1", urls[2].body, 0 }, // filename / directory clash appends .x to the file
			{	NULL } },
		0);

	exit(0);
}
