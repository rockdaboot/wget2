/*
 * Copyright(c) 2018 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = "from HTTPS",
			.headers = {
				"Content-Type: application/gzip",
				"Content-Encoding: gzip",
			},
		},
		// gzipp'ed 0 byte file
		{	.name = "/index2.html",
			.code = "200 Dontcare",
			.body = "\x1f\x8b\x08\x08\xee\x86\x90\x5a\x00\x03\x78\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: gzip",
			},
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// wget2 should not decompress application/gzip
/*	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);
*/
	// wget2 should not decompress text/html
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, urls[1].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
#ifdef WITH_ZLIB
			{ urls[1].name + 1, "" },
#else
			{ urls[1].name + 1, urls[1].body },
#endif
			{	NULL } },
		0);

	exit(0);
}
