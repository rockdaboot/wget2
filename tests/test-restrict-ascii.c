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
#include <string.h> // strlen()
#include "libtest.h"

static const char *mainpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Don't care.\n\
  </p>\n\
</body>\n\
</html>\n";

int main(void)
{
	wget_test_url_t urls[]={
//		{	.name = "/%CE%B3%CE%BD%CF%89%CF%83%CE%B9%CF%82.html", // "gnosis" in UTF-8 greek
		{	.name = "/%CE%B3%CE%BD%E1%BF%B6%CF%83%CE%B9%CF%82.html", // "gnosis" in UTF-8 greek
			.code = "200 Dontcare",
			.body = mainpage,
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

	// test-restrict-ascii
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--restrict-file-names=ascii --local-encoding=utf-8",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// test-restrict-ascii
/*
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--local-encoding=utf-8",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);
*/
	exit(EXIT_SUCCESS);
}
