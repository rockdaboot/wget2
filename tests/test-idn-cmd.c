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
 * 17.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

// Kon'nichiwa <dot> Japan
#define euc_jp_hostname "\272\243\306\374\244\317.\306\374\313\334"
#ifndef _WIN32
#  define utf8_hostname "\344\273\212\346\227\245\343\201\257.\346\227\245\346\234\254"
#endif
#define punycoded_hostname "xn--v9ju72g90p.xn--wgv71a"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "http://" punycoded_hostname "/index.html",
			.code = "200 Dontcare",
			.body = "What ever",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	char options[256];

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_IDN,
		0);

	// test-idn-cmd
	wget_snprintf(options, sizeof(options),
		"--iri -rH -e http_proxy=localhost:{{port}} -e https_proxy=localhost:{{sslport}} --local-encoding=EUC-JP " euc_jp_hostname);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ punycoded_hostname "/index.html", urls[0].body },
			{	NULL } },
		0);

// UTF-8 command line characters are mangled on MinGW on C locale
#ifndef _WIN32
	// test-idn-cmd
	wget_snprintf(options, sizeof(options),
		"--iri -rH -e http_proxy=localhost:{{port}} -e https_proxy=localhost:{{sslport}} --local-encoding=UTF-8 " utf8_hostname);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ punycoded_hostname "/index.html", urls[0].body },
			{	NULL } },
		0);
#endif

	exit(EXIT_SUCCESS);
}
