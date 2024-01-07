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
 * 23.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

// #define ccedilla_l15 "\xE7"
#define ccedilla_l15_pct "%E7"
#define ccedilla_u8 "\xC3\xA7"
#define ccedilla_u8_pct "%C3%A7"
#define eacute_l15 "\xE9"
#define eacute_u8 "\xC3\xA9"
#define eacute_u8_pct "%C3%A9"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>" \
				"Link to page 1 <a href=\"http://localhost:{{port}}/hello_" ccedilla_l15_pct eacute_l15 ".html\">La seule page en fran&ccedil;ais</a>." \
				"</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=ISO-8859-15",
			}
		},
		{	.name = "/hello_" ccedilla_u8_pct eacute_u8_pct ".html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>La seule page en fran" ccedilla_u8 "ais</title>" \
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-8859-15\"/></head><body>" \
				"<p></p></body></html>",
			.headers = {
				"Content-type: text/html; charset=UTF-8",
			}
		},
		{	.name = "/robots.txt",
			.code = "200 Dontcare",
			.body = "",
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

	// test-iri-disabled
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--iri -e robots=off --local-encoding=utf-8 --restrict-file-names=nocontrol -nH -r",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "hello_" ccedilla_u8 eacute_u8 ".html", urls[1].body, 0, WGET_RESTRICT_NAMES_NOCONTROL },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
