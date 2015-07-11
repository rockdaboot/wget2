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
 * 23.07.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

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
	mget_test_url_t urls[]={
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
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// test-iri-disabled
	mget_test(
		// MGET_TEST_KEEP_TMPFILES, 1,
		MGET_TEST_OPTIONS, "--iri -e robots=off --restrict-file-names=nocontrol -nH -r",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "hello_" ccedilla_u8 eacute_u8 ".html", urls[1].body },
			{	NULL } },
		0);

	exit(0);
}
