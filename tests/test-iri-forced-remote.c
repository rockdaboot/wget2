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
 * 27.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

#define ccedilla_l15 "\xE7"
#define ccedilla_u8 "\xC3\xA7"
#define eurosign_l15 "\xA4"
#define eurosign_u8 "\xE2\x82\xAC"
#define eacute_l15 "\xE9"
#define eacute_u8 "\xC3\xA9"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>" \
				"Link to page 1 <a href=\"http://localhost:{{port}}/p1_fran" ccedilla_l15 "ais.html\">La seule page en fran&ccedil;ais</a>." \
				"Link to page 1 <a href=\"http://localhost:{{port}}/p3_" eurosign_l15 eurosign_l15 eurosign_l15 ".html\">My tailor is rich</a>." \
				"</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=ISO-8859-15",
			}
		},
		{	.name = "/robots.txt",
			.code = "200 Dontcare",
			.body = "",
			.headers = {
				"Content-type: text/plain",
			}
		},
		{	.name = "/p1_fran%C3%A7ais.html", // UTF-8 encoded
			.code = "200 Dontcare",
			.body =
				"<html><head><title>La seule page en fran" ccedilla_l15 "ais</title>" \
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/></head><body>" \
				"<p>Link to page 2 <a href=\"http://localhost:{{port}}/p2_" eacute_l15 eacute_l15 "n.html\">Die enkele nerderlangstalige pagina</a>." \
				"</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=ISO-8859-15", // overrides META tag in document
			}
		},
		{	.name = "/p2_%C3%A9%C3%A9n.html", // UTF-8 encoded
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Die enkele nederlandstalige pagina</title>" \
				"</head><body><p>&Eacute;&eacute;n is niet veel maar toch meer dan nul.<br/>" \
				"Nerdelands is een mooie taal... dit zin stuckje spreekt vanzelf, of niet :)<br/>" \
				"</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=UTF-8",
			},
		},
		{	.name = "/p2_%E9%E9n.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Die enkele nederlandstalige pagina</title>" \
				"</head><body><p>&Eacute;&eacute;n is niet veel maar toch meer dan nul.<br/>" \
				"Nerdelands is een mooie taal... dit zin stuckje spreekt vanzelf, of niet :)<br/>" \
				"</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=ISO-8859-1",
			},
		},
		{	.name = "/p3_%E2%82%AC%E2%82%AC%E2%82%AC.html", // UTF-8 encoded
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Euro page</title>" \
				"</head><body><p>My tailor isn't rich anymore.</p></body></html>",
			.headers = {
				"Content-type: text/plain",
			},
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
		WGET_TEST_OPTIONS, "-e robots=on --trust-server-names --local-encoding=UTF-8 --remote-encoding=iso-8859-1 -nH -r",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ "p1_fran" ccedilla_u8 "ais.html", urls[2].body },
			{ "p2_" eacute_u8 eacute_u8 "n.html", urls[3].body },
			{ "p3_" eurosign_u8 eurosign_u8 eurosign_u8 ".html", urls[5].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
