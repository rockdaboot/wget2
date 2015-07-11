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
 * 17.07.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
#include "libtest.h"

#define ccedilla_l15 "\xE7"
#define ccedilla_u8 "\xC3\xA7"
#define eacute_l15 "\xE9"
#define eacute_u8 "\xC3\xA9"
#define eurosign_l15 "\xA4"
#define eurosign_u8 "\xE2\x82\xAC"

int main(void)
{
	mget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"Link to page 1 <a href=\"http://localhost:{{port}}/p1_fran" ccedilla_l15 "ais.html\">La seule page en fran&ccedil;ais</a>." \
				"Link to page 3 <a href=\"http://localhost:{{port}}/p3_" eurosign_l15 eurosign_l15 eurosign_l15 ".html\">My tailor is rich</a>.",
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
		{	.name = "/p1_fran%E7ais.html",
			.code = "404 Not found",
			.body =
				"<html><head><title>404</title></head><body><p>What ever</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=UTF-8",
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
				"Content-type: text/html; charset=ISO-8859-15", // server response overrides META charset attribute
			}
		},
		{	.name = "/p2_%C3%A9%C3%A9n.html", // UTF-8 encoded
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Die enkele nederlandstalige pagina</title>" \
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-8859-15\"/>" \
				"</head><body><p>&Eacute;&eacute;n is niet veel maar toch meer dan nul.<br/>" \
				"Nerdelands is een mooie taal... dit zin stuckje spreekt vanzelf, of niet :)<br/>" \
				"<a href=\"http://localhost:{{port}}/p4_m" eacute_u8 eacute_u8 "r.html\">M&eacute&eacute;r</a>" \
				"</p></body></html>",
			.headers = {
				"Content-type: text/html; charset=UTF-8", // server response overrides META charset attribute
			},
		},
		{	.name = "/p3_%E2%82%AC%E2%82%AC%E2%82%AC.html", // UTF-8 encoded
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Euro page</title>" \
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>" \
				"</head><body><p>My tailor isn't rich anymore.</p></body></html>",
			.headers = {
				"Content-type: text/plain; charset=ISO-8859-15",
			},
		},
		{	.name = "/p3_%A4%A4%A4.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Euro page</title>" \
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>" \
				"</head><body><p>My tailor isn't rich anymore.</p></body></html>",
			.headers = {
				"Content-type: text/plain; charset=ISO-8859-15",
			},
		},
		{	.name = "/p4_m%C3%A9%C3%A9r.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Bekende supermarkt</title></head>" \
				"<body><p>Ik ben toch niet gek !</p></body></html>",
			.headers = {
				"Content-type: text/plain; charset=UTF-8",
			},
		},
	};

	char request_header[256];

	// functions won't come back if an error occurs
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// test-iri
	snprintf(request_header, sizeof(request_header),
		"Referer: http://localhost:%d/p2_%%C3%%A9%%C3%%A9n.html",
		mget_test_get_http_server_port());
	urls[4].request_headers[0] = urls[7].request_headers[0] = request_header;

	mget_test(
//		MGET_TEST_KEEP_TMPFILES, 1,
		MGET_TEST_OPTIONS, "--iri -e robots=on --trust-server-names --restrict-file-names=nocontrol -nH -r",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ "p1_fran" ccedilla_u8 "ais.html", urls[3].body },
			{ "p2_" eacute_u8 eacute_u8 "n.html", urls[4].body },
			{ "p3_" eurosign_u8 eurosign_u8 eurosign_u8 ".html", urls[5].body },
			{ "p4_m" eacute_u8 eacute_u8 "r.html", urls[7].body },
			{	NULL } },
		0);

	exit(0);
}
