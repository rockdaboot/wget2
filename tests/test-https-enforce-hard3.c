/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <microhttpd.h>
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost/secondpage.html\">second page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			},
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body = "juhu",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_HTTP_REJECT_CONNECTIONS,
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_TLS,
		0);

#if MHD_VERSION >= 0x00096701 && MHD_VERSION <= 0x00096702
#ifdef __clang__
	#pragma clang diagnostic ignored "-Wunreachable-code"
#endif

	// the logging is enabled after wget_test_start_server()
	wget_error_printf("SKIP due to MHD 0x%08x issue\n", (unsigned) MHD_VERSION);
	exit(WGET_TEST_EXIT_SKIP);
#else
	wget_error_printf("Built with MHD 0x%08x\n", (unsigned) MHD_VERSION);
#endif

	// wget2 downloads from HTTPS though we give an http:// URL
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS,
			"--ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp"
			" --https-enforce=hard --recursive --default-https-port={{sslport}} --default-http-port={{port}} -nH",
		WGET_TEST_REQUEST_URL, "http://localhost/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
