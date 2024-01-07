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
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = "from HTTPS",
			.headers = {
				"Content-Type: text/plain",
			},
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_HTTPS_REJECT_CONNECTIONS,
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_TLS,
		0);

	// we don't start a HTTPS server, so we expect no fallback to HTTP and a exit code of 4
	// depending on the network stack and timing, we see different failures (handshake or network error)
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp --https-enforce=hard --default-https-port={{sslport}} --default-http-port={{port}}",
		WGET_TEST_REQUEST_URL, "http://localhost/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE2, 5, // TLS handshake error
		WGET_TEST_EXPECTED_ERROR_CODE,  4, // network error
		0);

	exit(EXIT_SUCCESS);
}
