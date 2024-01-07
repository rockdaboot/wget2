/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * Testing for post handshake authentication using 'WGET_TEST_POST_HANDSHAKE_AUTH'
 * `WGET_TEST_POST_HANDSHAKE_AUTH, 0`	(Don't check)
 * Check otherwise
 *
 */

#include <config.h>

#include <stdlib.h>

#include "libtest.h"

#ifdef WITH_GNUTLS
#  include <gnutls/gnutls.h>
#endif

#include <microhttpd.h>

int main(void)
{
#if !(MHD_VERSION >= 0x00096302 && defined GNUTLS_VERSION_NUMBER && GNUTLS_VERSION_NUMBER >= 0x030603)
	exit(WGET_TEST_EXIT_SKIP);
#else
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200",
			.body = "<html><body>\
				 Testing for post handshake authentication.\
				 </body></html>",
			.headers = {
				"Content-Type: text/html",
			},
		}
	};

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_TLS,
		WGET_TEST_SKIP_H2,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_POST_HANDSHAKE_AUTH, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
#endif
}
