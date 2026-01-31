/*
 * Copyright (c) 2025 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
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
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200",
			.body = "Hello World",
			.headers = {
				"Content-Type: text/plain",
			}
		}
	};

	// 1. Test with Bad Key Usage (KU)
	// The certificate has CRL Sign usage but not Digital Signature or Key Encipherment.
	// This should fail validation for a TLS server certificate.
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_TLS,
		WGET_TEST_HTTPS_CERT_FILE, SRCDIR "/certs/x509-server-bad-ku-cert.pem",
		WGET_TEST_HTTPS_KEY_FILE, SRCDIR "/certs/x509-server-key.pem",
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 5, // WGET_EXIT_SSL_AUTH
		0);

	// 2. Test with Bad Extended Key Usage (EKU)
	// The certificate has Code Signing EKU but not Server Authentication.
	// This should fail validation.
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_TLS,
		WGET_TEST_HTTPS_CERT_FILE, SRCDIR "/certs/x509-server-bad-eku-cert.pem",
		WGET_TEST_HTTPS_KEY_FILE, SRCDIR "/certs/x509-server-key.pem",
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 5,
		0);

	exit(EXIT_SUCCESS);
}
