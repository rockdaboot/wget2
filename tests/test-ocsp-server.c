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

#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200",
			.body = "...",
			.headers = {
				"Content-Type: text/plain",
			}
		}
	};

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_FEATURE_TLS,
		WGET_TEST_FEATURE_OCSP,
		0);

#ifndef WITH_WOLFSSL
	// Test ocsp with 'verified' response
	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/ocsp/x509-root-cert.pem --no-ocsp-file --no-ocsp-date --no-ocsp-nonce --ocsp --ocsp-server http://localhost:{{ocspport}}",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_OCSP_RESP_FILES, "", SRCDIR "/certs/ocsp/ocsp_resp_ok.der", NULL,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{urls[0].name + 1, urls[0].body},
			{	NULL} },
		0);

	// Test ocsp with 'revoked' response
	// Todo: Let WolfSSL code check the revocation.
	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/ocsp/x509-root-cert.pem --no-ocsp-file --no-ocsp-date --no-ocsp-nonce --ocsp --ocsp-server http://localhost:{{ocspport}}",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 5,
		WGET_TEST_OCSP_RESP_FILES, "", SRCDIR "/certs/ocsp/ocsp_resp_revoked.der", NULL,
		0);
#endif

	// Test ocsp with 'revoked' response ignored by --no-check-certificate
	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/ocsp/x509-root-cert.pem --no-ocsp-file --no-ocsp-date --no-ocsp-nonce --ocsp --ocsp-server http://localhost:{{ocspport}} --no-check-certificate",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_OCSP_RESP_FILES, "", SRCDIR "/certs/ocsp/ocsp_resp_revoked.der", NULL,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{urls[0].name + 1, urls[0].body},
			{	NULL} },
		0);

#ifndef WITH_WOLFSSL
	// Test ocsp without specifying responder URL
	wget_test(
		WGET_TEST_OPTIONS, "--ca-certificate=" SRCDIR "/certs/ocsp/x509-root-cert.pem --no-ocsp-file --no-ocsp-date --no-ocsp-nonce --ocsp",
		WGET_TEST_REQUEST_URL, "https://localhost:{{sslport}}/index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_OCSP_RESP_FILES, "", SRCDIR "/certs/ocsp/ocsp_resp_ok.der", NULL,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{urls[0].name + 1, urls[0].body},
			{	NULL} },
		0);
#endif

	exit(EXIT_SUCCESS);
}
