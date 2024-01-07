/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * Test various permutations of the GPG functionality
 */

#include <config.h>

#include "libtest.h"
#include "wget.h"
#include <stdlib.h>

static wget_test_url_t urls[] = {
	{	.name = "/gpg/helloworld.txt",
		.code = "200 Dontcare",
		.body = "Hello World!\n",
		.headers = {
			"Content-Type: application/octet-stream",
		}
	},
	{	.name = "/gpg/helloworld.txt.sign",
		.code = "200 Dontcare",
		.body = NULL,
		.headers = {
			"Content-Type: application/pgp-signature",
		}
	}
};

int main(void)
{
	const char *sig_file = SRCDIR "/gpg/helloworld.txt.trusted.sig";

	urls[1].body = wget_read_file(sig_file, &urls[1].body_len);

	if (!urls[1].body) {
		printf("No file: %s\n", sig_file);
		return 1;
	}

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --signature-extensions=sign --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Unfortunately these are binary files
			// so they contain NULL bytes.
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			// Signature file should be deleted
			// { "helloworld.txt.sign", NULL },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --signature-extensions=asc,sig,sign --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Unfortunately these are binary files
			// so they contain NULL bytes.
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			// Signature file should be deleted
			// { "helloworld.txt.sign", NULL },
			{ NULL } },
		0);

	wget_xfree(urls[1].body);

	exit(EXIT_SUCCESS);
}
