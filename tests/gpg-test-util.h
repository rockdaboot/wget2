/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Common function for testing the GPGME functionality
 */

#include <config.h>

#include "libtest.h"
#include "wget.h"
#include <stdlib.h>
#include <string.h> // strrchr()

extern wget_test_url_t urls[]; // prevent compiler warning
int gpg_test(const char *sig_file, int expected_exit);

wget_test_url_t urls[] = {
	{	.name = "/gpg/helloworld.txt",
		.code = "200 Dontcare",
		.body = "Hello World!\n",
		.headers = {
			"Content-Type: application/octet-stream",
		}
	},
	{	.name = "/gpg/helloworld.txt.sig",
		.code = "200 Dontcare",
		.body = NULL,
		.headers = {
			"Content-Type: application/pgp-signature",
		}
	}
};

int gpg_test(const char *sig_file, int expected_exit)
{
	size_t num_bytes;

	char *body = wget_read_file(sig_file, &num_bytes);
	if (!body) {
		printf("No file: %s\n", sig_file);
		return 1;
	}

	urls[1].body = body;
	urls[1].body_len = num_bytes;

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	char *file1_name = strrchr(urls[0].name, '/') + 1;

	if (expected_exit) {
		wget_test(
			WGET_TEST_OPTIONS, "--verify-sig --gnupg-homedir=" SRCDIR "/gpg",
			WGET_TEST_REQUEST_URL, urls[0].name + 1,
			WGET_TEST_EXPECTED_ERROR_CODE, expected_exit,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				// In this case the file shouldn't persist
				// (it failed validation)
				{ NULL } },
			0);
	} else {
		wget_test(
			WGET_TEST_OPTIONS, "--verify-sig --gnupg-homedir=" SRCDIR "/gpg",
			WGET_TEST_REQUEST_URL, urls[0].name + 1,
			WGET_TEST_EXPECTED_ERROR_CODE, expected_exit,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				// Unfortunately these are binary files
				// so they contain NULL bytes.
				// Probably safe to assume that the contents are correct.
				// Signature file is unconditionally deleted
				// The file should only persist if expected exit is 0
				{ file1_name, NULL },
				{ NULL } },
			0);
	}

	wget_xfree(body);

	return 0;
}
