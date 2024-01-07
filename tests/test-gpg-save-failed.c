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

int main(void)
{
	const char *sig_file = SRCDIR "/gpg/helloworld.txt.invalid.sig";

#ifdef WITH_GPGME
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


	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --gnupg-homedir=" SRCDIR "/gpg --verify-save-failed",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 9,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Even though verification failed
			// file should still be there.
			{ file1_name, NULL },
			{ NULL } },
		0);

	wget_xfree(body);
#endif
	exit(EXIT_SUCCESS);
}
