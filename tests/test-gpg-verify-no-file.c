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
 * Test the missing signature file behavior.
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

	// ================================================================================
	// 'fail' Section
	// ================================================================================

	// TODO : figure out duplicated lists or some shit
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig=fail --signature-extensions=s --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 8, // WG_EXIT_STATUS_REMOTE
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 8, // WG_EXIT_STATUS_REMOTE
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig=fail --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 8, // WG_EXIT_STATUS_REMOTE
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --signature-extensions=a,b,c --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 8, // WG_EXIT_STATUS_REMOTE
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "-s --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 8, // WG_EXIT_STATUS_REMOTE
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);

	// ================================================================================
	// 'no-fail' Section
	// ================================================================================

	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig=no-fail --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig=no-fail --signature-extensions=a,b,c --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	// Check that no-fail doesn't impact success.
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig=no-fail --signature-extensions=sign --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	// Check normal success
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --signature-extensions=sign --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	// Check normal success with more than one extension option
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig --signature-extensions=a,sign,b --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--no-verify-sig --signature-extensions=a,sign,b --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// Probably safe to assume that the contents are correct.
			{ "helloworld.txt", NULL },
			{ NULL } },
		0);

	// ================================================================================
	// Invalid arguments
	// ================================================================================

	wget_test(
		WGET_TEST_OPTIONS, "--no-verify-sig=fail --signature-extensions=a,sign,b --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 2, // WG_EXIT_STATUS_PARSE_INIT
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--verify-sig=disabled --signature-extensions=a,sign,b --gnupg-homedir=" SRCDIR "/gpg",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 2, // WG_EXIT_STATUS_PARSE_INIT
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_xfree(urls[1].body);

	exit(EXIT_SUCCESS);
}
