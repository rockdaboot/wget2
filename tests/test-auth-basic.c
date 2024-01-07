/*
 * Copyright (c) 2013 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Testing Wget
 *
 * Changelog
 * 08.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

#define username "my_username"
#define password "my_password"

int main(void)
{
	wget_test_url_t urls[] = {
		{	.name = "/needs-auth.txt",
			.auth_method = "Basic",
			.auth_username = username,
			.auth_password = password,
			.code = "200 Dontcare",
			.body = "You are authenticated.",
			.headers = {
				"Content-Type: text/plain",
			}
		}
	};
	wget_test_file_t netrc = {
		.name = ".netrc",
		.content = "default\r\nlogin " username "\r\npassword " password "\r\n"
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// test-auth-basic
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=" username " --password=" password,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// test-auth-basic with .netrc
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--netrc-file=.netrc",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ netrc.name, netrc.content },
			{ NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ netrc.name, netrc.content },
			{ NULL } },
		0);

	// wrong credentials
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--password=" password,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=\"\" --password=" password,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=\"whatever\" --password=" password,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=" username,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=" username " --password=\"\"",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=" username " --password=\"whatever\"",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=\"\" --password=\"\"",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=\"whatever\" --password=\"whatever\"",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	// use --auth-no-challenge options
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=" username " --password=" password " --auth-no-challenge",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ NULL } },
		0);

	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--user=" username " --password=\"whatever\" --auth-no-challenge",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 6,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
}
