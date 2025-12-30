/*
 * Copyright (c) 2025 Free Software Foundation, Inc.
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
 * Testing redirects with both Link and Location headers (e.g., MirrorBrain)
 *
 * This test reproduces the issue where a redirect with both Link and
 * Location headers causes the file to be downloaded multiple times.
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		// Simulates a MirrorBrain-style redirect with both Link and Location headers
		// The Location header points to mirror2, but Link headers say mirror1 is best
		// This reproduces the bug where both URLs get queued and downloaded
		{	.name = "/file.zip",
			.code = "302 Found",
			.headers = {
				"Content-Type: text/html",
				"Link: <http://localhost:{{port}}/mirror1/file.zip>; rel=duplicate; pri=1",
				"Link: <http://localhost:{{port}}/mirror2/file.zip>; rel=duplicate; pri=2",
				"Location: http://localhost:{{port}}/mirror2/file.zip",
			}
		},
		// First mirror (highest priority in Link headers)
		{	.name = "/mirror1/file.zip",
			.code = "200 OK",
			.body = "file contents",
			.headers = {
				"Content-Type: application/zip",
			}
		},
		// Second mirror (Location header points here)
		{	.name = "/mirror2/file.zip",
			.code = "200 OK",
			.body = "file contents",
			.headers = {
				"Content-Type: application/zip",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// Test: Download file with both Link and Location headers
	// Expected: Only ONE file should be downloaded (not multiple)
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_REQUEST_URL, "file.zip",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file.zip", urls[1].body },  // Should download only once
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}
