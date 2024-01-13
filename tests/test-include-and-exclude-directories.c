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
 *
 *
 * Testing Wget2 --exclude-directories combined with --include-directories
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h>
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/firstdir/secondpage.html\">second page</a>." \
				" Also, a <a href=\"http://localhost:{{port}}/nonexistent\">broken link</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/firstdir/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/seconddir/thirdpage.html\">third page</a>." \
				" Also, a <a href=\"http://localhost:{{port}}/nonexistent\">broken link</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Disposition: attachment; filename=\"filename.html\"",
			}
		},
		{	.name = "/seconddir/thirdpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Third Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/firstdir/pub/dummy.txt\">text file</a>." \
				" Also, a <a href=\"http://localhost:{{port}}/againnonexistent\">broken link</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/firstdir/pub/dummy.txt",
			.code = "200 Dontcare",
			.body = "What ever",
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/,,/file.txt",
			.code = "200 Dontcare",
			.body = "What ever",
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// Download all except /*/pub
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--exclude-directories=/*/pub -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, NULL },
			{ urls[1].name + 1, NULL },
			{ urls[2].name + 1, NULL },
			{ NULL } },
		0);

	// Download only files from / and from /*/pub
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--include-directories=/,/*/pub -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, NULL },
			{ urls[3].name + 1, NULL },
			{ NULL } },
		0);

	// Download all except /firstdir, but also download /*/pub
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--exclude-directories=/firstdir --include-directories=/*/pub -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, NULL },
			{ urls[2].name + 1, NULL },
			{ urls[3].name + 1, NULL },
			{ NULL } },
		0);

	// Only download /firstdir, except /firstdir/pub
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--include-directories=/firstdir --exclude-directories=/firstdir/pub -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, NULL },
			{ NULL } },
		0);

	// Test that /directory is equal to /directory/
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--include-directories=/firstdir/ --exclude-directories=/firstdir/pub/ -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, NULL },
			{ NULL } },
		0);

	// Only download /first (which doesn't exist, so no download expected at all)
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--include-directories=/first -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ NULL } },
		0);

	char *full_path = wget_aprintf("localhost%s", urls[3].name);
	// Download /*/pub with hostname directory (we omit -nH)
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--include-directories=/*/pub -r",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ full_path, NULL },
			{ NULL } },
		0);
	wget_xfree(full_path);

	// Download only /,\,/file.txt
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--include-directories=\"/\\,\\,\"",
		WGET_TEST_REQUEST_URL, ",,/file.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ strrchr(urls[4].name, '/') + 1, NULL },
			{ NULL } },
		0);

	//tests with -N --no-if-modified-since
	for (unsigned i = 0; i < countof(urls); i++) {
		urls[i].headers[1] = "Last-Modified: Sat, 09 Oct 2004 08:30:00 GMT";
	}
	// Download all except /firstdir, but also download /*/pub
	wget_test(
		WGET_TEST_OPTIONS, "--exclude-directories=/firstdir --include-directories=/*/pub -r -nH -N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, NULL },
			{ urls[2].name + 1, NULL },
			{ urls[3].name + 1, NULL },
			{ NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--exclude-directories=/firstdir --include-directories=/*/pub -r -nH -N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ urls[3].name + 1, "anycontent", 1097310600  },
			{ NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body, 1097310600 },
			{ urls[2].name + 1, urls[2].body, 1097310600 },
			{ urls[3].name + 1, urls[3].body, 1097310600 },
			{ NULL } },
		0);

	char *modified = wget_strdup(urls[2].body);
	modified[0] = '.';
	wget_test(
		WGET_TEST_OPTIONS, "--exclude-directories=/firstdir --include-directories=/*/pub -r -nH -N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ urls[2].name + 1, modified, 1097310600  },
			{ NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body, 1097310600 },
			{ urls[2].name + 1, modified, 1097310600 },
			{ urls[3].name + 1, urls[3].body, 1097310600 },
			{ NULL } },
		0);
	wget_xfree(modified);

	exit(EXIT_SUCCESS);
}
