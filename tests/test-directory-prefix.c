/*
 * Copyright (c) 2022-2026 Free Software Foundation, Inc.
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
 * Testing --directory-prefix
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <unistd.h> // getcwd()
#include "libtest.h"

#define PREFIX "prefix"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body>secondpage</body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Disposition: attachment; filename=\"filename.html\"",
			}
		},
		{	.name = "/escape.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body>escape</body></html>",
			.headers = {
				"Content-Type: text/html",
				"Content-Disposition: attachment; filename=\"../filename.html\"",
			}
		},
		{	.name = "/a:b.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Colon Page</title></head><body>colon</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// Single download
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
//		WGET_TEST_EXECUTABLE, "wget",
		WGET_TEST_OPTIONS, "--directory-prefix=" PREFIX " -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ PREFIX "/index.html", urls[0].body },
			{	NULL } },
		0);

	// Single download with Content-Disposition
	wget_test(
		WGET_TEST_OPTIONS, "--directory-prefix=" PREFIX " --content-disposition -nH",
		WGET_TEST_REQUEST_URL, "secondpage.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ PREFIX "/filename.html", urls[1].body },
			{	NULL } },
		0);

	// Single download with Content-Disposition, trying to escape the directory
	wget_test(
		WGET_TEST_OPTIONS, "--directory-prefix=" PREFIX " --content-disposition -nH",
		WGET_TEST_REQUEST_URL, "escape.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ PREFIX "/filename.html", urls[2].body },
			{	NULL } },
		0);

	// Test absolute directory-prefix path
	{
		char cwd[4096];
		if (!getcwd(cwd, sizeof(cwd))) {
			wget_error_printf_exit("Failed to get cwd\n");
		}

		char abs_opt[4096];
		wget_snprintf(abs_opt, sizeof(abs_opt), "--directory-prefix=%s/abs_prefix -nH", cwd);

		wget_test(
			WGET_TEST_OPTIONS, abs_opt,
			WGET_TEST_REQUEST_URL, "index.html",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{ "abs_prefix/index.html", urls[0].body },
				{	NULL } },
			0);
	}

#ifdef _WIN32
	// Test ".." above the drive root, Windows keeps it at the root ("C:\..\dir" is "C:\dir")
	{
		char cwd[4096];
		if (!getcwd(cwd, sizeof(cwd))) {
			wget_error_printf_exit("Failed to get cwd\n");
		}

		char abs_opt[4096];
		wget_snprintf(abs_opt, sizeof(abs_opt), "--directory-prefix=%.2s\\..%s\\abs_prefix2 -nH", cwd, cwd + 2);

		wget_test(
			WGET_TEST_OPTIONS, abs_opt,
			WGET_TEST_REQUEST_URL, "index.html",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{ "abs_prefix2/index.html", urls[0].body },
				{	NULL } },
			0);
	}

	// Test relative directory-prefix with backslashes and ".."
	wget_test(
		WGET_TEST_OPTIONS, "--directory-prefix=sub\\..\\rel_prefix -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "rel_prefix/index.html", urls[0].body },
			{	NULL } },
		0);

	// The file name from the URL is still escaped after the directory prefix
	wget_test(
		WGET_TEST_OPTIONS, "--directory-prefix=rel_prefix2 -nH",
		WGET_TEST_REQUEST_URL, "a:b.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "rel_prefix2/a:b.html", urls[3].body },
			{	NULL } },
		0);
#else
	// The directory prefix is a local path, --restrict-file-names only escapes the file name
	wget_test(
		WGET_TEST_OPTIONS, "--restrict-file-names=windows --directory-prefix=pre:fix -nH",
		WGET_TEST_REQUEST_URL, "a:b.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "pre:fix/a%3Ab.html", urls[3].body },
			{	NULL } },
		0);
#endif

	exit(EXIT_SUCCESS);
}
