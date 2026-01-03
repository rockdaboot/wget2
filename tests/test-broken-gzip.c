/*
 * Copyright (c) 2026 Free Software Foundation, Inc.
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

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

int main(void)
{
	// Define a broken gzip body (just random text)
	static const char *broken_gzip_body = "This is not valid gzip data";
	static const char *valid_body = "This is a valid file";

	wget_test_url_t urls[]={
		{   .name = "/broken.html",
			.code = "200 Dontcare",
			.body = broken_gzip_body,
			.body_len = strlen(broken_gzip_body),
			.headers = {
				"Content-Type: text/html",
				"Content-Encoding: gzip",
			},
		},
		{   .name = "/valid.html",
			.code = "200 Dontcare",
			.body = valid_body,
			.body_len = strlen(valid_body),
			.headers = {
				"Content-Type: text/html",
			},
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// The libtest framework will replace {{port}} with the actual port
	const char *input_file_content = "http://localhost:{{port}}/broken.html\nhttp://localhost:{{port}}/valid.html\n";

	// wget2 should attempt to download both, failing on the first but succeeding on the second
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--max-threads=1 -i input.txt", // explicit single thread to ensure sequential processing
		WGET_TEST_REQUEST_URL, NULL,
		WGET_TEST_EXPECTED_ERROR_CODE, 0, // Should exit with success
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "input.txt", input_file_content },
			{ NULL }
		},
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// broken.html is created but empty because decompression failed
			{ "broken.html", "", .content_length = 0 },
			{ "valid.html", valid_body },
			{ "input.txt", input_file_content },
			{ NULL }
		},
		0);

	exit(EXIT_SUCCESS);
}
