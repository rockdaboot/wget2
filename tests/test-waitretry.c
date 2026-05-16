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
 *
 *
 * Testing --waitretry option for HTTP error retries
 *
 * Changelog
 * 16.05.2025  Created
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[] = {
		{
			.name = "/error.html",
			.code = "429 Too Many Requests",
			.body = "rate limited",
			.headers = {
				"Content-Type: text/plain",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	long long start_ms = wget_get_timemillis();

	wget_test(
		WGET_TEST_OPTIONS, "--waitretry=2 --retry-on-http-error=429 --tries=3",
		WGET_TEST_REQUEST_URL, "error.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 4,
		0);

	long long elapsed_ms = wget_get_timemillis() - start_ms;

	// wait 2s after first failure + wait 4s after second failure
	if (elapsed_ms < 6000)
		wget_error_printf_exit("Expected log duration >= 6s (waitretry=2 not being used)\n");

	char *logs = wget_read_file("../test-waitretry.log", NULL), *p = logs;
	for (int i = 0; i < 3; i++, p++) {
		if (!(p = strstr(p, "HTTP ERROR response 429"))) {
			wget_error_printf_exit("Expected exactly 3x 'HTTP ERROR response 429'\n");
		}
	}
	if (strstr(p, "HTTP ERROR response 429")) {
		wget_error_printf_exit("Expected exactly 3x 'HTTP ERROR response 429'\n");
	}
	wget_free(logs);

	exit(EXIT_SUCCESS);
}
