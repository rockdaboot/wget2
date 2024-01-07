/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * Testing --limit-rate
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strcmp()
#include "libtest.h"

#define WITHIN_RANGE(value, desired, tolerance) \
  ((value <= desired + tolerance) && (value >= desired - tolerance))

// one megabyte file to use for limit rate testing
static char large_file[1 * 1024 * 1024];
static char small_file[5 * 1024];

static long long start_ms;
static long long elapsed_ms;
static long long desired_ms;
static long long tolerance_ms;
static long long normal_elapsed_ms;


int main(void)
{
	memset(large_file, 'A', sizeof(large_file) - 1);
	memset(small_file, 'B', sizeof(small_file) - 1);

	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <a href=\"/file1.bin\">file1</a>." \
				" <a href=\"/file2.bin\">file2</a>." \
				" <a href=\"/file3.bin\">file3</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/file1.bin",
			.code = "200 Dontcare",
			.body = large_file,
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/file2.bin",
			.code = "200 Dontcare",
			.body = large_file,
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/file3.bin",
			.code = "200 Dontcare",
			.body = large_file,
			.headers = {
				"Content-Type: text/plain",
			}
		},
		{	.name = "/smallfile1.bin",
			.code = "200 Dontcare",
			.body = small_file,
			.headers = {
				"Content-Type: text/plain",
			}
		},
	};

	const char *valgrind = getenv("VALGRIND_TESTS");

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_H2_ONLY,
		0);

	start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_REQUEST_URL, "file1.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
	0);
	normal_elapsed_ms = wget_get_timemillis() - start_ms;

	// --limit-rate active - one file
	start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_OPTIONS, "--limit-rate=500k",
		WGET_TEST_REQUEST_URL, "file1.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name + 1, urls[1].body },
			{ NULL } },
	0);
	elapsed_ms = wget_get_timemillis() - start_ms;
	desired_ms = 2000 + normal_elapsed_ms;
	if (!valgrind || !*valgrind || !strcmp(valgrind, "0"))
		tolerance_ms = 200;
	else
		tolerance_ms = 500; // relatively high value due to valgrind tests and CI runners

	if (!WITHIN_RANGE(elapsed_ms, desired_ms, tolerance_ms)) {
		wget_error_printf_exit("Time taken for single file with limit-rate enabled "
		                       "outside of expected range "
		                       "(elapsed=%lld ms, desired=%lld±%lld ms)\n",
		                       elapsed_ms, desired_ms, tolerance_ms);
	} else
		wget_info_printf("Time1 %lld %lld\n", normal_elapsed_ms, elapsed_ms);


	if (elapsed_ms < normal_elapsed_ms) {
		wget_error_printf_exit("Single file without limit-rate took longer "
		                       "than with limit-rate enabled "
		                       "(normal=%lld ms, elapsed=%lld ms)\n",
		                       normal_elapsed_ms, elapsed_ms);
	}

	// --limit-rate active - three files
	start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ NULL } },
	0);
	normal_elapsed_ms = wget_get_timemillis() - start_ms;

	start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --limit-rate=1500k",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ NULL } },
	0);
	elapsed_ms = wget_get_timemillis() - start_ms;
	desired_ms = 2000 + normal_elapsed_ms;
	if (!valgrind || !*valgrind || !strcmp(valgrind, "0"))
		tolerance_ms = 200;
	else
		tolerance_ms = 800; // relatively high value due to valgrind tests and CI runners

	if (!WITHIN_RANGE(elapsed_ms, desired_ms, tolerance_ms)) {
		wget_error_printf_exit("Time taken for mirror with limit-rate enabled "
		                       "outside of expected range "
		                       "(elapsed=%lld ms, desired=%lld±%lld ms)\n",
		                       elapsed_ms, desired_ms, tolerance_ms);
	}

	if (elapsed_ms < normal_elapsed_ms) {
		wget_error_printf_exit("Mirror without limit-rate took longer "
		                       "than with limit-rate enabled "
		                       "(normal=%lld ms, elapsed=%lld ms)\n",
		                       normal_elapsed_ms, elapsed_ms);
	}

	// limit rate with small files

	start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH",
		WGET_TEST_REQUEST_URL, "smallfile1.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[4].name + 1, urls[4].body },
			{ NULL } },
	0);
	normal_elapsed_ms = wget_get_timemillis() - start_ms;

	start_ms = wget_get_timemillis();
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --limit-rate=2.5k",
		WGET_TEST_REQUEST_URL, "smallfile1.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[4].name + 1, urls[4].body },
			{ NULL } },
	0);
	elapsed_ms = wget_get_timemillis() - start_ms;
	desired_ms = 2000 + normal_elapsed_ms;
	if (!valgrind || !*valgrind || !strcmp(valgrind, "0"))
		tolerance_ms = 200;
	else
		tolerance_ms = 500; // relatively high value due to valgrind tests and CI runners

	if (!WITHIN_RANGE(elapsed_ms, desired_ms, tolerance_ms)) {
		wget_error_printf_exit("Time taken for small file with limit-rate enabled "
		                       "outside of expected range "
		                       "(elapsed=%lld ms, desired=%lld±%lld ms)\n",
		                       elapsed_ms, desired_ms, tolerance_ms);
	}

	exit(EXIT_SUCCESS);
}
