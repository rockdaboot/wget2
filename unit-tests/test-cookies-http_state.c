/*
 * Copyright (c) 2016-2019 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
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
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Test cookies regarding https://github.com/abarth/http-state/
 *
 * To get the tests:
 * $ cd tests
 * $ git clone --depth=1 https://github.com/abarth/http-state
 *
 * Enable tests/test-cookie-http_state in tests/Makefile.am for testing.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#include <wget.h>
#include "../libwget/private.h"

#include "../src/wget_options.h"
#include "../src/wget_log.h"

#define COOKIETESTDIR SRCDIR"/http-state/tests/data/parser"

static int
	ok,
	failed;

static int filter(const struct dirent *dp)
{
	return wget_match_tail_nocase(dp->d_name, "-test");
}

static void test_cookies(void)
{
	wget_cookie_db *cookie_db;
	wget_http_response *resp;
	struct dirent **dps;
	int n, oh_my_gosh;
	size_t size;
	char *infile, *header, *response, *expected, *expected_content;

	if ((n = scandir(COOKIETESTDIR, &dps, filter, alphasort)) < 0) {
		error_printf("Failed to scandir '%s'\n", COOKIETESTDIR);
		failed++;
		return;
	}

	if (n == 0) {
		error_printf("Failed to find cookie tests in '%s'\n", COOKIETESTDIR);
		free(dps);
		failed++;
		return;
	}

	wget_iri *iri = wget_iri_parse("http://home.example.org/cookie-parser-result", NULL);

	cookie_db = wget_cookie_db_init(NULL);

	for (int it = 0; it < n; it++) {
		struct dirent *dp = dps[it];

		info_printf("\n### %s ###\n", dp->d_name);

		// read the test header lines
		wget_asprintf(&infile, COOKIETESTDIR"/%s", dp->d_name);
		header = wget_read_file(infile, &size);
		xfree(infile);

		info_printf("Input...: %s", header);

		// read the result header lines
		wget_asprintf(&infile, COOKIETESTDIR"/%.*s-expected", (int) (strlen(dp->d_name) - 5), dp->d_name);
		expected_content = wget_read_file(infile, &size);
		while (size && expected_content[size - 1] == '\n')
			expected_content[--size] = 0;
		if (!strncmp(expected_content, "Cookie: ", 8))
			expected = expected_content + 8;
		else
			expected = expected_content;
		xfree(infile);

		// construct a HTTP server response
		wget_asprintf(&response, "HTTP/1.1 200 OK\r\n%s", header);

		// parse the response
		if (!(resp = wget_http_parse_response_header(response))) {
			failed++;
			goto next;
		}

		// sanitize parsed cookies
		wget_cookie_normalize_cookies(iri, resp->cookies);

		// store cookies into database
		wget_cookie_db_deinit(cookie_db);
		wget_cookie_db_init(cookie_db);
		// wget_cookie_set_keep_session_cookies(cookie_db, 0);
		wget_cookie_db_load_psl(cookie_db, NULL); // switch off PSL checking

		wget_cookie_store_cookies(cookie_db, resp->cookies);

		// free response structure
		wget_http_free_response(&resp);

		// create cookie
		const char *cookie_string;
		if ((cookie_string = wget_cookie_create_request_header(cookie_db, iri))) {
			oh_my_gosh = !!strcmp(expected, cookie_string);
		} else {
			oh_my_gosh = !!*expected_content;
		}

		info_printf("Result..: %s\n", cookie_string);
		info_printf("Expected: %s\n", expected);

		if (oh_my_gosh) {
			info_printf("FAILED\n");
			failed++;
		} else {
			info_printf("PASSED\n");
			ok++;
		}

		xfree(cookie_string);
		xfree(expected_content);
next:
		xfree(response);
		xfree(header);
		xfree(dp);
	}

	wget_cookie_db_free(&cookie_db);
	wget_iri_free(&iri);
	xfree(dps);
}

int main(int argc, const char * const *argv)
{
	// if VALGRIND testing is enabled, we have to call ourselves with valgrind checking
	const char *valgrind = getenv("VALGRIND_TESTS");

	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
		// fallthrough
	}
	else if (!strcmp(valgrind, "1")) {
		char cmd[strlen(argv[0]) + 256];

		wget_snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS=\"\" valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes %s", argv[0]);
		return system(cmd) != 0;
	} else {
		char cmd[strlen(valgrind) + strlen(argv[0]) + 32];

		wget_snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS="" %s %s", valgrind, argv[0]);
		return system(cmd) != 0;
	}

	if (init(argc, argv) < 0) // allows us to test with options (e.g. with --debug)
		return -1;

	wget_global_init(
		WGET_DEBUG_STREAM, stdout,
		WGET_ERROR_STREAM, stdout,
		WGET_INFO_STREAM, stdout,
		NULL);

	test_cookies();

	deinit(); // free resources allocated by init()

	if (failed) {
		info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}
