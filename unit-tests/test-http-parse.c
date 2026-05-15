/*
 * Test of HTTP parsing routines.
 * Copyright (C) 2026 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wget.h>
#include "../libwget/private.h"

static int
	ok,
	failed;

static void check(int result, int line, const char *msg)
{
	if (result) {
		ok++;
	} else {
		failed++;
		wget_info_printf("L%d: %s\n", line, msg);
	}
}

#define CHECK(e) check(!!(e), __LINE__, #e)

static void check_filename(const char *input, const char *expected)
{
	const char *filename = NULL;
	(void) wget_http_parse_content_disposition(input, &filename);

	if (expected == NULL) {
		CHECK(filename == NULL);
	} else {
		CHECK(filename != NULL);
		if (filename) {
			if (strcmp(filename, expected) != 0) {
				wget_info_printf("  input='%s'  got='%s'  expected='%s'\n", input, filename, expected);
				failed++;
			} else {
				ok++;
			}
		}
	}

	xfree(filename);
}

static void test_content_disposition(void)
{
	wget_info_printf("=== Content-Disposition filename sanitization ===\n");

	// Normal filenames
	check_filename("attachment; filename=\"test.txt\"", "test.txt");
	check_filename("attachment; filename=test.txt", "test.txt");
	check_filename("attachment; filename=\"foo bar.txt\"", "foo bar.txt");

	// Directory traversal - should be sanitized
	check_filename("attachment; filename=\"../evil.txt\"", "evil.txt");
	check_filename("attachment; filename=\"../../evil.txt\"", "evil.txt");
	check_filename("attachment; filename=\"foo/../evil.txt\"", "evil.txt");
	check_filename("attachment; filename=\"foo/..\"", "");
	check_filename("attachment; filename=\"..\"", "");

#ifdef WIN32
	// Backslash traversal (Windows)
	check_filename("attachment; filename=\"..\\evil.txt\"", "evil.txt");
	check_filename("attachment; filename=\"foo\\..\\evil.txt\"", "evil.txt");
	check_filename("attachment; filename=\"C:foo\\..\\evil.txt\"", "evil.txt");
#endif

	// Absolute paths (leading "/" stripped, basename kept)
	check_filename("attachment; filename=\"/etc/passwd\"", "passwd");
	check_filename("attachment; filename=\"/foo/bar\"", "bar");

	// Empty and edge cases
	check_filename("attachment; filename=\"\"", "");

	wget_info_printf("\n");
}

int main(WGET_GCC_UNUSED int argc, const char **argv)
{
	// if VALGRIND testing is enabled, we have to call ourselves with valgrind checking
	const char *valgrind = getenv("VALGRIND_TESTS");

	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
		// fallthrough
	}
	else if (!strcmp(valgrind, "1")) {
		char cmd[4096];

		wget_snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS=\"\" valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes %s", argv[0]);
		return system(cmd) != 0;
	} else {
		char cmd[4096];

		wget_snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS="" %s %s", valgrind, argv[0]);
		return system(cmd) != 0;
	}

	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stderr);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);

	test_content_disposition();

	if (failed) {
		wget_info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	wget_info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}
