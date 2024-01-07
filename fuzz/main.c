/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "wget.h"
#include "fuzzer.h"

#ifdef TEST_RUN

#include <dirent.h>

#ifdef _WIN32
#  define SLASH '\\'
#else
#  define SLASH '/'
#endif

static int test_all_from(const char *dirname)
{
	DIR *dirp;

	if ((dirp = opendir(dirname))) {
		struct dirent *dp;

		while ((dp = readdir(dirp))) {
			if (*dp->d_name == '.') continue;

			char *fname = wget_aprintf("%s/%s", dirname, dp->d_name);

			uint8_t *data;
			size_t size;
			if ((data = (uint8_t *) wget_read_file(fname, &size))) {
				printf("testing %zu bytes from '%s'\n", size, fname);
				LLVMFuzzerTestOneInput(data, size);
				wget_free(data);
			}

			wget_xfree(fname);
		}
		closedir(dirp);
		return 0;
	}

	return 1;
}

int main(WGET_GCC_UNUSED int argc, char **argv)
{
	// if VALGRIND testing is enabled, we have to call ourselves with valgrind checking
	const char *valgrind = getenv("VALGRIND_TESTS");
	const char *target;
	size_t target_len;

	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
		// fallthrough
	}
	else if (!strcmp(valgrind, "1")) {
		char *cmd = wget_aprintf("VALGRIND_TESTS=\"\" valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes --suppressions=" SRCDIR "/valgrind-suppressions --gen-suppressions=all %s", argv[0]);
		int result = system(cmd) != 0;
		wget_xfree(cmd);
		return result;
	} else {
		char *cmd = wget_aprintf("VALGRIND_TESTS="" %s %s", valgrind, argv[0]);
		int result = system(cmd) != 0;
		wget_xfree(cmd);
		return result;
	}

	wget_global_init(
		// WGET_DEBUG_STREAM, stdout,
		WGET_ERROR_STREAM, stdout,
		WGET_INFO_STREAM, stdout,
		0);

	if ((target = strrchr(argv[0], SLASH))) {
		if (strrchr(target, '/'))
			target = strrchr(target, '/');
	} else
		target = strrchr(argv[0], '/');
	target = target ? target + 1 : argv[0];

	if (strncmp(target, "lt-", 3) == 0)
		target += 3;

	target_len = strlen(target);

#ifdef _WIN32
	target_len -= 4; // ignore .exe
#endif

	{
		char *corporadir;

		corporadir = wget_aprintf(SRCDIR "/%.*s.in", (int) target_len, target);
		int rc = test_all_from(corporadir);
		if (rc)
			wget_error_printf("Failed to find %s\n", corporadir);
		wget_xfree(corporadir);

		corporadir = wget_aprintf(SRCDIR "/%.*s.repro", (int) target_len, target);
		bool failure = test_all_from(corporadir) && rc;
		wget_xfree(corporadir);
		if (failure)
			return 77;
	}

	wget_global_deinit();

	return 0;
}

#else

#ifndef __AFL_LOOP
static int __AFL_LOOP(int n)
{
	static int first = 1;

	if (first) {
		first = 0;
		return 1;
	}

	return 0;
}
#endif

int main(int argc, char **argv)
{
	int ret;
	unsigned char buf[64 * 1024];

	while (__AFL_LOOP(10000)) { // only works with afl-clang-fast
		ret = fread(buf, 1, sizeof(buf), stdin);
		if (ret < 0)
			return 0;

		LLVMFuzzerTestOneInput(buf, ret);
	}

	return 0;
}

#endif /* #ifdef TEST_RUN */
