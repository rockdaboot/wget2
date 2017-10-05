/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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

			char fname[strlen(dirname) + strlen(dp->d_name) + 2];
			snprintf(fname, sizeof(fname), "%s/%s", dirname, dp->d_name);

			uint8_t *data;
			size_t size;
			if ((data = (uint8_t *) wget_read_file(fname, &size))) {
				wget_info_printf("testing %zu bytes from '%s'\n", size, fname);
				LLVMFuzzerTestOneInput(data, size);
				wget_free(data);
			}
		}
		closedir(dirp);
		return 0;
	}

	return 1;
}

int main(int argc, char **argv)
{
	// if VALGRIND testing is enabled, we have to call ourselves with valgrind checking
	const char *valgrind = getenv("VALGRIND_TESTS");

	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
			  // fallthrough
	}
	else if (!strcmp(valgrind, "1")) {
			  char cmd[strlen(argv[0]) + 256];

			  snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS=\"\" valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes %s", argv[0]);
			  return system(cmd) != 0;
	} else {
			  char cmd[strlen(valgrind) + strlen(argv[0]) + 32];

			  snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS="" %s %s", valgrind, argv[0]);
			  return system(cmd) != 0;
	}

	wget_global_init(
		// WGET_DEBUG_STREAM, stdout,
		WGET_ERROR_STREAM, stdout,
		WGET_INFO_STREAM, stdout,
		NULL);

	const char *target = strrchr(argv[0], SLASH);
	target = target ? target + 1 : argv[0];
	size_t target_len;

	if (strncmp(target, "lt-", 3) == 0)
		target += 3;

	target_len = strlen(target);

#ifdef _WIN32
	target_len -= 4; // ignore .exe
#endif

	char corporadir[sizeof(SRCDIR) + 1 + target_len + 8];
	snprintf(corporadir, sizeof(corporadir), SRCDIR "/%.*s.in", (int) target_len, target);

	if (test_all_from(corporadir))
		wget_error_printf_exit("Failed to find %s\n", corporadir);

	snprintf(corporadir, sizeof(corporadir), SRCDIR "/%.*s.repro", (int) target_len, target);

	test_all_from(corporadir);

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
