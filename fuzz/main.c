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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifdef TEST_RUN

#include <dirent.h>

int main(int argc, char **argv)
{
	DIR *dirp;
	struct dirent *dp;

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

	const char *target = strrchr(argv[0], '/');
	target = target ? target + 1 : argv[0];

	char corporadir[sizeof(SRCDIR) + 1 + strlen(target) + 4];
	snprintf(corporadir, sizeof(corporadir), SRCDIR "/%s.in", target);

	if ((dirp = opendir(corporadir))) {
		while ((dp = readdir(dirp))) {
			if (*dp->d_name == '.') continue;

			char fname[strlen(corporadir) + strlen(dp->d_name) + 2];
			snprintf(fname, sizeof(fname), "%s/%s", corporadir, dp->d_name);

			uint8_t *data;
			size_t size;
			if ((data = (uint8_t *) wget_read_file(fname, &size))) {
				wget_info_printf("testing %zu bytes from '%s'\n", size, fname);
				LLVMFuzzerTestOneInput(data, size);
				wget_free(data);
			}
		}
		closedir(dirp);
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

#endif /* TEST_RUN */
