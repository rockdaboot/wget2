/*
 * Copyright(c) 2018-2019 Free Software Foundation, Inc.
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
 * Utility functions
 */

#include <config.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <glob.h>

#include "wget_main.h"
#include "wget_utils.h"

// this function should be called protected by a mutex - else race conditions will happen
void mkdir_path(const char *fname, bool is_file)
{
	const char *p1;
	char *p2;

	for (p1 = fname + 1; *p1 && (p2 = strchr(p1, '/')); p1 = p2 + 1) {
		int rc;
		*p2 = 0; // replace path separator

		// relative paths should have been normalized earlier,
		// but for security reasons, don't trust myself...
		if (*p1 == '.' && p1[1] == '.')
			error_printf_exit(_("Internal error: Unexpected relative path: '%s'\n"), fname);

		rc = mkdir(fname, 0755);

		debug_printf("mkdir(%s)=%d errno=%d\n",fname,rc,errno);
		if (rc) {
			struct stat st;

			if (errno == EEXIST && stat(fname, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG) {
				// we have a file in the way... move it away and retry
				int renamed = 0;

				for (int fnum = 1; fnum <= 999 && !renamed; fnum++) {
					char dst[strlen(fname) + 1 + 32];

					wget_snprintf(dst, sizeof(dst), "%s.%d", fname, fnum);
					if (access(dst, F_OK) != 0 && rename(fname, dst) == 0)
						renamed = 1;
				}

				if (renamed) {
					rc = mkdir(fname, 0755);

					if (rc) {
						error_printf(_("Failed to make directory '%s' (errno=%d)\n"), fname, errno);
						*p2 = '/'; // restore path separator
						break;
					}
				} else
					error_printf(_("Failed to rename '%s' (errno=%d)\n"), fname, errno);
			} else if (errno != EEXIST) {
				error_printf(_("Failed to make directory '%s' (errno=%d)\n"), fname, errno);
				*p2 = '/'; // restore path separator
				break;
			}
		} else debug_printf("created dir %s\n", fname);

		*p2 = '/'; // restore path separator
	}

	// If the path does not represent a file, we want to also create the
	// directory for the last part
	if (!is_file) {
		int rc = mkdir(fname, 0755);
		debug_printf("mkdir(%s)=%d errno=%d\n",fname,rc,errno);
	}
}


char *shell_expand(const char *fname)
{
	char *expanded_str = NULL;

	if (*fname == '~') {
		char *slash = strchrnul(fname, '/');
		expanded_str = wget_strnglob(fname, slash - fname, GLOB_TILDE | GLOB_ONLYDIR | GLOB_NOCHECK);
	}

	// Either the string does not start with a "~", or the glob expansion
	// failed. In both cases, return the original string back
	return expanded_str ? expanded_str : wget_strdup(fname);
}
