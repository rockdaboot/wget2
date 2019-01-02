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

#include <string.h>
#include <glob.h>

#include <wget.h>
#include "wget_utils.h"

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
