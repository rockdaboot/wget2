/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
 * Header file for utility functions
 */

#ifndef SRC_WGET_UTILS_H
#define SRC_WGET_UTILS_H

#include <wget.h>

void mkdir_path(const char *fname, bool is_file);
char *shell_expand(const char *fname);
char *wget_restrict_file_name(const char *fname, char *esc, int mode);

#endif /* SRC_WGET_UTILS_H */
