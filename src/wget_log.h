/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Header file for logging routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef SRC_WGET_LOG_H
#define SRC_WGET_LOG_H

#include <stdarg.h>

void log_init(void);

void log_write_error_stdout(const char *data, size_t len);

#endif /* SRC_WGET_LOG_H */
