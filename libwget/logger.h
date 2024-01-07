/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file shared between logger.c and log.c
 */

#ifndef LIBWGET_LOGGER_H
# define LIBWGET_LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <wget.h>

// _WGET_LOGGER is shared between log.c and logger.c, but must not be exposed to the public
struct wget_logger_st {
	FILE *fp;
	const char *fname;
	void (*func)(const char *buf, size_t bufsize);
	void (*vprintf)(const wget_logger *logger, const char *fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0);
	void (*write)(const wget_logger *logger, const char *buf, size_t bufsize);
};

#endif /* LIBWGET_LOGGER_H */
