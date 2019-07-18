/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 *
 *
 * Logging routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include <wget.h>
#include "private.h"
#include "logger.h"

static wget_logger
	_info,
	_error,
	_debug;

void wget_info_vprintf(const char *fmt, va_list args)
{
	if (_info.vprintf)
		_info.vprintf(&_info, fmt, args);
}

void wget_info_printf(const char *fmt, ...)
{
	if (_info.vprintf) {
		va_list args;

		va_start(args, fmt);
		_info.vprintf(&_info, fmt, args);
		va_end(args);
	}
}

void wget_error_vprintf(const char *fmt, va_list args)
{
	if (_error.vprintf)
		_error.vprintf(&_error, fmt, args);
}

void wget_error_printf(const char *fmt, ...)
{
	if (_error.vprintf) {
		va_list args;

		va_start(args, fmt);
		_error.vprintf(&_error, fmt, args);
		va_end(args);
	}
}

void wget_error_printf_exit(const char *fmt, ...)
{
	if (_error.vprintf) {
		va_list args;

		va_start(args, fmt);
		_error.vprintf(&_error, fmt, args);
		va_end(args);
	}

	exit(EXIT_FAILURE);
}

void wget_debug_vprintf(const char *fmt, va_list args)
{
	if (_debug.vprintf)
		_debug.vprintf(&_debug, fmt, args);
}

void wget_debug_printf(const char *fmt, ...)
{
	if (_debug.vprintf) {
		va_list args;

		va_start(args, fmt);
		_debug.vprintf(&_debug, fmt, args);
		va_end(args);
	}
}

void wget_debug_write(const char *buf, size_t len)
{
	if (_debug.write)
		_debug.write(&_debug, buf, len);
}

wget_logger *wget_get_logger(int id)
{
	if (id == WGET_LOGGER_DEBUG)
		return &_debug;
	else if (id == WGET_LOGGER_ERROR)
		return &_error;
	else if (id == WGET_LOGGER_INFO)
		return &_info;
	else
		return NULL;
}
