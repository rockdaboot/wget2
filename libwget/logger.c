/*
 * Copyright (c) 2013 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Logger routines
 *
 * Changelog
 * 09.01.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <wget.h>
#include "private.h"
#include "logger.h"

static void WGET_GCC_PRINTF_FORMAT(2,0) WGET_GCC_NONNULL((1,2))
logger_vprintf_func(const wget_logger *logger, const char *fmt, va_list args)
{
	char sbuf[4096];
	wget_buffer buf;
	int err = errno;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf(&buf, fmt, args);
	logger->func(buf.data, buf.length);
	wget_buffer_deinit(&buf);

	errno = err;
}

static void WGET_GCC_NONNULL((1))
logger_write_func(const wget_logger *logger, const char *buf, size_t len)
{
	logger->func(buf, len);
}

static void  WGET_GCC_PRINTF_FORMAT(2,0) WGET_GCC_NONNULL((1,2))
logger_vfprintf(FILE *fp, const char *fmt, va_list args)
{
	char sbuf[4096];
	wget_buffer buf;
	int err = errno;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf(&buf, fmt, args);
	fwrite(buf.data, 1, buf.length, fp);
	wget_buffer_deinit(&buf);

	errno = err;
}

static void  WGET_GCC_PRINTF_FORMAT(2,0) WGET_GCC_NONNULL((1,2))
logger_vprintf_file(const wget_logger *logger, const char *fmt, va_list args)
{
	logger_vfprintf(logger->fp, fmt, args);
}

static void WGET_GCC_NONNULL((1))
logger_write_file(const wget_logger *logger, const char *buf, size_t len)
{
	fwrite(buf, 1, len, logger->fp);
}

static void WGET_GCC_PRINTF_FORMAT(2,0) WGET_GCC_NONNULL((1,2))
logger_vprintf_fname(const wget_logger *logger, const char *fmt, va_list args)
{
	FILE *fp = fopen(logger->fname, "a");

	if (fp) {
		logger_vfprintf(fp, fmt, args);
		fclose(fp);
	}
}

static void WGET_GCC_NONNULL((1))
logger_write_fname(const wget_logger *logger, const char *buf, size_t len)
{
	FILE *fp = fopen(logger->fname, "a");

	if (fp) {
		fwrite(buf, 1, len, fp);
		fclose(fp);
	}
}

void wget_logger_set_func(wget_logger *logger, wget_logger_func *func)
{
	if (logger) {
		logger->func = func;
		logger->vprintf = func ? logger_vprintf_func : NULL;
		logger->write = func ? logger_write_func : NULL;
	}
}

wget_logger_func *wget_logger_get_func(wget_logger *logger)
{
	return logger ? logger->func : NULL;
}

void wget_logger_set_stream(wget_logger *logger, FILE *fp)
{
	if (logger) {
		logger->fp = fp;
		logger->vprintf = fp ? logger_vprintf_file : NULL;
		logger->write = fp ? logger_write_file : NULL;
	}
}

FILE *wget_logger_get_stream(wget_logger *logger)
{
	return logger ? logger->fp : NULL;
}

void wget_logger_set_file(wget_logger *logger, const char *fname)
{
	if (logger) {
		logger->fname = fname;
		logger->vprintf = fname ? logger_vprintf_fname : NULL;
		logger->write = fname ? logger_write_fname : NULL;
	}
}

const char *wget_logger_get_file(wget_logger *logger)
{
	return logger ? logger->fname : NULL;
}

bool wget_logger_is_active(wget_logger *logger)
{
	return logger->vprintf != 0;
}
