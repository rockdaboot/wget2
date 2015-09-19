/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Logger routines
 *
 * Changelog
 * 09.01.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include <libwget.h>
#include "private.h"

/*
static void G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((1,2))
_logger_vprintf_func(const wget_logger_t *logger, const char *fmt, va_list args)
{
	char sbuf[4096];
	int err = errno, len;
	va_list args2;

	// vsnprintf destroys args, so we need a copy for the fallback case
	va_copy(args2, args);

	// first try without malloc
	len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);

	if (len >= 0 && len < (int)sizeof(sbuf)) {
		logger->func(sbuf, len);
	} else {
		// fallback to memory allocation, print without timestamp
		char *buf;
		len = vasprintf(&buf, fmt, args2);
		if (len != -1) {
			logger->func(buf, len);
			xfree(buf);
		}
	}

	errno = err;
}
*/

static void G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((1,2))
_logger_vprintf_func(const wget_logger_t *logger, const char *fmt, va_list args)
{
	char sbuf[4096];
	wget_buffer_t buf;
	int err = errno;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf2(&buf, fmt, args);
	logger->func(buf.data, buf.length);
	wget_buffer_deinit(&buf);

	errno = err;
}

static void _logger_write_func(const wget_logger_t *logger, const char *buf, size_t len)
{
	logger->func(buf, len);
}

static void  G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((1,2))
_logger_vfprintf(FILE *fp, const char *fmt, va_list args)
{
	char sbuf[4096];
	wget_buffer_t buf;
	int err = errno;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf2(&buf, fmt, args);
	fwrite(buf.data, 1, buf.length, fp);
	wget_buffer_deinit(&buf);

	errno = err;
}

static void  G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((1,2))
_logger_vprintf_file(const wget_logger_t *logger, const char *fmt, va_list args)
{
	_logger_vfprintf(logger->fp, fmt, args);
}

static void _logger_write_file(const wget_logger_t *logger, const char *buf, size_t len)
{
	fwrite(buf, 1, len, logger->fp);
}

static void G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL((1,2))
_logger_vprintf_fname(const wget_logger_t *logger, const char *fmt, va_list args)
{
	FILE *fp = fopen(logger->fname, "a");

	if (fp) {
		_logger_vfprintf(fp, fmt, args);
		fclose(fp);
	}
}

static void _logger_write_fname(const wget_logger_t *logger, const char *buf, size_t len)
{
	FILE *fp = fopen(logger->fname, "a");

	if (fp) {
		fwrite(buf, 1, len, fp);
		fclose(fp);
	}
}

void wget_logger_set_func(wget_logger_t *logger, void (*func)(const char *buf, size_t len))
{
	if (logger) {
		logger->func = func;
		logger->vprintf = func ? _logger_vprintf_func : NULL;
		logger->write = func ? _logger_write_func : NULL;
	}
}

void (*wget_logger_get_func(wget_logger_t *logger))(const char *, size_t)
{
	return logger ? logger->func : NULL;
}

void wget_logger_set_stream(wget_logger_t *logger, FILE *fp)
{
	if (logger) {
		logger->fp = fp;
		logger->vprintf = fp ? _logger_vprintf_file : NULL;
		logger->write = fp ? _logger_write_file : NULL;
	}
}

FILE *wget_logger_get_stream(wget_logger_t *logger)
{
	return logger ? logger->fp : NULL;
}

void wget_logger_set_file(wget_logger_t *logger, const char *fname)
{
	if (logger) {
		logger->fname = fname;
		logger->vprintf = fname ? _logger_vprintf_fname : NULL;
		logger->write = fname ? _logger_write_fname : NULL;
	}
}

const char *wget_logger_get_file(wget_logger_t *logger)
{
	return logger ? logger->fname : NULL;
}
