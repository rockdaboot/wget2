/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Logging routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
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

#include <libmget.h>

#include "xalloc.h"
#include "printf.h"
#include "log.h"

static const char
	*logfile;
static char
	debug,
	quiet,
	verbose = 1;

static void _write_log(const char *buf, int len)
{
	FILE *fp;
	struct timeval tv;
	struct tm *tp, tbuf;

	if (!buf || len <= 0)
		return;

	gettimeofday(&tv, NULL); // obsoleted by POSIX.1-2008, maybe use clock_gettime() ? needs -lrt
	tp = localtime_r((const time_t *)&tv.tv_sec, &tbuf); // cast top avoid warning on OpenBSD

	if (!logfile)
		fp = stderr;
	else if (*logfile == '-' && logfile[1] == 0)
		fp = stdout;
	else
		fp = fopen(logfile, "a");

	if (fp) {
		fprintf(fp, "%02d.%02d%02d%02d.%03ld %s%s",
			tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec, tv.tv_usec / 1000,
			buf, buf[len - 1] == '\n' ? "" : "\n");

		if (fp != stderr && fp != stdout)
			fclose(fp);
	}
}

void log_set_logfile(const char *_logfile)
{
	logfile = _logfile;
}

void log_set_debug(char _debug)
{
	debug = _debug;
}

void log_set_quiet(char _quiet)
{
	quiet = _quiet;
}

void log_set_verbose(char _verbose)
{
	verbose = _verbose;
}

void log_vprintf(const char *fmt, va_list args)
{
	if (debug) {
		char sbuf[4096];
		int err = errno, len;
		va_list args2;

		// vsnprintf destroys args, so we need a copy for the fallback case
		va_copy(args2, args);

		// first try without malloc
		len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);

		if (len >= 0 && len < (int)sizeof(sbuf)) {
			_write_log(sbuf, len);
		} else {
			// fallback to memory allocation
			char *buf;
			len = vasprintf(&buf, fmt, args2);
			if (len != -1) {
				_write_log(buf, len);
				xfree(buf);
			}
		}

		errno = err;
	}
}

void log_printf(const char *fmt, ...)
{
	if (debug) {
		va_list args;

		va_start(args, fmt);
		log_vprintf(fmt, args);
		va_end(args);
	}
}

void log_printf_exit(const char *fmt, ...)
{
	if (debug) {
		va_list args;

		va_start(args, fmt);
		log_vprintf(fmt, args);
		va_end(args);
	}

	exit(EXIT_FAILURE);
}

void log_write(const char *buf, int len)
{
	if (debug) {
		_write_log(buf, len);
	}
}

void err_printf_exit(const char *fmt, ...)
{
	if (!quiet) {
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}

	exit(EXIT_FAILURE);
}

void err_printf(const char *fmt, ...)
{
	if (!quiet) {
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}
}

void info_printf(const char *fmt, ...)
{
	if (verbose && !quiet) {
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}
}
