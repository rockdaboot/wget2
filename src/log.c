/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
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
#include <fcntl.h>
#include "timespec.h" // gnulib gettime()

#include <libwget.h>

#include "options.h"
#include "log.h"

static void _write_out(FILE *default_fp, const char *data, size_t len, int with_timestamp, const char *colorstring)
{
	FILE *fp;
	int fd = -1;
	int tty = 0;

	if (!data || (ssize_t)len <= 0)
		return;

	if (!config.logfile) {
		fp = default_fp;
	} else if (!strcmp(config.logfile, "-")) {
		fp = stdout;
	} else {
		fp = NULL;
		fd = open(config.logfile, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (fd == -1)
			fp = default_fp;
	}

	if (fp)
		tty = isatty(fileno(fp));

	char sbuf[4096];
	wget_buffer_t buf;
	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	if (tty && colorstring)
		wget_buffer_strcpy(&buf, colorstring);

	if (with_timestamp) {
		struct timespec ts;
		struct tm *tp, tbuf;

		gettime(&ts);
		tp = localtime_r((const time_t *)&ts.tv_sec, &tbuf); // cast avoids warning on OpenBSD

		wget_buffer_printf_append(&buf, "%02d.%02d%02d%02d.%03d ",
			tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec, (int) (ts.tv_nsec / 1000000));
	}

	wget_buffer_memcat(&buf, data, len);
	if (data[len -1] != '\n')
		wget_buffer_memcat(&buf, "\n", 1);

	if (tty && colorstring)
		wget_buffer_strcat(&buf, "\033[m"); // reset text color

	if (fp) {
		fwrite(buf.data, 1, buf.length, fp);
	} else if (fd != -1) {
		if (write(fd, buf.data, buf.length) == -1)
			fwrite(buf.data, 1, buf.length, stderr);
		close(fd);
	}

	wget_buffer_deinit(&buf);
}

static void _write_debug(const char *data, size_t len)
{
	if (!data || (ssize_t)len <= 0)
		return;

	_write_out(stderr, data, len, 1, "\033[35m"); // magenta/purple text
}

static void _write_error(const char *data, size_t len)
{
	if (!data || (ssize_t)len <= 0)
		return;

	_write_out(stderr, data, len, 0, "\033[31m"); // red text
}

static void _write_info(const char *data, size_t len)
{
	if (!data || (ssize_t)len <= 0)
		return;

	_write_out(stdout, data, len, 0, NULL);
}

void log_init(void)
{
/*
	WGET_LOGGER *logger = wget_get_logger(WGET_LOGGER_DEBUG);
	if (config.debug) {
		if (!config.logfile)
			wget_logger_set_file(logger, stderr); // direct debug output to STDERR
		else if (*config.logfile == '-' && config.logfile[1] == 0)
			wget_logger_set_file(logger, stdout); // direct debug output to STDIN
		else
			wget_logger_set_filename(logger, config.logfile);  // direct debug output to logfile

		wget_logger_set_timestamp(logger, 1); // switch timestamps on
	} else
		wget_logger_set_file(logger, NULL); // stop logging (if already started)
*/

	// set debug logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_DEBUG), config.debug ? _write_debug : NULL);

	// set debug logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_ERROR), config.quiet ? NULL : _write_error);

	// set error logging
//	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), config.quiet ? NULL : stderr);

	// set info logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_INFO), config.verbose && !config.quiet ? _write_info : NULL);
//	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), config.verbose && !config.quiet ? stdout : NULL);
}
