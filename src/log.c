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
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#if defined __clang__
  // silence warnings in gnulib code
  #pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

#include "timespec.h" // gnulib gettime()

#ifdef _WIN32
#	include <windows.h>
	static CRITICAL_SECTION g_crit;
#endif

#include <wget.h>

#include "wget_options.h"
#include "wget_log.h"

static void write_out(
	FILE *default_fp,
	const char *data,
	size_t len,
	int with_timestamp,
	const char *colorstring,
	wget_console_color color_id)
{
	FILE *fp;
	int fd = -1;

	if (!data || (ssize_t)len <= 0)
		return;

	if (!config.logfile) {
		fp = default_fp;
	} else if (!strcmp(config.logfile, "-")) {
		fp = stdout;
	} else {
		fp = NULL;
		if (!config.dont_write)
			fd = open(config.logfile, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fd == -1)
			fp = default_fp;
	}

	char sbuf[4096];
	wget_buffer buf;
	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

#ifndef _WIN32
	int use_color = 0;

	if (fp && colorstring && isatty(fileno(fp)))
		use_color = 1;

	if (use_color)
		wget_buffer_strcpy(&buf, colorstring);
#else
	(void) colorstring; // silence unused warning
#endif

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

#ifndef _WIN32
	if (use_color)
		wget_buffer_strcat(&buf, "\033[m"); // reset text color
#endif

	if (fp) {
#ifndef _WIN32
		(void) color_id; // silence unused warning
		fwrite(buf.data, 1, buf.length, fp);
#else
		EnterCriticalSection(&g_crit);
		wget_console_set_fg_color(color_id);
		fwrite(buf.data, 1, buf.length, fp);
		fflush(fp);
		wget_console_reset_fg_color();
		LeaveCriticalSection (&g_crit);
#endif
	} else if (fd != -1) {
		if (write(fd, buf.data, buf.length) == -1)
			fwrite(buf.data, 1, buf.length, stderr);
		close(fd);
	}

	wget_buffer_deinit(&buf);
}

static void write_debug(FILE *fp, const char *data, size_t len)
{
	write_out(fp, data, len, 1, "\033[35m", WGET_CONSOLE_COLOR_MAGENTA); // magenta/purple text
}

static void write_error(FILE *fp, const char *data, size_t len)
{
	write_out(fp, data, len, 0, "\033[31m", WGET_CONSOLE_COLOR_RED); // red text
}

static void write_info(FILE *fp, const char *data, size_t len)
{
	if (!data || (ssize_t)len <= 0)
		return;

	write_out(fp, data, len, 0, NULL, WGET_CONSOLE_COLOR_WHITE /* Or 'WGET_CONSOLE_COLOR_RESET'? */);

}

static void write_debug_stderr(const char *data, size_t len)
{
	write_debug(stderr, data, len);
}

static void WGET_GCC_UNUSED write_debug_stdout(const char *data, size_t len)
{
	write_debug(stdout, data, len);
}

static void write_error_stderr(const char *data, size_t len)
{
	write_error(stderr, data, len);
}

static void write_error_stdout(const char *data, size_t len)
{
	write_error(stdout, data, len);
}

static void write_info_stderr(const char *data, size_t len)
{
	write_info(stderr, data, len);
}

static void write_info_stdout(const char *data, size_t len)
{
	write_info(stdout, data, len);
}


void log_write_error_stdout(const char *data, size_t len)
{
	write_error_stdout(data, len);
}

void log_init(void)
{
#ifdef _WIN32
	InitializeCriticalSection (&g_crit);
#endif

	wget_console_init();

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

// no printing during fuzzing
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	// set debug logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_DEBUG), config.debug ? write_debug_stderr : NULL);

	// set debug logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_ERROR), config.quiet ? NULL : write_error_stderr);

	// set error logging
//	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), config.quiet ? NULL : stderr);

	// set info logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_INFO),
		config.verbose && !config.quiet ? ((fileno(stdout) == fileno(stderr) || !wget_strcmp(config.output_document, "-")) ? write_info_stderr : write_info_stdout) : NULL);
//	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), config.verbose && !config.quiet ? stdout : NULL);
#endif
}
