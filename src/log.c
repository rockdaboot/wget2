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

#include "options.h"
#include "log.h"

static void _write_debug(const char *data, size_t len)
{
	FILE *fp;
	struct timeval tv;
	struct tm *tp, tbuf;

	if (!data || (ssize_t)len <= 0)
		return;

	gettimeofday(&tv, NULL); // obsoleted by POSIX.1-2008, maybe use clock_gettime() ? needs -lrt
	tp = localtime_r((const time_t *)&tv.tv_sec, &tbuf); // cast avoids warning on OpenBSD

	if (!config.logfile)
		fp = stderr;
	else if (*config.logfile == '-' && config.logfile[1] == 0)
		fp = stdout;
	else
		fp = fopen(config.logfile, "a");

	if (fp) {
		char sbuf[4096];
		mget_buffer_t buf;

		mget_buffer_init(&buf, sbuf, sizeof(sbuf));
		mget_buffer_printf2(&buf, "%02d.%02d%02d%02d.%03d ",
			tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec, (int) (tv.tv_usec / 1000));
		mget_buffer_memcat(&buf, data, len);
		if (data[len -1] != '\n')
			mget_buffer_memcat(&buf, "\n", 1);
		fwrite(buf.data, 1, buf.length, fp);
		mget_buffer_deinit(&buf);

		if (fp != stderr && fp != stdout)
			fclose(fp);
	}
}

void log_init(void)
{
/*
	MGET_LOGGER *logger = mget_get_logger(MGET_LOGGER_DEBUG);
	if (config.debug) {
		if (!config.logfile)
			mget_logger_set_file(logger, stderr); // direct debug output to STDERR
		else if (*config.logfile == '-' && config.logfile[1] == 0)
			mget_logger_set_file(logger, stdout); // direct debug output to STDIN
		else
			mget_logger_set_filename(logger, config.logfile);  // direct debug output to logfile

		mget_logger_set_timestamp(logger, 1); // switch timestamps on
	} else
		mget_logger_set_file(logger, NULL); // stop logging (if already started)
*/

	// set debug logging
	mget_logger_set_func(mget_get_logger(MGET_LOGGER_DEBUG), config.debug ? _write_debug : NULL);

	// set error logging
	mget_logger_set_stream(mget_get_logger(MGET_LOGGER_ERROR), config.quiet ? NULL : stderr);

	// set info logging
	mget_logger_set_stream(mget_get_logger(MGET_LOGGER_INFO), config.verbose && !config.quiet ? stdout : NULL);
}
