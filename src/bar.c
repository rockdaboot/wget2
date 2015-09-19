/*
 * Copyright(c) 2014 Tim Ruehsen
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
 * Progress bar routines
 *
 * Changelog
 * 11.09.2014  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include <libwget.h>

#include "options.h"
//#include "log.h"
#include "bar.h"

static wget_bar_t
	*bar;
static wget_thread_mutex_t
	mutex = WGET_THREAD_MUTEX_INITIALIZER;

void bar_init(void)
{
	char lf[config.num_threads + 1];

	memset(lf, '\n', config.num_threads + 1);
	fwrite(lf, 1, config.num_threads + 1, stdout);

	bar = wget_bar_init(NULL, config.num_threads + 1, 70);
	
/*
	// set debug logging
	wget_logger_set_func(wget_get_logger(WGET_LOGGER_DEBUG), config.debug ? _write_debug : NULL);

	// set error logging
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), config.quiet ? NULL : stderr);

	// set info logging
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), config.verbose && !config.quiet ? stdout : NULL);
*/
}

void bar_deinit(void)
{
	wget_bar_free(&bar);
}

void bar_print(int slotpos, const char *s)
{
	// This function will be called async from threads.
	// Cursor positioning might break without a mutex.
	wget_thread_mutex_lock(&mutex);
	wget_bar_print(bar, slotpos, s);
	wget_thread_mutex_unlock(&mutex);
}

void bar_vprintf(int slotpos, const char *fmt, va_list args)
{
	wget_thread_mutex_lock(&mutex);
	wget_bar_vprintf(bar, slotpos, fmt, args);
	wget_thread_mutex_unlock(&mutex);
}

void bar_printf(int slotpos, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	bar_vprintf(slotpos, fmt, args);
	va_end(args);
}

void bar_update(int slotpos, int max, int cur)
{
	wget_thread_mutex_lock(&mutex);
	wget_bar_update(bar, slotpos, max, cur);
	wget_thread_mutex_unlock(&mutex);
}
