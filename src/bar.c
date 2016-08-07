/*
 * Copyright(c) 2014 Tim Ruehsen
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
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include <libwget.h>

#include "options.h"
//#include "log.h"
#include "bar.h"
#include "utils.h"


// Rate at which progress thread it updated. This is the amount of time (in ms)
// for which the thread will sleep before waking up and redrawing the progress
enum { _BAR_THREAD_SLEEP_DURATION = 125 };

//Forward declaration for progress bar thread
static void *wget_bar_update_thread(void *p) G_GNUC_WGET_FLATTEN;

static wget_bar_t
	*bar;
static wget_thread_mutex_t
	mutex = WGET_THREAD_MUTEX_INITIALIZER;
static wget_thread_t
	progress_thread;
static int
	screen_width;

void bar_init(void)
{
	char lf[config.num_threads + 1];

	memset(lf, '\n', config.num_threads + 1);
	fwrite(lf, 1, config.num_threads + 1, stdout);

	/* Initialize screen_width if this hasn't been done or if it might
	   have changed, as indicated by receiving SIGWINCH.  */
	screen_width = determine_screen_width ();
	if (!screen_width)
		screen_width = DEFAULT_SCREEN_WIDTH;
	else if (screen_width < MINIMUM_SCREEN_WIDTH)
		screen_width = MINIMUM_SCREEN_WIDTH;

	bar = wget_bar_init(NULL, config.num_threads + 1, screen_width - 1);

	wget_thread_start(&progress_thread, wget_bar_update_thread, bar, 0);


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
	wget_bar_deinit(bar);
	wget_thread_cancel(progress_thread);
	wget_thread_join(progress_thread);
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

void bar_register(wget_bar_ctx *bar_ctx)
{
	wget_thread_mutex_lock(&mutex);
	wget_bar_register(bar, bar_ctx);
	wget_thread_mutex_unlock(&mutex);
}

void bar_deregister(wget_bar_ctx *bar_ctx)
{
	wget_thread_mutex_lock(&mutex);
	wget_bar_deregister(bar, bar_ctx);
	wget_thread_mutex_unlock(&mutex);
}

static void *wget_bar_update_thread(void *p)
{
	wget_bar_t *prog_bar = (wget_bar_t *) p;

	/* while (!terminate) { */
	while (true) {
		for (int i = 0; i < config.num_threads; i++) {
			wget_bar_update(prog_bar, i);
		}
		wget_millisleep(_BAR_THREAD_SLEEP_DURATION);
	}
	return NULL;
}
