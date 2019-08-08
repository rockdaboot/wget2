/*
 * Copyright(c) 2014 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 * Progress bar routines
 *
 * Changelog
 * 11.09.2014  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_options.h"
#include "wget_log.h"
#include "wget_bar.h"


// Rate at which progress thread it updated. This is the amount of time (in ms)
// for which the thread will sleep before waking up and redrawing the progress
enum { _BAR_THREAD_SLEEP_DURATION = 125 };

static wget_bar
	*bar;
static wget_thread
	progress_thread;
static bool
	_terminate_thread;

static void *_bar_update_thread(void *p WGET_GCC_UNUSED)
{
	while (!_terminate_thread) {
		wget_bar_update(bar);

		wget_millisleep(_BAR_THREAD_SLEEP_DURATION);
	}

	return NULL;
}

static void _error_write(const char *buf, size_t len)
{
	// write 'above' the progress bar area, scrolls screen one line up
	wget_bar_write_line(bar, buf, len);
}

bool bar_init(void)
{
	if (wget_thread_support()) {
		if (!(bar = wget_bar_init(NULL, 1)))
			goto nobar;

		wget_bar_set_speed_type(config.report_speed);

		// set custom write function for wget_error_printf()
		wget_logger_set_func(wget_get_logger(WGET_LOGGER_ERROR), _error_write);

		_terminate_thread = 0;
		if (wget_thread_start(&progress_thread, _bar_update_thread, NULL, 0)) {
			wget_bar_free(&bar);
			goto nobar;
		}

		return true;
	}

nobar:
	wget_error_printf(_("Cannot create progress bar thread. Disabling progress bar.\n"));
	config.progress = 0;
	return false;
}

void bar_deinit(void)
{
	_terminate_thread = 1;
	wget_thread_join(&progress_thread);
	wget_bar_free(&bar);
}

void bar_print(int slot, const char *s)
{
	wget_bar_print(bar, slot, s);
}

void bar_vprintf(int slot, const char *fmt, va_list args)
{
	wget_bar_vprintf(bar, slot, fmt, args);
}

void bar_printf(int slot, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	bar_vprintf(slot, fmt, args);
	va_end(args);
}

void bar_slot_begin(int slot, const char *filename, int new_file, ssize_t filesize)
{
	wget_bar_slot_begin(bar, slot, filename, new_file, filesize);
}

void bar_set_downloaded(int slot, size_t nbytes)
{
	wget_bar_slot_downloaded(bar, slot, nbytes);
}

void bar_slot_deregister(int slot)
{
	wget_bar_slot_deregister(bar, slot);
}

void bar_update_slots(int nslots)
{
	wget_bar_set_slots(bar, nslots);
}
