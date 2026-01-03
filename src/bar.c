/*
 * Copyright (c) 2014 Tim Ruehsen
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
 * Progress bar routines
 *
 * Changelog
 * 11.09.2014  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_options.h"
#include "wget_bar.h"


// Rate at which progress thread it updated. This is the amount of time (in ms)
// for which the thread will sleep before waking up and redrawing the progress
enum {
	BAR_THREAD_SLEEP_DURATION = 1000,
	BAR_THREAD_WINDOWS_CONSOLE_SIZE_CHECK_INTERVAL = 1000
};

static wget_bar
	*bar;
static wget_thread
	progress_thread;
static volatile bool
	terminate_thread;

// Dot progress implementation
#define RING_SIZE 64
typedef struct {
	long long total_length;
	long long downloaded;
	long long accumulated;
	long long row_start_bytes;
	long long row_start_time;
	long long time_ring[RING_SIZE];
	long long bytes_ring[RING_SIZE];
	int ring_pos;
	int dots_printed;
	int rows_printed;
	bool ring_wrapped;
	char *filename;
} dot_slot_t;

static dot_slot_t *dot_slots;
static int n_dot_slots;
static wget_thread_mutex dot_mutex;

static void dot_init(void)
{
	wget_thread_mutex_init(&dot_mutex);
}

static void dot_exit(void)
{
	if (dot_slots) {
		for (int i = 0; i < n_dot_slots; i++)
			xfree(dot_slots[i].filename);
		xfree(dot_slots);
	}
	wget_thread_mutex_destroy(&dot_mutex);
}

static void dot_slot_begin(int slot, const char *filename, ssize_t filesize)
{
	wget_thread_mutex_lock(dot_mutex);
	if (slot >= n_dot_slots) {
		int new_n = slot + 1;
		dot_slots = wget_realloc(dot_slots, new_n * sizeof(dot_slot_t));
		memset(dot_slots + n_dot_slots, 0, (new_n - n_dot_slots) * sizeof(dot_slot_t));
		n_dot_slots = new_n;
	}

	dot_slot_t *dp = &dot_slots[slot];
	xfree(dp->filename);
	dp->filename = wget_strdup(filename);
	dp->total_length = filesize;
	dp->downloaded = 0;
	dp->accumulated = 0;
	dp->row_start_bytes = 0;
	dp->row_start_time = wget_get_timemillis();
	dp->dots_printed = 0;
	dp->rows_printed = 0;

	// init ring buffer
	dp->ring_pos = 0;
	dp->ring_wrapped = false;
	dp->time_ring[0] = 0;
	dp->bytes_ring[0] = 0;

	wget_thread_mutex_unlock(dot_mutex);
}

static long long get_speed(dot_slot_t *dp)
{
	long long cur_time = wget_get_timemillis();

	// update ring buffer
	int next_pos = dp->ring_pos;
	dp->time_ring[next_pos] = cur_time;
	dp->bytes_ring[next_pos] = dp->downloaded;

	long long time_span;
	long long bytes_span;

	if (dp->ring_wrapped) {
		int oldest = next_pos + 1;
		if (oldest >= RING_SIZE)
			oldest = 0;
		time_span = cur_time - dp->time_ring[oldest];
		bytes_span = dp->downloaded - dp->bytes_ring[oldest];
	} else {
		time_span = cur_time - dp->row_start_time;
		bytes_span = dp->downloaded;
	}

	if (++dp->ring_pos >= RING_SIZE) {
		dp->ring_pos = 0;
		dp->ring_wrapped = true;
	}

	if (time_span <= 0) time_span = 1;
	return (bytes_span * 1000 + time_span / 2) / time_span;
}

static void print_row_stats(dot_slot_t *dp)
{
	long long speed = get_speed(dp);

	int percentage = 0;
	if (dp->total_length > 0)
		percentage = (int)(100 * dp->downloaded / dp->total_length);

	char speed_buf[16];
	wget_human_readable(speed_buf, sizeof(speed_buf), speed);

	char eta_buf[32] = "";
	if (dp->total_length > 0 && speed > 0) {
		long long eta = (dp->total_length - dp->downloaded + speed / 2) / speed;
		if (eta < 60)
			wget_snprintf(eta_buf, sizeof(eta_buf), "%llds", eta);
		else if (eta < 3600)
			wget_snprintf(eta_buf, sizeof(eta_buf), "%lldm%llds", eta / 60, eta % 60);
		else
			wget_snprintf(eta_buf, sizeof(eta_buf), "%lldh%lldm", eta / 3600, (eta % 3600) / 60);
	}

	wget_fprintf(stderr, " %3d%% %s %s", percentage, speed_buf, eta_buf);
}

static void dot_update(int slot, size_t nbytes)
{
	wget_thread_mutex_lock(dot_mutex);
	if (slot < n_dot_slots) {
		dot_slot_t *dp = &dot_slots[slot];
		dp->downloaded += nbytes;
		dp->accumulated += nbytes;

		const long long DOT_BYTES = config.dot_bytes ? config.dot_bytes : 1024;
		const int DOTS_PER_LINE = config.dots_in_line ? config.dots_in_line : 50;
		const int DOT_SPACING = config.dot_spacing ? config.dot_spacing : 10;

		while (dp->accumulated >= DOT_BYTES) {
			dp->accumulated -= DOT_BYTES;

			if (dp->dots_printed == 0) {
				char buf[16];
				wget_fprintf(stderr, "\n%6s", wget_human_readable(buf, sizeof(buf), dp->rows_printed * DOTS_PER_LINE * DOT_BYTES));
			}

			if (dp->dots_printed % DOT_SPACING == 0)
				wget_fprintf(stderr, " ");

			wget_fprintf(stderr, ".");
			dp->dots_printed++;

			if (dp->dots_printed >= DOTS_PER_LINE) {
				print_row_stats(dp);
				dp->dots_printed = 0;
				dp->rows_printed++;
			}
		}
		fflush(stderr);
	}
	wget_thread_mutex_unlock(dot_mutex);
}

static void dot_finish_slot(int slot)
{
	wget_thread_mutex_lock(dot_mutex);
	if (slot < n_dot_slots) {
		dot_slot_t *dp = &dot_slots[slot];
		const int DOTS_PER_LINE = config.dots_in_line ? config.dots_in_line : 50;
		const int DOT_SPACING = config.dot_spacing ? config.dot_spacing : 10;

		// Fill remaining dots with spaces to align stats
		if (dp->dots_printed > 0) {
			int spaces = DOTS_PER_LINE - dp->dots_printed;
			for (int i = dp->dots_printed; i < DOTS_PER_LINE; i++) {
				if (i % DOT_SPACING == 0)
					spaces++;
			}
			wget_fprintf(stderr, "%*.*s", spaces, spaces, "");
			print_row_stats(dp);
			wget_fprintf(stderr, "\n");
		} else if (dp->total_length == dp->downloaded) {
             // Let's just output a newline to be safe if we are not mid-line.
             wget_fprintf(stderr, "\n");
		}
        fflush(stderr);
	}
	wget_thread_mutex_unlock(dot_mutex);
}

#ifdef _WIN32
static void *bar_update_thread(void *p WGET_GCC_UNUSED)
{
	static int elapsed = 0;
	int lastWidth = 0;
	int curWidth = 0;

	while (!terminate_thread) {
		wget_bar_update(bar);
		wget_millisleep(BAR_THREAD_SLEEP_DURATION);

		elapsed += BAR_THREAD_SLEEP_DURATION;
		if (elapsed >= BAR_THREAD_WINDOWS_CONSOLE_SIZE_CHECK_INTERVAL) {
			if (! wget_get_screen_size(&curWidth, NULL) && curWidth != lastWidth)
				wget_bar_screen_resized();
			elapsed = 0;
		}
	}

	return NULL;
}
#else // _WIN32
static void *bar_update_thread(void *p WGET_GCC_UNUSED)
{
	while (!terminate_thread) {
		wget_bar_update(bar);
		wget_millisleep(BAR_THREAD_SLEEP_DURATION);
	}

	return NULL;
}
#endif // _WIN32

static void error_write(const char *buf, size_t len)
{
	// write 'above' the progress bar area, scrolls screen one line up, red text color
	// CSI 31m:  Red text color
	// CSI m: reset text color
	wget_bar_write_line_ext(bar, buf, len, "\033[31m", "\033[m");
}

static void info_write(const char *buf, size_t len)
{
	// write 'above' the progress bar area, scrolls screen one line up
	wget_bar_write_line(bar, buf, len);
}

bool bar_init(void)
{
	if (config.progress == PROGRESS_TYPE_DOT) {
		dot_init();
		return true;
	}

	if (wget_thread_support()) {
		if (!(bar = wget_bar_init(NULL, 1)))
			goto nobar;

		wget_bar_set_speed_type(config.report_speed);

		// set custom write function for wget_error_printf()
		wget_logger_set_func(wget_get_logger(WGET_LOGGER_ERROR), error_write);
		wget_logger_set_func(wget_get_logger(WGET_LOGGER_INFO), info_write);

		terminate_thread = 0;
		if (wget_thread_start(&progress_thread, bar_update_thread, NULL, 0)) {
			wget_bar_free(&bar);
			goto nobar;
		}

		return true;
	}

nobar:
	wget_error_printf(_("Cannot create progress bar thread. Disabling progress bar.\n"));
	config.progress = PROGRESS_TYPE_NONE;
	return false;
}

void bar_deinit(void)
{
	if (config.progress == PROGRESS_TYPE_DOT) {
		dot_exit();
		return;
	}

	if (bar) {
		terminate_thread = 1;
		wget_thread_join(&progress_thread);
		wget_bar_free(&bar);
	}
}

void bar_print(int slot, const char *s)
{
	if (config.progress == PROGRESS_TYPE_DOT) return;
	wget_bar_print(bar, slot, s);
}

void bar_vprintf(int slot, const char *fmt, va_list args)
{
	if (config.progress == PROGRESS_TYPE_DOT) return;
	wget_bar_vprintf(bar, slot, fmt, args);
}

void bar_printf(int slot, const char *fmt, ...)
{
	if (config.progress == PROGRESS_TYPE_DOT) return;
	va_list args;

	va_start(args, fmt);
	bar_vprintf(slot, fmt, args);
	va_end(args);
}

void bar_slot_begin(int slot, const char *filename, int new_file, ssize_t filesize)
{
	if (config.progress == PROGRESS_TYPE_DOT) {
		dot_slot_begin(slot, filename, filesize);
		return;
	}
	wget_bar_slot_begin(bar, slot, filename, new_file, filesize);
}

void bar_set_downloaded(int slot, size_t nbytes)
{
	if (config.progress == PROGRESS_TYPE_DOT) {
		dot_update(slot, nbytes);
		return;
	}
	wget_bar_slot_downloaded(bar, slot, nbytes);
}

void bar_slot_deregister(int slot)
{
	if (config.progress == PROGRESS_TYPE_DOT) {
		dot_finish_slot(slot);
		return;
	}
	wget_bar_slot_deregister(bar, slot);
}

void bar_update_slots(int nslots)
{
	if (config.progress == PROGRESS_TYPE_DOT) return;
	wget_bar_set_slots(bar, nslots);
}
