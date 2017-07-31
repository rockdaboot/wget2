/*
 * Copyright(c) 2014 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Progress bar routines
 *
 * Changelog
 * 18.10.2014  Tim Ruehsen  created from src/bar.c
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
#include <signal.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Progress Bar Routines
 * \defgroup libwget-progress Progress Display Functions
 * @{
 *
 * Methods for creating and printing a progress bar display.
 */


// We use enums to define the progress bar parameters because they are the
// closest thing we have to defining true constants in C without using
// preprocessor macros. The advantage of enums is that they will create a
// symbol in the symbol table making debugging a whole lot easier.

// Define the parameters for how the progress bar looks
enum _BAR_SIZES {
	_BAR_FILENAME_SIZE  = 20,
	_BAR_RATIO_SIZE     =  3,
	_BAR_METER_COST     =  2,
	_BAR_DOWNBYTES_SIZE =  8,
};

// Define the cost (in number of columns) of the progress bar decorations. This
// includes all the elements that are not the progress indicator itself.
enum _BAR_DECOR_SIZE {
	_BAR_DECOR_COST =
		_BAR_FILENAME_SIZE  + 1 + \
		_BAR_RATIO_SIZE     + 2 + \
		_BAR_METER_COST     + 1 + \
		_BAR_DOWNBYTES_SIZE
};

enum _SCREEN_WIDTH {
	DEFAULT_SCREEN_WIDTH = 70,
	MINIMUM_SCREEN_WIDTH = 45,
};

enum _bar_slot_status_t {
	EMPTY = 0,
	DOWNLOADING = 1,
	COMPLETE = 2
};

typedef struct {
	char
		*progress,
		*filename,
		human_size[_BAR_DOWNBYTES_SIZE];
	uint64_t
		file_size,
		bytes_downloaded;
	int
		tick;
	enum _bar_slot_status_t
		status;
	unsigned
		redraw : 1;
} _bar_slot_t;

struct _wget_bar_st {
	_bar_slot_t
		*slots;
	char
		*progress_mem_holder,
		*unknown_size,
		*known_size,
		*spaces;
	int
		nslots,
		screen_width,
		max_width;
	wget_thread_mutex_t
		mutex;
};

static volatile sig_atomic_t winsize_changed;

static inline G_GNUC_WGET_ALWAYS_INLINE void
_restore_cursor_position(void)
{
	// CSI u: Restore cursor position
	printf("\033[u");
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_bar_print_slot(const wget_bar_t *bar, int slot)
{
	// CSI s: Save cursor
	// CSI <n> A: Cursor up
	// CSI <n> G: Cursor horizontal absolute
	printf("\033[s\033[%dA\033[1G", bar->nslots - slot);
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_bar_set_progress(const wget_bar_t *bar, int slot)
{
	_bar_slot_t *slotp = &bar->slots[slot];

	if (slotp->file_size > 0) {
//		size_t bytes = (slot->status == DOWNLOADING) ? slot->raw_downloaded : slot->bytes_downloaded;
		size_t bytes = slotp->bytes_downloaded;
		int cols = (int) ((bytes / (double) slotp->file_size) * bar->max_width);
		if (cols > bar->max_width)
			cols = bar->max_width;
		else if (cols <= 0)
			cols = 1;

		snprintf(slotp->progress, bar->max_width + 1, "%.*s>%.*s",
				cols - 1, bar->known_size,
				bar->max_width - cols, bar->spaces);
	} else {
		int ind = slotp->tick % ((bar->max_width * 2) - 6);
		int pre_space;

		if (ind <= bar->max_width - 3)
			pre_space = ind;
		else
			pre_space = bar->max_width - (ind - bar->max_width + 5);

		snprintf(slotp->progress, bar->max_width + 1, "%.*s<=>%.*s",
				pre_space, bar->spaces,
				bar->max_width - pre_space - 4, bar->spaces);
	}
}

static void _bar_update_slot(const wget_bar_t *bar, int slot)
{
	uint64_t max, cur;
	int ratio;
	char *human_readable_bytes;
	_bar_slot_t *slotp = &bar->slots[slot];

	// We only print a progress bar for the slot if a context has been
	// registered for it
	if (slotp->status == DOWNLOADING || slotp->status == COMPLETE) {
		max = slotp->file_size;
		cur = slotp->bytes_downloaded;

		ratio = max ? (int) ((100 * cur) / max) : 0;

		human_readable_bytes = wget_human_readable(slotp->human_size, sizeof(slotp->human_size), cur);
		_bar_set_progress(bar, slot);

		_bar_print_slot(bar, slot);

		// The progress bar looks like this:
		//
		// filename   xxx% [======>      ] xxx.xxK
		//
		// It is made of the following elements:
		// filename		_BAR_FILENAME_SIZE		Name of local file
		// xxx%			_BAR_RATIO_SIZE + 1		Amount of file downloaded
		// []			_BAR_METER_COST			Bar Decorations
		// xxx.xxK		_BAR_DOWNBYTES_SIZE		Number of downloaded bytes
		// ===>			Remaining				Progress Meter

		printf("%-*.*s %*d%% [%s] %*s",
				_BAR_FILENAME_SIZE, _BAR_FILENAME_SIZE, slotp->filename,
				_BAR_RATIO_SIZE, ratio,
				slotp->progress,
				_BAR_DOWNBYTES_SIZE, human_readable_bytes);

		_restore_cursor_position();
		fflush(stdout);
		slotp->tick++;
	}
}

static int _bar_get_width(void)
{
	int width = DEFAULT_SCREEN_WIDTH;

	if (wget_get_screen_size(&width, NULL) == 0) {
		if (width < MINIMUM_SCREEN_WIDTH)
			width = MINIMUM_SCREEN_WIDTH;
		else
			width--; // leave one space at the end, else we see a linebreak on Windows
	}

	return width - _BAR_DECOR_COST;
}

static void _bar_update_winsize(wget_bar_t *bar, bool slots_changed) {

	if (winsize_changed || slots_changed) {
		int max_width = _bar_get_width();

		if (bar->max_width < max_width) {
			xfree(bar->known_size);
			bar->known_size = xmalloc(max_width);
			memset(bar->known_size, '=', max_width);

			xfree(bar->unknown_size);
			bar->unknown_size = xmalloc(max_width);
			memset(bar->unknown_size, '*', max_width);

			xfree(bar->spaces);
			bar->spaces = xmalloc(max_width);
			memset(bar->spaces, ' ', max_width);
		}
		if (bar->max_width < max_width || slots_changed) {
			xfree(bar->progress_mem_holder);
			bar->progress_mem_holder = xcalloc(bar->nslots, max_width);
			for (int i = 0; i < bar->nslots; i++) {
				bar->slots[i].progress = bar->progress_mem_holder + (i * max_width);
			}
		}

		bar->max_width = max_width;
	}
	winsize_changed = 0;

}

static void _bar_update(wget_bar_t *bar)
{
	_bar_update_winsize(bar, false);
	for (int i = 0; i < bar->nslots; i++) {
		if (bar->slots[i].redraw || winsize_changed) {
			_bar_update_slot(bar, i);
			bar->slots[i].redraw = 0;
		}
	}
}


/**
 * \param[in] bar Pointer to a \p wget_bar_t object
 * \param[in] nslots Number of progress bars
 * \return Pointer to a \p wget_bar_t object
 *
 * Initialize a new progress bar instance for Wget. If \p bar is a NULL
 * pointer, it will be allocated on the heap and a pointer to the newly
 * allocated memory will be returned. To free this memory, call either the
 *  wget_bar_deinit() or wget_bar_free() functions based on your needs.
 *
 * \p nslots is the number of screen lines to reserve for printing the progress
 * bars. This may be any number, but you generally want at least as many slots
 * as there are downloader threads.
 */
wget_bar_t *wget_bar_init(wget_bar_t *bar, int nslots)
{

	/* Initialize screen_width if this hasn't been done or if it might
	   have changed, as indicated by receiving SIGWINCH.  */
	int max_width = _bar_get_width();

	if (nslots < 1 || max_width < 1)
		return NULL;

	if (!bar) {
		bar = xcalloc(1, sizeof(*bar));
	} else
		memset(bar, 0, sizeof(*bar));

	wget_bar_set_slots(bar, nslots);

	return bar;
}

/**
 * \param[in] bar Pointer to a wget_bar_t object
 * \param[in] nslots The new number of progress bars that should be drawn
 *
 * Update the number of progress bar lines that are drawn on the screen.
 * This is useful when the number of downloader threads changes dynamically or
 * to change the number of reserved lines. Calling this function will
 * immediately reserve \p nslots lines on the screen. However if \p nslots is
 * lower than the existing value, nothing will be done.
 */
void wget_bar_set_slots(wget_bar_t *bar, int nslots)
{
	wget_thread_mutex_lock(&bar->mutex);
	int more_slots = nslots - bar->nslots;

	if (more_slots > 0) {
		xfree(bar->slots);
		bar->slots = xcalloc(nslots, sizeof(_bar_slot_t));
		bar->nslots = nslots;
		for (int i = 0; i < more_slots; i++) {
			printf("\n");
		}
		_bar_update_winsize(bar, true);
		_bar_update(bar);
	}
	wget_thread_mutex_unlock(&bar->mutex);
}

void wget_bar_slot_begin(wget_bar_t *bar, int slot, const char *filename, ssize_t file_size)
{
	wget_thread_mutex_lock(&bar->mutex);
	_bar_slot_t *slotp = &bar->slots[slot];

	xfree(slotp->filename);
	slotp->filename = wget_strdup(filename);
	slotp->tick = 0;
	slotp->file_size = file_size;
	slotp->bytes_downloaded = 0;
	slotp->status = DOWNLOADING;
	slotp->redraw = 1;
	wget_thread_mutex_unlock(&bar->mutex);
}

void wget_bar_slot_downloaded(wget_bar_t *bar, int slot, size_t nbytes)
{
	wget_thread_mutex_lock(&bar->mutex);
	bar->slots[slot].bytes_downloaded = nbytes;
	bar->slots[slot].redraw = 1;
	wget_thread_mutex_unlock(&bar->mutex);
}

void wget_bar_slot_deregister(wget_bar_t *bar, int slot)
{
	wget_thread_mutex_lock(&bar->mutex);
	if (slot >= 0 && slot < bar->nslots) {
		_bar_slot_t *slotp = &bar->slots[slot];

		slotp->status = COMPLETE;
		_bar_update_slot(bar, slot);
	}
	wget_thread_mutex_unlock(&bar->mutex);
}

void wget_bar_update(wget_bar_t *bar)
{
	wget_thread_mutex_lock(&bar->mutex);
	_bar_update(bar);
	wget_thread_mutex_unlock(&bar->mutex);
}

/**
 * \param[in] bar Pointer to \p wget_bar_t
 *
 * Free the various progress bar data structures.
 */
void wget_bar_deinit(wget_bar_t *bar)
{
	if (bar) {
		for (int i = 0; i < bar->nslots; i++) {
			xfree(bar->slots[i].filename);
		}
		xfree(bar->progress_mem_holder);
		xfree(bar->spaces);
		xfree(bar->known_size);
		xfree(bar->unknown_size);
		xfree(bar->slots);
	}
}

/**
 * Free the pointer holding the \p *wget_bar_t structure as well
 */
void wget_bar_free(wget_bar_t **bar)
{
	if (bar) {
		wget_bar_deinit(*bar);
		xfree(*bar);
	}
}

void wget_bar_print(wget_bar_t *bar, int slot, const char *s)
{
	wget_thread_mutex_lock(&bar->mutex);
	_bar_print_slot(bar, slot);
	// CSI <n> G: Cursor horizontal absolute
	printf("\033[27G[%-*.*s]", bar->max_width, bar->max_width, s);
	_restore_cursor_position();
	fflush(stdout);
	wget_thread_mutex_unlock(&bar->mutex);
}

ssize_t wget_bar_vprintf(wget_bar_t *bar, int slot, const char *fmt, va_list args)
{
	char text[bar->max_width + 1];

	ssize_t len = vsnprintf(text, sizeof(text), fmt, args);
	wget_bar_print(bar, slot, text);

	return len;
}

ssize_t wget_bar_printf(wget_bar_t *bar, int slot, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ssize_t len = wget_bar_vprintf(bar, slot, fmt, args);
	va_end(args);

	return len;
}

void wget_bar_screen_resized(void)
{
	winsize_changed = 1;
}

void wget_bar_write_line(wget_bar_t *bar, const char *buf, size_t len)
{
	wget_thread_mutex_lock(&bar->mutex);
	// CSI s:    Save cursor
	// CSI <n>S: Scroll up whole screen
	// CSI <n>A: Cursor up
	// CSI <n>G: Cursor horizontal absolute
	// CSI 0J:   Clear from cursor to end of screen
	// CSI 31m:  Red text color
	printf("\033[s\033[1S\033[%dA\033[1G\033[0J\033[31m", bar->nslots + 1);
	fwrite(buf, 1, len, stdout);
	printf("\033[m"); // reset text color
	_restore_cursor_position();

	_bar_update(bar);
	wget_thread_mutex_unlock(&bar->mutex);
}
/** @}*/
