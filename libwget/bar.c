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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Progress bar routines
 *
 * Changelog
 * 18.10.2014  Tim Ruehsen  created from src/bar.c
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

#include <wget.h>
#include "utils.h"
#include "private.h"

/**
 * \file
 * \brief Progress Bar Routines
 * \defgroup libwget-progress Progress Display Functions
 * @{
 *
 * Methods for creating and printing a progress bar display.
 */


// We use enums to define the progress bar paramters because they are the
// closest thing we have to defining true constants in C without using
// preprocessor macros. The advantage of enums is that they will create a
// symbol in the symbol table making debugging a whole lot easier.

// Define the parameters for how the progress bar looks
enum {
	_BAR_FILENAME_SIZE  = 20,
	_BAR_RATIO_SIZE     =  3,
	_BAR_METER_COST     =  2,
	_BAR_DOWNBYTES_SIZE =  8,
};

// Define the cost (in number of columns) of the progress bar decorations. This
// includes all the elements that are not the progress indicator itself.
enum {
	_BAR_DECOR_COST =
		_BAR_FILENAME_SIZE  + 1 + \
		_BAR_RATIO_SIZE     + 2 + \
		_BAR_METER_COST     + 1 + \
		_BAR_DOWNBYTES_SIZE
};

enum _bar_slot_status_t {
	EMPTY, REGISTERED, DOWNLOADING, COMPLETE
};

typedef struct {
	wget_bar_ctx
		*ctx;
	char
		*progress,
		*filename,
		human_size[_BAR_DOWNBYTES_SIZE];
	int
		tick;
	size_t
		file_size,
		bytes_downloaded;
	enum _bar_slot_status_t
		status;
} _bar_slot_t;

struct _wget_bar_st {
	_bar_slot_t
		*slots;
	char
		*unknown_size,
		*known_size,
		*spaces;
	int
		nslots,
		max_slots,
		max_width;
};

// Forward declarations for static methods
static inline G_GNUC_WGET_ALWAYS_INLINE void
	_return_cursor_position(void);
static inline G_GNUC_WGET_ALWAYS_INLINE void
	_bar_print_slot(const wget_bar_t *bar, int slotpos);
static inline G_GNUC_WGET_ALWAYS_INLINE void
	_bar_print_final(const wget_bar_t *bar, int slotpos);
static void
	_bar_update_slot(const wget_bar_t *bar, int slotpos);

/**
 * \param[in] bar Pointer to a \p wget_bar_t object
 * \param[in] nslots Number of progress bars
 * \param[in] max_width Maximum width of the progress bars
 * \return Pointer to a \p wget_bar_t object
 *
 * Initialize a new progress bar instance for Wget. If \p bar is a NULL
 * pointer, it will be allocated on the heap and a pointer to the newly
 * allocated memory will be returned.
 *
 * \p nslots is the number of screen lines to reserve for printing the progress
 * bars. This may be any number, but you generally want atleast as many slots
 * as there are downloader threads.
 *
 * \p max_width is the maximum number of screen columns that the progress bar
 * may occupy.
 */
wget_bar_t *wget_bar_init(wget_bar_t *bar, int nslots, int max_width)
{
	// While the API defines max_width to be the total size of the progress
	// bar, the code assume sit to be the size of the [===> ] actual bar
	// drawing. So compute that early enough.
	max_width -= _BAR_DECOR_COST;

	if (nslots < 1 || max_width < 1)
		return NULL;

	if (!bar) {
		bar = xcalloc(1, sizeof(*bar));
	} else
		memset(bar, 0, sizeof(*bar));

	if (bar->max_slots < nslots) {
		xfree(bar->slots);
		bar->max_slots = nslots;
		bar->slots = xcalloc(nslots, sizeof(_bar_slot_t) * nslots);
	} else {
		memset(bar->slots, 0, sizeof(_bar_slot_t) * nslots);
	}

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

		for (int i = 0; i < bar->max_slots; i++) {
			xfree(bar->slots[i].progress);
			bar->slots[i].progress = xmalloc(max_width + 1);
			bar->slots[i].status = EMPTY;
		}

		bar->max_width = max_width;
	}


	return bar;
}

void wget_bar_set_slots(wget_bar_t *bar, int nslots)
{
	char lf[nslots];
	memset(lf, '\n', sizeof(lf));

	if (nslots <= bar->nslots)
		return;

	/* _bar_print_slot(bar, 0); */
	fwrite(lf, 1, nslots - bar->nslots, stdout);
	bar->nslots = nslots;
	wget_bar_update(bar);
}

void wget_bar_slot_begin(wget_bar_t *bar, wget_bar_ctx *ctx, const char *filename, ssize_t file_size)
{
	int slotpos = ctx->_slotpos;
	bar->slots[slotpos].filename = wget_strdup(filename);
	bar->slots[slotpos].file_size = file_size;
	bar->slots[slotpos].status = DOWNLOADING;
}

void wget_bar_slot_register(wget_bar_t *bar, wget_bar_ctx *ctx, int slotpos)
{
	ctx->_slotpos = slotpos;
	xfree(bar->slots[slotpos].filename);
	bar->slots[slotpos].ctx = ctx;
	bar->slots[slotpos].tick = 0;
	bar->slots[slotpos].status = REGISTERED;
	/* error_printf("Context registered for slotpos: %d %p %p %p\n", slotpos, bar, &bar->slots[slotpos], bar->slots[slotpos].ctx); */
}

void wget_bar_slot_deregister(wget_bar_t *bar, wget_bar_ctx *ctx)
{
	bar->slots[ctx->_slotpos].ctx = NULL;
	wget_thread_mutex_lock(&ctx->mutex);
	bar->slots[ctx->_slotpos].bytes_downloaded = ctx->raw_downloaded;
	wget_thread_mutex_unlock(&ctx->mutex);
	bar->slots[ctx->_slotpos].status = COMPLETE;
	_bar_update_slot(bar, ctx->_slotpos);
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_return_cursor_position(void)
{
	printf("\033[u");
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_bar_print_slot(const wget_bar_t *bar, int slotpos)
{
	printf("\033[s\033[%dA\033[1G", bar->nslots - slotpos);
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_bar_set_progress(const wget_bar_t *bar, int slotpos)
{
	_bar_slot_t *slot = &bar->slots[slotpos];

	if (slot->file_size > 0) {
		size_t bytes = (slot->status == DOWNLOADING) ? slot->ctx->raw_downloaded : slot->bytes_downloaded;
		int cols = (bytes / (double) slot->file_size) * bar->max_width;
		if (cols > bar->max_width)
			cols = bar->max_width;
		else if (cols <= 0)
			cols = 1;

		snprintf(slot->progress, bar->max_width + 1, "%.*s>%.*s",
				cols - 1, bar->known_size,
				bar->max_width - cols, bar->spaces);
	} else {
		int ind = slot->tick % ((bar->max_width * 2) - 6);
		int pre_space;

		if (ind <= bar->max_width - 3)
			pre_space = ind;
		else
			pre_space = bar->max_width - (ind - bar->max_width + 5);

		snprintf(slot->progress, bar->max_width + 1, "%.*s<=>%.*s",
				pre_space, bar->spaces,
				bar->max_width - pre_space - 3, bar->spaces);
	}
}

void wget_bar_update(const wget_bar_t *bar)
{
	for (int i = 0; i < bar->nslots; i++)
		_bar_update_slot(bar, i);
}

static void
_bar_update_slot(const wget_bar_t *bar, int slotpos)
{
	off_t
		max,
		cur;
	int ratio;
	char *human_readable_bytes;
	_bar_slot_t *slot = &bar->slots[slotpos];
	wget_bar_ctx *ctx = slot->ctx;

	// We only print a progress bar for the slot if a context has been
	// registered for it
	if (slot->status == DOWNLOADING) {
		wget_thread_mutex_lock(&ctx->mutex);
		max = slot->file_size;
		cur = ctx->raw_downloaded;

		ratio = max ? (100 * cur) / max : 0;

		human_readable_bytes = wget_human_readable(slot->human_size, sizeof(slot->human_size), cur);
		_bar_set_progress(bar, slotpos);

		_bar_print_slot(bar, slotpos);

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
				_BAR_FILENAME_SIZE, _BAR_FILENAME_SIZE, slot->filename,
				_BAR_RATIO_SIZE, ratio,
				slot->progress,
				_BAR_DOWNBYTES_SIZE, human_readable_bytes);

		_return_cursor_position();
		fflush(stdout);
		wget_thread_mutex_unlock(&ctx->mutex);
		slot->tick++;
	} else if (slot->status == COMPLETE) {
		_bar_print_final(bar, slotpos);
	}
}

static void _bar_print_final(const wget_bar_t *bar, int slotpos) {

	off_t
		max,
		cur;
	int ratio;
	_bar_slot_t *slot = &bar->slots[slotpos];
	char *human_readable_bytes;

	max = slot->file_size;
	cur = slot->bytes_downloaded;

	ratio = max ? (100 * cur) / max : 0;

	human_readable_bytes = wget_human_readable(slot->human_size, sizeof(slot->human_size), cur);
	_bar_set_progress(bar, slotpos);

	_bar_print_slot(bar, slotpos);

	printf("%-*.*s %*d%% [%s] %*s",
			_BAR_FILENAME_SIZE, _BAR_FILENAME_SIZE, slot->filename,
			_BAR_RATIO_SIZE, ratio,
			slot->progress,
			_BAR_DOWNBYTES_SIZE, human_readable_bytes);

	_return_cursor_position();
	fflush(stdout);
}

/**
 * \param[in] bar Pointer to \p wget_bar_t
 *
 * Free the various progress bar data structures
 */
void wget_bar_deinit(wget_bar_t *bar)
{
	if (bar) {
		for (int i = 0; i < bar->max_slots; i++) {
			xfree(bar->slots[i].progress);
			xfree(bar->slots[i].filename);
		}
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

void wget_bar_print(wget_bar_t *bar, int slotpos, const char *s)
{
	_bar_print_slot(bar, slotpos);
	printf("\033[27G[%-*.*s]", bar->max_width, bar->max_width, s);
	_return_cursor_position();
	fflush(stdout);
}

ssize_t wget_bar_vprintf(wget_bar_t *bar, size_t slotpos, const char *fmt, va_list args)
{
	char text[bar->max_width + 1];

	ssize_t len = vsnprintf(text, sizeof(text), fmt, args);
	wget_bar_print(bar, slotpos, text);

	return len;
}

ssize_t wget_bar_printf(wget_bar_t *bar, size_t slotpos, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ssize_t len = wget_bar_vprintf(bar, slotpos, fmt, args);
	va_end(args);

	return len;
}
