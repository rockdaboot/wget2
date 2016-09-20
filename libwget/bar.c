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

#include <libwget.h>
#include "private.h"

/**
 * \file
 * \brief Progress Bar Routines
 * \defgroup libwget-progress Progress Display Functions
 * @{
 *
 * Methods for creating and printing a progress bar display.
 */

typedef struct {
	double
		ratio;
	int
		max,
		cur,
		cols;
	unsigned char
		first : 1;
	wget_bar_ctx
		*ctx,
		last_ctx;
	char
		human_size[16];
} _bar_slot_t;

struct _wget_bar_st {
	_bar_slot_t
		*slots;
	char
		*filled,
		*spaces;
	int
		nslots,
		max_width;
};

// Forward declarations for static methods
static inline G_GNUC_WGET_ALWAYS_INLINE void
	_return_cursor_position(void);
static inline G_GNUC_WGET_ALWAYS_INLINE void
	_bar_print_slot(const wget_bar_t *bar, int slotpos);
static inline G_GNUC_WGET_ALWAYS_INLINE void
	_bar_print_final(const wget_bar_t *bar, int slotpos);

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

static wget_thread_mutex_t
	stdout_mutex;

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
	int allocated = 0;

	// While the API defines max_width to be the total size of the progress
	// bar, the code assume sit to be the size of the [===> ] actual bar
	// drawing. So compute that early enough.
	max_width -= _BAR_DECOR_COST;

	if (!bar) {
		if (!(bar = xcalloc(1, sizeof(*bar))))
			return NULL;
		allocated = 1;
	} else
		memset(bar, 0, sizeof(*bar));

	if (bar->nslots < nslots) {
		xfree(bar->slots);
		bar->nslots = nslots;
		if (!(bar->slots = xcalloc(nslots, sizeof(_bar_slot_t) * nslots)))
			goto cleanup;
	} else {
		memset(bar->slots, 0, sizeof(_bar_slot_t) * nslots);
	}

	if (bar->max_width < max_width) {
		xfree(bar->filled);
		if (!(bar->filled = xmalloc(max_width)))
			goto cleanup;
		memset(bar->filled, '=', max_width);

		xfree(bar->spaces);
		if (!(bar->spaces = xmalloc(max_width)))
			goto cleanup;
		memset(bar->spaces, ' ', max_width);

		bar->max_width = max_width;
	}

	for (int it = 0; it < nslots; it++) {
		bar->slots[it].first = 1;
	}

	wget_thread_mutex_init(&stdout_mutex);

	return bar;

cleanup:
	if (allocated)
		wget_bar_free(&bar);
	else
		wget_bar_deinit(bar);

	return NULL;
}

void wget_bar_register(wget_bar_t *bar, wget_bar_ctx *ctx)
{
	bar->slots[ctx->slotpos].ctx = ctx;
	/* error_printf("Context registered for slotpos: %ld %p %p %p\n", ctx->slotpos, bar, &bar->slots[ctx->slotpos], bar->slots[ctx->slotpos].ctx); */
}

void wget_bar_deregister(wget_bar_t *bar, wget_bar_ctx *ctx)
{
	wget_bar_ctx *last_ctx;
	wget_thread_mutex_lock(&ctx->mutex);
	bar->slots[ctx->slotpos].ctx = NULL;

	// Copy all the members of ctx to last_ctx
	{
		last_ctx = &bar->slots[ctx->slotpos].last_ctx;
		// If last_ctx has been used before, then free the memory allocated for
		// its filename member.
		xfree(last_ctx->filename);
		last_ctx->slotpos = ctx->slotpos;
		last_ctx->expected_size = ctx->expected_size;
		last_ctx->raw_downloaded = ctx->raw_downloaded;
		// Filename will be overwritten when a new file is downloaded by the same
		// downloader thread. Hence, we make a copy here.
		last_ctx->filename = strdup(ctx->filename);
	}

	_bar_print_final(bar, ctx->slotpos);
	wget_thread_mutex_unlock(&ctx->mutex);
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_return_cursor_position(void) {
	printf("\033[u");
}

static inline G_GNUC_WGET_ALWAYS_INLINE void
_bar_print_slot(const wget_bar_t *bar, int slotpos) {
	printf("\033[s\033[%dA\033[1G", bar->nslots - slotpos);
}

void wget_bar_update(const wget_bar_t *bar, int slotpos) {

	wget_bar_ctx *ctx;
	off_t
		max,
		cur;
	double ratio;
	int cols;
	char *human_readable_bytes;

	_bar_slot_t *slot = &bar->slots[slotpos];
	// We only print a progress bar for the slot if a context has been
	// registered for it
	if ((ctx = slot->ctx)) {

		wget_thread_mutex_lock(&ctx->mutex);
		max = ctx->expected_size;
		cur = ctx->raw_downloaded;

		ratio = max ? cur / (double) max : 0;
		cols = bar->max_width * ratio;

		if (cols > bar->max_width)
			cols = bar->max_width;

		slot->max = max;

		if (slot->cols != cols || (slot->ratio * 100) != (ratio * 100) || slot->first) {
			slot->cols = cols;
			slot->ratio = ratio;
			slot->first = 0;

			if (cols <= 0)
				cols = 1;

			human_readable_bytes = wget_human_readable(slot->human_size, sizeof(slot->human_size), cur);

			wget_thread_mutex_lock(&stdout_mutex);
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

			printf("%-*.*s %*d%% [%.*s>%.*s] %*s",
					_BAR_FILENAME_SIZE, _BAR_FILENAME_SIZE, ctx->filename,
					_BAR_RATIO_SIZE, (int) (ratio * 100),
					cols - 1, bar->filled,
					bar->max_width - cols, bar->spaces,
					_BAR_DOWNBYTES_SIZE, human_readable_bytes);

			_return_cursor_position();
			fflush(stdout);
			wget_thread_mutex_unlock(&stdout_mutex);
		}
		wget_thread_mutex_unlock(&ctx->mutex);
	} else {
		_bar_print_final(bar, slotpos);
	}
}

static void _bar_print_final(const wget_bar_t *bar, int slotpos) {

	off_t
		max,
		cur;
	double ratio;
	int cols;
	_bar_slot_t *slot = &bar->slots[slotpos];
	wget_bar_ctx *ctx = &slot->last_ctx;
	char *human_readable_bytes;

	max = ctx->expected_size;
	cur = ctx->raw_downloaded;

	ratio = max ? cur / (double) max : 0;
	cols = bar->max_width * ratio;

	slot->max = max;
	slot->cols = cols;
	slot->ratio = ratio;
	slot->first = 0;

	if (cols <= 0)
		cols = 1;
	else if (cols > bar->max_width)
		cols = bar->max_width;

	human_readable_bytes = wget_human_readable(slot->human_size, sizeof(slot->human_size), cur);

	wget_thread_mutex_lock(&stdout_mutex);
	_bar_print_slot(bar, slotpos);

	printf("%-*.*s %*d%% [%.*s>%.*s] %*s",
			_BAR_FILENAME_SIZE, _BAR_FILENAME_SIZE, ctx->filename,
			_BAR_RATIO_SIZE, (int) (ratio * 100),
			cols - 1, bar->filled,
			bar->max_width - cols, bar->spaces,
			_BAR_DOWNBYTES_SIZE, human_readable_bytes);

	_return_cursor_position();
	fflush(stdout);
	wget_thread_mutex_unlock(&stdout_mutex);
}

/**
 * \param[in] bar Pointer to \p wget_bar_t
 *
 * Free the various progress bar data structures
 */
void wget_bar_deinit(wget_bar_t *bar)
{
	if (bar) {
		for (int i = 0; i < bar->nslots; i++) {
			xfree(bar->slots[i].last_ctx.filename);
		}
		xfree(bar->spaces);
		xfree(bar->filled);
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
	wget_thread_mutex_lock(&stdout_mutex);
	_bar_print_slot(bar, slotpos);
	printf("\033[27G[%-*.*s]", bar->max_width, bar->max_width, s);
	_return_cursor_position();
	fflush(stdout);
	wget_thread_mutex_unlock(&stdout_mutex);
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
