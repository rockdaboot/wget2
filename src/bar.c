/*
 * Copyright(c) 2014 Tim Ruehsen
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

#include <libmget.h>

#include "options.h"
#include "log.h"
#include "bar.h"

typedef struct {
	double
		ratio;
	int
		max,
		cur,
		cols;
	char
		first;
} slot_t;

typedef struct {
	slot_t
		*slots;
	char
		*filled,
		*spaces;
	int
		nslots,
		max_width;
	char
		allocated;
} mget_bar_t;

mget_bar_t *mget_bar_init(mget_bar_t *bar, int nslots, int max_width)
{
	int allocated = 0, it;

	if (!bar) {
		if (!(bar = calloc(1, sizeof(*bar))))
			return NULL;
		allocated = 1;
	} else
		memset(bar, 0, sizeof(*bar));

	if (bar->nslots < nslots) {
		free(bar->slots);
		bar->nslots = nslots;
		if (!(bar->slots = calloc(nslots, sizeof(slot_t) * nslots)))
			goto cleanup;
	} else {
		memset(bar->slots, 0, sizeof(slot_t) * nslots);
	}

	if (bar->max_width < max_width) {
		free(bar->filled);
		if (!(bar->filled = malloc(max_width)))
			goto cleanup;
		memset(bar->filled, '=', max_width);

		free(bar->spaces);
		if (!(bar->spaces = malloc(max_width)))
			goto cleanup;
		memset(bar->spaces, ' ', max_width);

		bar->max_width = max_width;
	}

	for (it = 0; it < nslots; it++)
		bar->slots[it].first = 1;

	return bar;

cleanup:
	free(bar->spaces);
	free(bar->filled);
	free(bar->slots);
	if (allocated)
		free(bar);

	return NULL;
}

void mget_bar_deinit(mget_bar_t *bar)
{
	if (bar) {
		free(bar->spaces);
		free(bar->filled);
		free(bar->slots);
	}
}

void mget_bar_free(mget_bar_t **bar)
{
	if (bar && *bar) {
		mget_bar_deinit(*bar);
		free(*bar);
	}
}

void mget_bar_update(const mget_bar_t *bar, int slotpos, int max, int cur)
{
	slot_t *slot = &bar->slots[slotpos];
	double ratio = max ? cur / (double) max : 0;
	int cols = bar->max_width * ratio;

	if (cols > bar->max_width)
		cols = bar->max_width;

	slot->max = max;

	if (slot->cols != cols || (int)(slot->ratio * 100) != (int)(ratio * 100) || slot->first) {
		slot->cols = cols;
		slot->ratio = ratio;
		slot->first = 0;

		if (cols <= 0)
			cols = 1;

//		printf("col=%d bar->max_width=%d\n",cols,bar->max_width);
		printf("\033[s\033[%dA\033[1G", bar->nslots - slotpos);
		printf("%3d%% [%.*s>%.*s]", (int)(ratio * 100), cols - 1, bar->filled, bar->max_width - cols, bar->spaces);
		printf("\033[u");
		fflush(stdout);
	}
}

void mget_bar_print(mget_bar_t *bar, int slotpos, const char *s)
{
	printf("\033[s\033[%dA\033[6G[%-*.*s]\033[u", bar->nslots - slotpos, bar->max_width, bar->max_width, s);
	fflush(stdout);
}

ssize_t
	mget_bar_vprintf(mget_bar_t *bar, int slotpos, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(3,0) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_bar_printf(mget_bar_t *bar, int slotpos, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL_ALL;

ssize_t mget_bar_vprintf(mget_bar_t *bar, int slotpos, const char *fmt, va_list args)
{
	char text[bar->max_width + 1];

	ssize_t len = vsnprintf(text, sizeof(text), fmt, args);
	mget_bar_print(bar, slotpos, text);

	return len;
}

ssize_t mget_bar_printf(mget_bar_t *bar, int slotpos, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	return mget_bar_vprintf(bar, slotpos, fmt, args);
	va_end(args);
}

static mget_bar_t
	*bar;
static mget_thread_mutex_t
	mutex = MGET_THREAD_MUTEX_INITIALIZER;

void bar_init(void)
{
	char lf[config.num_threads + 1];

	memset(lf, '\n', config.num_threads + 1);
	fwrite(lf, 1, config.num_threads + 1, stdout);

	bar = mget_bar_init(NULL, config.num_threads + 1, 70);
	
/*
	// set debug logging
	mget_logger_set_func(mget_get_logger(MGET_LOGGER_DEBUG), config.debug ? _write_debug : NULL);

	// set error logging
	mget_logger_set_stream(mget_get_logger(MGET_LOGGER_ERROR), config.quiet ? NULL : stderr);

	// set info logging
	mget_logger_set_stream(mget_get_logger(MGET_LOGGER_INFO), config.verbose && !config.quiet ? stdout : NULL);
*/
}

void bar_deinit(void)
{
	mget_bar_free(&bar);
}

void bar_print(int slotpos, const char *s)
{
	// This function will be called async from threads.
	// Cursor positioning might break without a mutex.
	mget_thread_mutex_lock(&mutex);
	mget_bar_print(bar, slotpos, s);
	mget_thread_mutex_unlock(&mutex);
}

void bar_vprintf(int slotpos, const char *fmt, va_list args)
{
	mget_thread_mutex_lock(&mutex);
	mget_bar_vprintf(bar, slotpos, fmt, args);
	mget_thread_mutex_unlock(&mutex);
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
	mget_thread_mutex_lock(&mutex);
	mget_bar_update(bar, slotpos, max, cur);
	mget_thread_mutex_unlock(&mutex);
}
