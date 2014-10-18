/*
 * Copyright(c) 2014 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
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

#include <libmget.h>
#include "private.h"

typedef struct {
	double
		ratio;
	int
		max,
		cur,
		cols;
	char
		first;
} _bar_slot_t;

struct _mget_bar_st {
	_bar_slot_t
		*slots;
	char
		*filled,
		*spaces;
	int
		nslots,
		max_width;
	char
		allocated;
};

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
		if (!(bar->slots = calloc(nslots, sizeof(_bar_slot_t) * nslots)))
			goto cleanup;
	} else {
		memset(bar->slots, 0, sizeof(_bar_slot_t) * nslots);
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
	_bar_slot_t *slot = &bar->slots[slotpos];
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
