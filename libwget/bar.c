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
	unsigned char
		allocated : 1;
};

// Define the parameters for how the progress bar looks
#define _BAR_FILENAME_SIZE	20
#define _BAR_RATIO_SIZE		3
#define _BAR_METER_COST		2
#define _BAR_DOWNBYTES_SIZE	8

// In each of the below elements, 1 extra byte has been added to account for
// the padding between each element.
//
// _BAR_RATIO_SIZE adds another extra byte to account for the %-sign at the end
// of the ratio.
#define _BAR_TOTAL_SIZE (_BAR_FILENAME_SIZE  + 1 + \
                         _BAR_RATIO_SIZE     + 2 + \
                         _BAR_METER_COST     + 1 + \
                         _BAR_DOWNBYTES_SIZE       \
                        )

// These are helper macros to allow us to create a "string literal" dynamically
// at compile time. printf() does not like using a dynamically generated string
// as its format string, so we must work around that and generate it at compile
// time.
//
// _STR_HELPER(x) simply prints out the argument as a string
// _STR(x) uses _STR_HELPER(x) to print out its argument. This level of
// indirection allows us to expand macros. This is used to generate the format
// stirng using sizes for each component as defined above.
#define _STR_HELPER(x) #x
#define _STR(x) _STR_HELPER(x)

// Define the format string for the progress bar. See above for an explanation
// of why we do this in preprocessor macros.
//
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
//
// The final format string after the preprocessor magic should be:
// %-20.20s %3d%% [%.*s>%.*s] %8s
#define _FMT_STR "%-"_STR(_BAR_FILENAME_SIZE)"."_STR(_BAR_FILENAME_SIZE)"s %"_STR(_BAR_RATIO_SIZE)"d%% [%.*s>%.*s] %"_STR(_BAR_DOWNBYTES_SIZE)"s"


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
	int allocated = 0, it;
	max_width = max_width - _BAR_TOTAL_SIZE;

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

/**
 * \param[in] bar Pointer to \p wget_bar_t
 *
 * Free the various progress bar data structures
 */
void wget_bar_deinit(wget_bar_t *bar)
{
	if (bar) {
		free(bar->spaces);
		free(bar->filled);
		free(bar->slots);
	}
}

/**
 * Free the pointer holding the \p *wget_bar_t structure as well
 */
void wget_bar_free(wget_bar_t **bar)
{
	if (bar && *bar) {
		wget_bar_deinit(*bar);
		free(*bar);
	}
}

/**
 * \param[in] bar Pointer to \p wget_bar_t struct
 * \param[in] slotpos Slot position to update
 * \param[in] max Maximum expected filesize
 * \param[in] cur Currently downloaded size
 * \param[in] filename String
 * \return None
 *
 * Update the progress bar display at slot number \p slotpos
 */
void wget_bar_update(const wget_bar_t *bar, int slotpos, off_t max, off_t cur, const char *filename)
{
	_bar_slot_t *slot = &bar->slots[slotpos];
	double ratio = max ? cur / (double) max : 0;
	int cols = bar->max_width * ratio;

	if (cols > bar->max_width)
		cols = bar->max_width;

	slot->max = max;

	if (slot->cols != cols || (slot->ratio * 100) != (ratio * 100) || slot->first) {
		slot->cols = cols;
		slot->ratio = ratio;
		slot->first = 0;

		if (cols <= 0)
			cols = 1;

//		printf("col=%d bar->max_width=%d\n",cols,bar->max_width);
		printf("\033[s\033[%dA\033[1G", bar->nslots - slotpos);
		printf(_FMT_STR, filename, (int) (ratio * 100), cols - 1, bar->filled, bar->max_width - cols, bar->spaces, wget_human_readable(cur, 1000, 2));
		printf("\033[u");
		fflush(stdout);
	}
}


void wget_bar_print(wget_bar_t *bar, int slotpos, const char *s)
{
	printf("\033[s\033[%dA\033[6G[%-*.*s]\033[u", bar->nslots - slotpos, bar->max_width, bar->max_width, s);
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

#undef _STR
#undef _STR_HELPER
#undef _FMT_STR
