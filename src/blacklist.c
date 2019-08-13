/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * IRI blacklist routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_blacklist.h"

static wget_hashmap
	*blacklist;

static wget_thread_mutex
	mutex;

void blacklist_init(void)
{
	wget_thread_mutex_init(&mutex);
}

void blacklist_exit(void)
{
	wget_thread_mutex_destroy(&mutex);
}

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int WGET_GCC_NONNULL_ALL hash_iri(const wget_iri *iri)
{
	unsigned int h = iri->port; // use port as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	h = h * 101 + iri->scheme;

	for (p = (unsigned char *)iri->host; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->path; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->query; p && *p; p++)
		h = h * 101 + *p;

	return h;
}

static int WGET_GCC_NONNULL_ALL blacklist_print_entry(WGET_GCC_UNUSED void *ctx, const wget_iri *iri)
{
	debug_printf("blacklist %s\n", iri->uri);
	return 0;
}

void blacklist_print(void)
{
	wget_thread_mutex_lock(mutex);
	wget_hashmap_browse(blacklist, (wget_hashmap_browse_fn *) blacklist_print_entry, NULL);
	wget_thread_mutex_unlock(mutex);
}

int blacklist_size(void)
{
	return wget_hashmap_size(blacklist);
}

static void _free_entry(wget_iri *iri)
{
	wget_iri_free(&iri);
}

wget_iri *blacklist_add(wget_iri *iri)
{
	if (!iri)
		return NULL;

	if (wget_iri_supported(iri)) {
		wget_thread_mutex_lock(mutex);

		if (!blacklist) {
			blacklist = wget_hashmap_create(128, (wget_hashmap_hash_fn *) hash_iri, (wget_hashmap_compare_fn *) wget_iri_compare);
			wget_hashmap_set_key_destructor(blacklist, (wget_hashmap_key_destructor *) _free_entry);
		}

		if (!wget_hashmap_contains(blacklist, iri)) {
			// info_printf("Add to blacklist: %s\n",iri->uri);
			wget_hashmap_put(blacklist, iri, NULL); // use hashmap as a hashset (without value)
			wget_thread_mutex_unlock(mutex);
			return iri;
		} else {
			debug_printf("not requesting '%s'. (Already Seen)\n", iri->uri);
		}

		wget_thread_mutex_unlock(mutex);
	}

	wget_iri_free(&iri);

	return NULL;
}

void blacklist_free(void)
{
	wget_thread_mutex_lock(mutex);
	wget_hashmap_free(&blacklist);
	wget_thread_mutex_unlock(mutex);
}
