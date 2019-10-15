/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2019 Free Software Foundation, Inc.
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

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static WGET_GCC_NONNULL_ALL wget_hashmap_hash_fn hash_iri;
static unsigned int WGET_GCC_NONNULL_ALL hash_iri(const void *key)
{
	const wget_iri *iri = (wget_iri *) key;
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

static WGET_GCC_NONNULL_ALL wget_hashmap_browse_fn blacklist_print_entry;
static int WGET_GCC_NONNULL_ALL blacklist_print_entry(void *ctx, const void *key, void *value)
{
	(void) ctx; (void) value;

	const wget_iri *iri = (wget_iri *) key;
	debug_printf("blacklist %s\n", iri->uri);
	return 0;
}

static wget_hashmap_key_destructor free_key;
static void free_key(void *key)
{
	wget_iri_free((wget_iri **) &key);
}

void blacklist_init(void)
{
	wget_thread_mutex_init(&mutex);

	blacklist = wget_hashmap_create(128, hash_iri, (wget_hashmap_compare_fn *) wget_iri_compare);
	wget_hashmap_set_key_destructor(blacklist, free_key);
}

void blacklist_exit(void)
{
	wget_thread_mutex_destroy(&mutex);
}

/**
 * Only called outside multi-threading, no locking needed
 */
void blacklist_print(void)
{
	wget_hashmap_browse(blacklist, (wget_hashmap_browse_fn *) blacklist_print_entry, NULL);
}

/**
 * \param[in] iri wget_iri to put into the blacklist
 * \return A new blacklist_entry or %NULL if that \p iri was already known
 *
 * The given \p iri will be put into the blacklist.
 */
blacklist_entry *blacklist_add(wget_iri *iri)
{
	blacklist_entry *entryp;

	wget_thread_mutex_lock(mutex);

	if (!wget_hashmap_get(blacklist, iri, &entryp)) {
		entryp = wget_malloc(sizeof(blacklist_entry));
		entryp->iri = iri;

		// info_printf("Add to blacklist: %s\n",iri->uri);

		wget_hashmap_put(blacklist, iri, entryp);
		wget_thread_mutex_unlock(mutex);

		return entryp;
	}

	wget_thread_mutex_unlock(mutex);

	debug_printf("not requesting '%s'. (Already Seen)\n", iri->uri);

	return NULL;
}

/**
 * Only called outside multi-threading, no locking needed
 */
void blacklist_free(void)
{
	wget_hashmap_free(&blacklist);
}
