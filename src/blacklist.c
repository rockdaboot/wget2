/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * IRI blacklist routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <libmget.h>

#include "log.h"
#include "blacklist.h"

static MGET_HASHMAP
	*blacklist;

static mget_thread_mutex_t
	mutex = MGET_THREAD_MUTEX_INITIALIZER;

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
static unsigned int G_GNUC_MGET_NONNULL_ALL hash_iri(const MGET_IRI *iri)
{
	unsigned int h = 0; // use 0 as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)iri->scheme; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->port; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->host; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->path; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->query; p && *p; p++)
		h = h * 101 + *p;

	return h;
}

static int G_GNUC_MGET_NONNULL_ALL _blacklist_print(const MGET_IRI *iri)
{
	info_printf("blacklist %s\n", iri->uri);
	return 0;
}

void blacklist_print(void)
{
	mget_thread_mutex_lock(&mutex);
	mget_hashmap_browse(blacklist, (int(*)(const void *, const void *))_blacklist_print);
	mget_thread_mutex_unlock(&mutex);
}

static void _free_entry(MGET_IRI *iri, G_GNUC_MGET_UNUSED void *value)
{
	mget_iri_free_content(iri);
}

MGET_IRI *blacklist_add(MGET_IRI *iri)
{
	if (!iri)
		return NULL;

	if (mget_iri_supported(iri)) {
		mget_thread_mutex_lock(&mutex);

		if (!blacklist) {
			blacklist = mget_hashmap_create(128, -2, (unsigned int(*)(const void *))hash_iri, (int(*)(const void *, const void *))mget_iri_compare);
			mget_hashmap_set_destructor(blacklist, (void(*)(void *, void *))_free_entry);
		}

		if (!mget_hashmap_contains(blacklist, iri)) {
			// info_printf("Add to blacklist: %s\n",iri->uri);
			mget_hashmap_put_noalloc(blacklist, iri, NULL); // use hashmap as a hashset (without value)
			mget_thread_mutex_unlock(&mutex);
			return iri;
		}

		mget_thread_mutex_unlock(&mutex);
	}

	mget_iri_free(&iri);

	return NULL;
}

void blacklist_free(void)
{
	mget_thread_mutex_lock(&mutex);
	mget_hashmap_free(&blacklist);
	mget_thread_mutex_unlock(&mutex);
}
