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

//static VECTOR
static MGET_HASHMAP
	*blacklist;

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
static unsigned int hash_iri(const MGET_IRI *iri)
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
	mget_hashmap_browse(blacklist, (int(*)(const void *, const void *))_blacklist_print);
}

MGET_IRI *blacklist_add(MGET_IRI *iri)
{
	MGET_IRI *existing_iri;

	if (!iri)
		return NULL;

	if (!blacklist)
		blacklist = mget_hashmap_create(128, -2, (unsigned int(*)(const void *))hash_iri, (int(*)(const void *, const void *))mget_iri_compare);

	if ((existing_iri = mget_hashmap_get(blacklist, iri))) {
		// info_printf("Already in blacklist: %s\n",iri->uri);
		mget_iri_free(&iri);
		return existing_iri;
	}

	if (mget_iri_supported(iri)) {
		// info_printf("Add to blacklist: %s\n",iri->uri);
		mget_hashmap_put_ident_noalloc(blacklist, iri);
		return iri;
	}

	mget_iri_free(&iri);

	return NULL;
}

/*
int in_blacklist(IRI *iri)
{
	int it;

	for (it = 0; iri_schemes[it]; it++) {
		if (iri_schemes[it] == iri->scheme)
			return vec_find(blacklist, iri) >= 0;
	}

	return 1; // unknown scheme becomes blacked out
}

IRI *blacklist_add(IRI *iri)
{
	if (!iri)
		return NULL;

	if (!blacklist)
		blacklist = vec_create(128, -2, (int(*)(const void *, const void *))iri_compare);

	if (!in_blacklist(iri)) {
		//	info_printf("Add to blacklist: %s\n",uri);
		vec_insert_sorted_noalloc(blacklist, iri);
		return iri;
	}

	iri_free(&iri);

	return NULL;
}

void blacklist_print(void)
{
	int n;

	for (n = 0; n < vec_size(blacklist); n++) {
		IRI *iri = vec_get(blacklist, n);
		info_printf("blacklist[%d] %s\n", n, iri->uri);
	}
}

void blacklist_free(void)
{
	vec_free(&blacklist);
}
*/

static int _free_entry(MGET_IRI *iri)
{
	mget_iri_free_content(iri);
	return 0;
}

void blacklist_free(void)
{
	mget_hashmap_browse(blacklist, (int(*)(const void *, const void *))_free_entry);
	mget_hashmap_free(&blacklist);
}
