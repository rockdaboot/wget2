/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * hashmap routines
 *
 * Changelog
 * 06.11.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <wget.h>
#include "private.h"

typedef struct _ENTRY ENTRY;

struct _ENTRY {
	void
		*key,
		*value;
	ENTRY
		*next;
	unsigned int
		hash;
};

struct _wget_hashmap_st {
	wget_hashmap_hash_t
		hash; // hash function
	wget_hashmap_compare_t
		cmp; // compare function
	wget_hashmap_key_destructor_t
		key_destructor; // key destructor function
	wget_hashmap_value_destructor_t
		value_destructor; // value destructor function
	ENTRY
		**entry; // pointer to array of pointers to entries
	int
		max,     // allocated entries
		cur,     // number of entries in use
		off,     // resize strategy: >0: resize = max + off, <0: resize = -off * max
		threshold; // resize when max reaches threshold
	float
		factor;
};

// create hashmap with initial size <max>
// cmp: comparison function for finding
// the hashmap plus shallow content is freed by hashmap_free()

wget_hashmap_t *wget_hashmap_create(int max, wget_hashmap_hash_t hash, wget_hashmap_compare_t cmp)
{
	wget_hashmap_t *h = xmalloc(sizeof(wget_hashmap_t));

	h->entry = xcalloc(max, sizeof(ENTRY *));
	h->max = max;
	h->cur = 0;
	h->off = -2;
	h->hash = hash;
	h->cmp = cmp;
	h->key_destructor = free;
	h->value_destructor = free;
	h->factor = 0.75;
	h->threshold = (int)(max * h->factor);

	return h;
}

// hashmap growth is specified by off:
//   positive values: increase hashmap by <off> entries on each resize
//   negative values: increase hashmap by *<-off>, e.g. -2 doubles the size on each resize
void wget_hashmap_set_growth_policy(wget_hashmap_t *h, int off)
{
	h->off = off;
}

static _GL_INLINE ENTRY * G_GNUC_WGET_NONNULL_ALL hashmap_find_entry(const wget_hashmap_t *h, const char *key, unsigned int hash, int pos)
{
	ENTRY *e;

	// info_printf("find %s:  pos=%d cur=%d, max=%d hash=%08x\n",key,pos,h->cur,h->max,hash);
	for (e = h->entry[pos]; e; e = e->next) {
		if (hash == e->hash && (key == e->key || !h->cmp(key, e->key))) {
			return e;
		}
	}

//	if (h->entry[pos])
//		info_printf("collision on %s\n", key);

	return NULL;
}

static void G_GNUC_WGET_NONNULL_ALL hashmap_rehash(wget_hashmap_t *h, int newmax, int recalc_hash)
{
	ENTRY **new_entry, *entry, *next;
	int it, pos, cur = h->cur;

	if (cur) {
		new_entry = xcalloc(newmax, sizeof(ENTRY *));

		for (it = 0; it < h->max && cur; it++) {
			for (entry = h->entry[it]; entry; entry = next) {
				next = entry->next;

				// now move entry from 'h' to 'new_hashmap'
				if (recalc_hash)
					entry->hash = h->hash(entry->key);
				pos = entry->hash % newmax;
				entry->next = new_entry[pos];
				new_entry[pos] = entry;

				cur--;
			}
		}

		xfree(h->entry);
		h->entry = new_entry;
		h->max = newmax;
		h->threshold = (int)(newmax * h->factor);
	}
}

static _GL_INLINE void G_GNUC_WGET_NONNULL((1,3)) hashmap_new_entry(wget_hashmap_t *h, unsigned int hash, const char *key, const char *value)
{
	ENTRY *entry;
	int pos = hash % h->max;

	entry = xmalloc(sizeof(ENTRY));
	entry->key = (void *)key;
	entry->value = (void *)value;
	entry->hash = hash;
	entry->next = h->entry[pos];
	h->entry[pos] = entry;

	if (++h->cur >= h->threshold) {
		if (h->off > 0) {
			hashmap_rehash(h, h->max + h->off, 0);
		} else if (h->off<-1) {
			hashmap_rehash(h, h->max * -h->off, 0);
		} else {
			// no resizing occurs
		}
	}
}

// return:
//  0: new entry
//  1: existing entry has been replaced
int wget_hashmap_put_noalloc(wget_hashmap_t *h, const void *key, const void *value)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos))) {
		if (entry->key != key && entry->key != value) {
			if (h->key_destructor)
				h->key_destructor(entry->key);
			if (entry->key == entry->value)
				entry->value = NULL;
		}
		if (entry->value != value && entry->value != key) {
			if (h->value_destructor)
				h->value_destructor(entry->value);
		}

		entry->key = (void *) key;
		entry->value = (void *) value;

		return 1;
	}

	// a new entry
	hashmap_new_entry(h, hash, key, value);

	return 0;
}

int wget_hashmap_put(wget_hashmap_t *h, const void *key, size_t keysize, const void *value, size_t valuesize)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos))) {
		if (h->value_destructor)
			h->value_destructor(entry->value);

		entry->value = wget_memdup(value, valuesize);

		return 1;
	}

	// a new entry
	hashmap_new_entry(h, hash, wget_memdup(key, keysize), wget_memdup(value, valuesize));

	return 0;
}

void *wget_hashmap_get(const wget_hashmap_t *h, const void *key)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos)))
		return entry->value; // watch out, value may be NULL

	return NULL;
}

int wget_hashmap_get_null(const wget_hashmap_t *h, const void *key, void **value)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos))) {
		if (value) *value = entry->value;
		return 1;
	}

	return 0;
}

int wget_hashmap_contains(const wget_hashmap_t *h, const void *key)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos)))
		return 1;

	return 0;
}

static int G_GNUC_WGET_NONNULL_ALL hashmap_remove_entry(wget_hashmap_t *h, const char *key, int free_kv)
{
	ENTRY *entry, *next, *prev = NULL;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	for (entry = h->entry[pos]; entry; prev = entry, entry = next) {
		next = entry->next;

		if (hash == entry->hash && (key == entry->key || !h->cmp(key, entry->key))) {
			if (prev)
				prev->next = next;
			else
				h->entry[pos] = next;

			if (free_kv) {
				if (h->key_destructor)
					h->key_destructor(entry->key);
				if (entry->value != entry->key) {
					if (h->value_destructor)
						h->value_destructor(entry->value);
				}
				entry->key = NULL;
				entry->value = NULL;
			}
			xfree(entry);

			h->cur--;
			return 1;
		}
	}

	return 0;
}

int wget_hashmap_remove(wget_hashmap_t *h, const void *key)
{
	if (h)
		return hashmap_remove_entry(h, key, 1);
	else
		return 0;
}

int wget_hashmap_remove_nofree(wget_hashmap_t *h, const void *key)
{
	if (h)
		return hashmap_remove_entry(h, key, 0);
	else
		return 0;
}

void wget_hashmap_free(wget_hashmap_t **h)
{
	if (h && *h) {
		wget_hashmap_clear(*h);
		xfree((*h)->entry);
		xfree(*h);
	}
}

void wget_hashmap_clear(wget_hashmap_t *h)
{
	if (h) {
		ENTRY *entry, *next;
		int it, cur = h->cur;

		for (it = 0; it < h->max && cur; it++) {
			for (entry = h->entry[it]; entry; entry = next) {
				next = entry->next;

				if (h->key_destructor)
					h->key_destructor(entry->key);

				// free value if different from key
				if (entry->value != entry->key && h->value_destructor)
					h->value_destructor(entry->value);

				entry->key = NULL;
				entry->value = NULL;

				xfree(entry);
				cur--;
			}
			h->entry[it] = NULL;
		}
		h->cur = 0;
	}
}

int wget_hashmap_size(const wget_hashmap_t *h)
{
	return h ? h->cur : 0;
}

int wget_hashmap_browse(const wget_hashmap_t *h, wget_hashmap_browse_t browse, void *ctx)
{
	if (h) {
		ENTRY *entry;
		int it, ret, cur = h->cur;

		for (it = 0; it < h->max && cur; it++) {
			for (entry = h->entry[it]; entry; entry = entry->next) {
				if ((ret = browse(ctx, entry->key, entry->value)) != 0)
					return ret;
				cur--;
			}
		}
	}

	return 0;
}

void wget_hashmap_setcmpfunc(wget_hashmap_t *h, wget_hashmap_compare_t cmp)
{
	if (h)
		h->cmp = cmp;
}

void wget_hashmap_sethashfunc(wget_hashmap_t *h, wget_hashmap_hash_t hash)
{
	if (h) {
		h->hash = hash;

		hashmap_rehash(h, h->max, 1);
	}
}

void wget_hashmap_set_key_destructor(wget_hashmap_t *h, wget_hashmap_key_destructor_t destructor)
{
	if (h)
		h->key_destructor = destructor;
}

void wget_hashmap_set_value_destructor(wget_hashmap_t *h, wget_hashmap_value_destructor_t destructor)
{
	if (h)
		h->value_destructor = destructor;
}

void wget_hashmap_setloadfactor(wget_hashmap_t *h, float factor)
{
	if (h) {
		h->factor = factor;
		h->threshold = (int)(h->max * h->factor);
		// rehashing occurs earliest on next put()
	}
}
