/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * hashmap routines
 *
 * Changelog
 * 06.11.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libmget.h>
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

struct _MGET_HASHMAP {
	unsigned int
		(*hash)(const void *); // hash function
	int
		(*cmp)(const void *, const void *); // compare function
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
// hashmap growth is specified by off:
//   positive values: increase hashmap by <off> entries on each resize
//   negative values: increase hashmap by *<-off>, e.g. -2 doubles the size on each resize
// cmp: comparison function for finding
// the hashmap plus shallow content is freed by hashmap_free()

MGET_HASHMAP *mget_hashmap_create(int max, int off, unsigned int (*hash)(const void *), int (*cmp)(const void *, const void *))
{
	MGET_HASHMAP *h = xmalloc(sizeof(MGET_HASHMAP));

	h->entry = xcalloc(max, sizeof(ENTRY *));
	h->max = max;
	h->cur = 0;
	h->off = off;
	h->hash = hash;
	h->cmp = cmp;
	h->factor = 0.75;
	h->threshold = (int)(max * h->factor);

	return h;
}

static inline ENTRY * G_GNUC_MGET_NONNULL_ALL hashmap_find_entry(const MGET_HASHMAP *h, const char *key, unsigned int hash, int pos)
{
	ENTRY *e;

	// info_printf("find %s:  pos=%d cur=%d, max=%d hash=%08x\n",key,pos,h->cur,h->max,hash);
	for (e = h->entry[pos]; e; e = e->next) {
		if (hash == e->hash && (key == e->key || !h->cmp(key, e->key))) {
			return e;
		}
	}

	// if (h->entry[pos])
	// 	info_printf("collision on %s\n", key);

	return NULL;
}

static inline void G_GNUC_MGET_NONNULL_ALL hashmap_free_entry(ENTRY **e)
{
	if (*e) {
		xfree((*e)->value);
		xfree((*e)->key);
		xfree(*e);
	}
}

static void G_GNUC_MGET_NONNULL_ALL hashmap_rehash(MGET_HASHMAP *h, int newmax, int recalc_hash)
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

static inline void G_GNUC_MGET_NONNULL((1,3)) hashmap_new_entry(MGET_HASHMAP *h, unsigned int hash, const char *key, const char *value)
{
	ENTRY *entry;
	int pos = hash % h->max;

	entry = malloc(sizeof(ENTRY));
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

int mget_hashmap_put_noalloc(MGET_HASHMAP *h, const void *key, const void *value)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos))) {
		if (entry->key == entry->value) {
			if (key != value && entry->value != value)
				entry->value = (void *)value;
		} else if (entry->value != value) {
			xfree(entry->value);
			entry->value = (void *)value;
		}

		if (entry->key != key)
			xfree(key);

		return 1;
	}

	// a new entry
	hashmap_new_entry(h, hash, key, value);

	return 0;
}

int mget_hashmap_put(MGET_HASHMAP *h, const void *key, size_t keysize, const void *value, size_t valuesize)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos))) {
		if (entry->key != entry->value)
			xfree(entry->value);

		entry->value = value ? mget_memdup(value, valuesize) : NULL;

		return 1;
	}

	// a new entry
	hashmap_new_entry(h, hash, mget_memdup(key, keysize), value ? mget_memdup(value, valuesize) : NULL);
	
	return 0;
//	return hashmap_put_noalloc(h, xmemdup(key, keysize), value ? xmemdup(value, valuesize) : NULL);
}

int mget_hashmap_put_ident(MGET_HASHMAP *h, const void *key, size_t keysize)
{
	ENTRY *entry;
	void *keydup;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos))) {
		if (entry->key != entry->value) {
			xfree(entry->value);
			entry->value = entry->key;
		}

		return 1;
	}

	// a new entry
	keydup = mget_memdup(key, keysize);
	hashmap_new_entry(h, hash, keydup, keydup);

	return 0;

	// if the key is as well the value (e.g. for blacklists)
//	void *keydup = xmemdup(key, keysize);
//	return hashmap_put_noalloc(h, keydup, keydup);
}

int mget_hashmap_put_ident_noalloc(MGET_HASHMAP *h, const void *key)
{
	// if the key is as well the value (e.g. for blacklists)
	return mget_hashmap_put_noalloc(h, key, key);
}

void *mget_hashmap_get(const MGET_HASHMAP *h, const void *key)
{
	ENTRY *entry;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	if ((entry = hashmap_find_entry(h, key, hash, pos)))
		return entry->value;

	return NULL;
}

static void G_GNUC_MGET_NONNULL_ALL hashmap_remove_entry(MGET_HASHMAP *h, const char *key, int free_kv)
{
	ENTRY *e, *next, *prev = NULL;
	unsigned int hash = h->hash(key);
	int pos = hash % h->max;

	for (e = h->entry[pos]; e; prev = e, e = next) {
		next = e->next;

		if (hash == e->hash && (key == e->key || !h->cmp(key, e->key))) {
			if (prev)
				prev->next = next;
			else
				h->entry[pos] = next;

			if (free_kv) {
				if (e->key == e->value) {
					// special case: key/value identity
					xfree(e->key);
					e->value = NULL;
				} else {
					xfree(e->key);
					xfree(e->value);
				}
			}
			xfree(e);

			h->cur--;
			return;
		}
	}
}

void mget_hashmap_remove(MGET_HASHMAP *h, const void *key)
{
	if (h)
		hashmap_remove_entry(h, key, 1);
}

void mget_hashmap_remove_nofree(MGET_HASHMAP *h, const void *key)
{
	if (h)
		hashmap_remove_entry(h, key, 0);
}

void mget_hashmap_free(MGET_HASHMAP **h)
{
	if (h && *h) {
		mget_hashmap_clear(*h);
		xfree((*h)->entry);
		xfree(*h);
	}
}

void mget_hashmap_clear(MGET_HASHMAP *h)
{
	if (h) {
		ENTRY *entry, *next;
		int it, cur = h->cur;

		for (it = 0; it < h->max && cur; it++) {
			for (entry = h->entry[it]; entry; entry = next) {
				next = entry->next;
				if (entry->key == entry->value) {
					// special case: key/value identity
					xfree(entry->value);
					entry->key = NULL;
				} else {
					xfree(entry->value);
					xfree(entry->key);
				}
				xfree(entry);
				cur--;
			}
			h->entry[it] = NULL;
		}
		h->cur = 0;
	}
}

int mget_hashmap_size(const MGET_HASHMAP *h)
{
	return h ? h->cur : 0;
}

int mget_hashmap_browse(const MGET_HASHMAP *h, int (*browse)(const void *key, const void *value))
{
	if (h) {
		ENTRY *entry;
		int it, ret, cur = h->cur;

		for (it = 0; it < h->max && cur; it++) {
			for (entry = h->entry[it]; entry; entry = entry->next) {
				if ((ret = browse(entry->key, entry->value)) != 0)
					return ret;
				cur--;
			}
		}
	}

	return 0;
}

void mget_hashmap_setcmpfunc(MGET_HASHMAP *h, int (*cmp)(const void *key1, const void *key2))
{
	if (h)
		h->cmp = cmp;
}

void mget_hashmap_sethashfunc(MGET_HASHMAP *h, unsigned int (*hash)(const void *key))
{
	if (h) {
		h->hash = hash;

		hashmap_rehash(h, h->max, 1);
	}
}

void mget_hashmap_setloadfactor(MGET_HASHMAP *h, float factor)
{
	if (h) {
		h->factor = factor;
		h->threshold = (int)(h->max * h->factor);
		// rehashing occurs earliest on next put()
	}
}
