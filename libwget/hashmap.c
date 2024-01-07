/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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

typedef struct entry_st entry_t;

struct entry_st {
	void
		*key,
		*value;
	entry_t
		*next;
	unsigned int
		hash;
};

struct wget_hashmap_st {
	wget_hashmap_hash_fn
		*hash; // hash function
	wget_hashmap_compare_fn
		*cmp; // compare function
	wget_hashmap_key_destructor
		*key_destructor; // key destructor function
	wget_hashmap_value_destructor
		*value_destructor; // value destructor function
	entry_t
		**entry;   // pointer to array of pointers to entries
	int
		max,       // allocated entries
		cur,       // number of entries in use
		threshold; // resize when max reaches threshold
	float
		resize_factor, // resize strategy: >0: resize = off * max, <0: resize = max + (-off)
		load_factor;
};

struct wget_hashmap_iterator_st {
	struct wget_hashmap_st
		*h;
	entry_t
		*entry;
	int
		pos;
};

/**
 * \file
 * \brief Hashmap functions
 * \defgroup libwget-hashmap Hashmap functions
 * @{
 *
 * Hashmaps are key/value stores that perform at O(1) for insertion, searching and removing.
 */

/**
 * \param[in] h Hashmap
 * \return New iterator instance for \p h
 *
 * Creates a hashmap iterator for \p h.
 */
wget_hashmap_iterator *wget_hashmap_iterator_alloc(wget_hashmap *h)
{
	struct wget_hashmap_iterator_st *iter = wget_calloc(1, sizeof(struct wget_hashmap_iterator_st));

	if (iter)
		iter->h = h;

	return (wget_hashmap_iterator *) iter;
}

/**
 * \param[in] iter Hashmap iterator
 *
 * Free the given iterator \p iter.
 */
void wget_hashmap_iterator_free(wget_hashmap_iterator **iter)
{
	if (iter)
		xfree(*iter);
}

/**
 * \param[in] iter Hashmap iterator
 * \param[out] value Pointer to the value belonging to the returned key
 * \return Pointer to the key or NULL if no more elements left
 *
 * Returns the next key / value in the hashmap. If all key/value pairs have been
 * iterated over the function returns NULL and \p value is untouched.
 *
 * When iterating over a hashmap, the order of returned key/value pairs is not defined.
 */
void *wget_hashmap_iterator_next(wget_hashmap_iterator *iter, void **value)
{
	struct wget_hashmap_iterator_st *_iter = (struct wget_hashmap_iterator_st *) iter;
	struct wget_hashmap_st *h = _iter->h;

	if (_iter->entry) {
		if ((_iter->entry = _iter->entry->next)) {
found:
			if (value)
				*value = _iter->entry->value;
			return _iter->entry->key;
		}

		_iter->pos++;
	}

	if (!_iter->entry && h) {
		for (; _iter->pos < h->max; _iter->pos++) {
			if (h->entry[_iter->pos]) {
				_iter->entry = h->entry[_iter->pos];
				goto found;
			}
		}
	}

	return NULL;
}

/**
 * \param[in] max Initial number of pre-allocated entries
 * \param[in] hash Hash function to build hashes from elements
 * \param[in] cmp Comparison function used to find elements
 * \return New hashmap instance
 *
 * Create a new hashmap instance with initial size \p max.
 * It should be free'd after use with wget_hashmap_free().
 *
 * Before the first insertion of an element, \p hash and \p cmp must be set.
 * So if you use %NULL values here, you have to call wget_hashmap_setcmpfunc() and/or
 * wget_hashmap_hashcmpfunc() with appropriate function pointers. No doing so will result
 * in undefined behavior (likely you'll see a segmentation fault).
 */
wget_hashmap *wget_hashmap_create(int max, wget_hashmap_hash_fn *hash, wget_hashmap_compare_fn *cmp)
{
	wget_hashmap *h = wget_malloc(sizeof(wget_hashmap));

	if (!h)
		return NULL;

	h->entry = wget_calloc(max, sizeof(entry_t *));

	if (!h->entry) {
		xfree(h);
		return NULL;
	}

	h->max = max;
	h->cur = 0;
	h->resize_factor = 2;
	h->hash = hash;
	h->cmp = cmp;
	h->key_destructor = free;
	h->value_destructor = free;
	h->load_factor = 0.75;
	h->threshold = (int)(max * h->load_factor);

	return h;
}

WGET_GCC_NONNULL_ALL
static entry_t * hashmap_find_entry(const wget_hashmap *h, const char *key, unsigned int hash)
{
	for (entry_t * e = h->entry[hash % h->max]; e; e = e->next) {
		if (hash == e->hash && (key == e->key || !h->cmp(key, e->key))) {
			return e;
		}
	}

	return NULL;
}

WGET_GCC_NONNULL_ALL
static void hashmap_rehash(wget_hashmap *h, entry_t **new_entry, int newmax, int recalc_hash)
{
	entry_t *entry, *next;
	int cur = h->cur;

	for (int it = 0; it < h->max && cur; it++) {
		for (entry = h->entry[it]; entry; entry = next) {
			next = entry->next;

			// now move entry from 'h' to 'new_hashmap'
			if (recalc_hash)
				entry->hash = h->hash(entry->key);
			int pos = entry->hash % newmax;
			entry->next = new_entry[pos];
			new_entry[pos] = entry;

			cur--;
		}
	}

	xfree(h->entry);
	h->entry = new_entry;
	h->max = newmax;
	h->threshold = (int)(newmax * h->load_factor);
}

WGET_GCC_NONNULL((1,3))
static int hashmap_new_entry(wget_hashmap *h, unsigned int hash, const char *key, const char *value)
{
	entry_t *entry;

	if (!(entry = wget_malloc(sizeof(entry_t))))
		return WGET_E_MEMORY;

	int pos = hash % h->max;

	entry->key = (void *)key;
	entry->value = (void *)value;
	entry->hash = hash;
	entry->next = h->entry[pos];
	h->entry[pos] = entry;

	if (++h->cur >= h->threshold) {
		int newsize = (int) (h->max * h->resize_factor);

		if (newsize > 0) {
			entry_t **new_entry;

			if (!(new_entry = wget_calloc(newsize, sizeof(entry_t *)))) {
				h->cur--;
				xfree(h->entry[pos]);
				return WGET_E_MEMORY;
			}

			// h->cur is always > 0 here, so we don't need a check
			hashmap_rehash(h, new_entry, newsize, 0);
		}
	}

	return WGET_E_SUCCESS;
}

/**
 * \param[in] h Hashmap to put data into
 * \param[in] key Key to insert into \p h
 * \param[in] value Value to insert into \p h
 * \return 0 if inserted a new entry, 1 if entry existed, WGET_E_MEMORY if internal allocation failed
 *
 * Insert a key/value pair into hashmap \p h.
 *
 * \p key and \p value are *not* cloned, the hashmap takes 'ownership' of both.
 *
 * If \p key already exists and the pointer values the old and the new key differ,
 * the old key will be destroyed by calling the key destructor function (default is free()).
 *
 * To realize a hashset (just keys without values), \p value may be %NULL.
 *
 * Neither \p h nor \p key must be %NULL, else the return value will always be 0.
 */
int wget_hashmap_put(wget_hashmap *h, const void *key, const void *value)
{
	if (h && key) {
		entry_t *entry;
		unsigned int hash = h->hash(key);
		int rc;

		if ((entry = hashmap_find_entry(h, key, hash))) {
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
		if ((rc = hashmap_new_entry(h, hash, key, value)) < 0)
			return rc;
	}

	return 0;
}

/**
 * \param[in] h Hashmap
 * \param[in] key Key to search for
 * \return 1 if \p key has been found, 0 if not found
 *
 * Check if \p key exists in \p h.
 */
int wget_hashmap_contains(const wget_hashmap *h, const void *key)
{
	return wget_hashmap_get(h, key, NULL);
}

/**
 * \param[in] h Hashmap
 * \param[in] key Key to search for
 * \param[out] value Value to be returned
 * \return 1 if \p key has been found, 0 if not found
 *
 * Get the value for a given key.
 *
 * Neither \p h nor \p key must be %NULL.
 */
#undef wget_hashmap_get
int wget_hashmap_get(const wget_hashmap *h, const void *key, void **value)
{
	if (h && key) {
		entry_t *entry;

		if ((entry = hashmap_find_entry(h, key, h->hash(key)))) {
			if (value)
				*value = entry->value;
			return 1;
		}
	}

	return 0;
}

WGET_GCC_NONNULL_ALL
static int hashmap_remove_entry(wget_hashmap *h, const char *key, int free_kv)
{
	entry_t *entry, *next, *prev = NULL;
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

/**
 * \param[in] h Hashmap
 * \param[in] key Key to be removed
 * \return 1 if \p key has been removed, 0 if not found
 *
 * Remove \p key from hashmap \p h.
 *
 * If \p key is found, the key and value destructor functions are called
 * when removing the entry from the hashmap.
 */
int wget_hashmap_remove(wget_hashmap *h, const void *key)
{
	if (h && key)
		return hashmap_remove_entry(h, key, 1);
	else
		return 0;
}

/**
 * \param[in] h Hashmap
 * \param[in] key Key to be removed
 * \return 1 if \p key has been removed, 0 if not found
 *
 * Remove \p key from hashmap \p h.
 *
 * Key and value destructor functions are *not* called when removing the entry from the hashmap.
 */
int wget_hashmap_remove_nofree(wget_hashmap *h, const void *key)
{
	if (h && key)
		return hashmap_remove_entry(h, key, 0);
	else
		return 0;
}

/**
 * \param[in] h Hashmap to be free'd
 *
 * Remove all entries from hashmap \p h and free the hashmap instance.
 *
 * Key and value destructor functions are called for each entry in the hashmap.
 */
void wget_hashmap_free(wget_hashmap **h)
{
	if (h && *h) {
		wget_hashmap_clear(*h);
		xfree((*h)->entry);
		xfree(*h);
	}
}

/**
 * \param[in] h Hashmap to be cleared
 *
 * Remove all entries from hashmap \p h.
 *
 * Key and value destructor functions are called for each entry in the hashmap.
 */
void wget_hashmap_clear(wget_hashmap *h)
{
	if (h) {
		entry_t *entry, *next;
		int it, cur = h->cur;

		for (it = 0; it < h->max && cur; it++) {
			for (entry = h->entry[it]; entry; entry = next) {
				next = entry->next;

				if (h->key_destructor)
					h->key_destructor(entry->key);

				// free value if different from key
				if (h->value_destructor) {
					if (entry->value != entry->key || (entry->value == entry->key && !h->key_destructor))
						h->value_destructor(entry->value);
				}

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

/**
 * \param[in] h Hashmap
 * \return Number of entries in hashmap \p h
 *
 * Return the number of entries in the hashmap \p h.
 */
int wget_hashmap_size(const wget_hashmap *h)
{
	return h ? h->cur : 0;
}

/**
 * \param[in] h Hashmap
 * \param[in] browse Function to be called for each element of \p h
 * \param[in] ctx Context variable use as param to \p browse
 * \return Return value of the last call to \p browse
 *
 * Call function \p browse for each element of hashmap \p h or until \p browse
 * returns a value not equal to zero.
 *
 * \p browse is called with \p ctx and the pointer to the current element.
 *
 * The return value of the last call to \p browse is returned or 0 if either \p h or \p browse is %NULL.
 */
int wget_hashmap_browse(const wget_hashmap *h, wget_hashmap_browse_fn *browse, void *ctx)
{
	if (h && browse) {
		entry_t *entry;
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

/**
 * \param[in] h Hashmap
 * \param[in] cmp Comparison function used to find keys
 *
 * Set the comparison function.
 */
void wget_hashmap_setcmpfunc(wget_hashmap *h, wget_hashmap_compare_fn *cmp)
{
	if (h)
		h->cmp = cmp;
}

/**
 * \param[in] h Hashmap
 * \param[in] hash Hash function used to hash keys
 * \return WGET_E_SUCCESS if set successfully, else WGET_E_MEMORY or WGET_E_INVALID
 *
 * Set the key hash function.
 *
 * The keys of all entries in the hashmap will be hashed again. This includes a memory allocation, so
 * there is a possibility of failure.
 */
int wget_hashmap_sethashfunc(wget_hashmap *h, wget_hashmap_hash_fn *hash)
{
	if (!h)
		return WGET_E_INVALID;

	if (!h->cur)
		return WGET_E_SUCCESS; // no re-hashing needed

	entry_t **new_entry = wget_calloc(h->max, sizeof(entry_t *));

	if (!new_entry)
		return WGET_E_MEMORY;

	h->hash = hash;
	hashmap_rehash(h, new_entry, h->max, 1);

	return WGET_E_SUCCESS;
}

/**
 * \param[in] h Hashmap
 * \param[in] destructor Destructor function for keys
 *
 * Set the key destructor function.
 *
 * Default is free().
 */
void wget_hashmap_set_key_destructor(wget_hashmap *h, wget_hashmap_key_destructor *destructor)
{
	if (h)
		h->key_destructor = destructor;
}

/**
 * \param[in] h Hashmap
 * \param[in] destructor Destructor function for values
 *
 * Set the value destructor function.
 *
 * Default is free().
 */
void wget_hashmap_set_value_destructor(wget_hashmap *h, wget_hashmap_value_destructor *destructor)
{
	if (h)
		h->value_destructor = destructor;
}

/**
 * \param[in] h Hashmap
 * \param[in] factor The load factor
 *
 * Set the load factor function.
 *
 * The load factor is determines when to resize the internal memory.
 * 0.75 means "resize if 75% or more of all slots are used".
 *
 * The resize strategy is set by wget_hashmap_set_growth_policy().
 *
 * The resize (and rehashing) occurs earliest on the next insertion of a new key.
 *
 * Default is 0.75.
 */
void wget_hashmap_set_load_factor(wget_hashmap *h, float factor)
{
	if (h) {
		h->load_factor = factor;
		h->threshold = (int)(h->max * h->load_factor);
		// rehashing occurs earliest on next put()
	}
}

/**
 * \param[in] h Hashmap
 * \param[in] factor Hashmap growth factor
 *
 * Set the factor for resizing the hashmap when it's load factor is reached.
 *
 * The new size is 'factor * oldsize'. If the new size is less or equal 0,
 * the involved put function will do nothing and the internal state of
 * the hashmap will not change.
 *
 * Default is 2.
 */
void wget_hashmap_set_resize_factor(wget_hashmap *h, float factor)
{
	if (h)
		h->resize_factor = factor;
}

/**@}*/
