/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 * stringmap routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <wget.h>
#include "private.h"

// Paul Larson's hash function from Microsoft Research
#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
G_GNUC_WGET_PURE
static unsigned int hash_string(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)*key++;

	return hash;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
G_GNUC_WGET_PURE
static unsigned int hash_string_nocase(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)tolower(*key++);

	return hash;
}

/**
 * \file
 * \brief Stringmap functions
 * \defgroup libwget-stringmap Stringmap functions
 * @{
 *
 * Stringmaps are key/value stores that perform at O(1) for insertion, searching and removing.
 * The key is a C string.
 *
 * These functions are a wrapper around the Hashmap API.
 */

/**
 * \param[in] max Initial number of pre-allocated entries
 * \return New stringmap instance
 *
 * Create a new stringmap instance with initial size \p max.
 * It should be free'd after use with wget_stringmap_free().
 *
 * The hash function is an efficient string hash algorithm originally researched by Paul Larson.
 *
 * The compare function is strcmp(). The key strings are compared case-sensitive.
 */
wget_stringmap_t *wget_stringmap_create(int max)
{
	return wget_hashmap_create(max, (wget_hashmap_hash_t)hash_string, (wget_hashmap_compare_t)wget_strcmp);
}

/**
 * \param[in] max Initial number of pre-allocated entries
 * \return New stringmap instance
 *
 * Create a new stringmap instance with initial size \p max.
 * It should be free'd after use with wget_stringmap_free().
 *
 * The hash function is an efficient string hash algorithm originally researched by Paul Larson, using
 * lowercase'd keys.
 *
 * The compare function is strcasecmp() (case-insensitive).
 */
wget_stringmap_t *wget_stringmap_create_nocase(int max)
{
	return wget_hashmap_create(max, (wget_hashmap_hash_t)hash_string_nocase, (wget_hashmap_compare_t)wget_strcasecmp);
}

/**
 * \param[in] h Stringmap to put data into
 * \param[in] key Key to insert into \p h
 * \param[in] value Value to insert into \p h
 * \return 0 if inserted a new entry, 1 if entry existed
 *
 * Insert a key/value pair into stringmap \p h.
 *
 * \p key and \p value are *not* cloned, the stringmap takes 'ownership' of both.
 *
 * If \p key already exists and the pointer values the old and the new key differ,
 * the old key will be destroyed by calling the key destructor function (default is free()).
 *
 * To realize a hashset (just keys without values), \p value may be %NULL.
 *
 * Neither \p h nor \p key must be %NULL.
 */
int wget_stringmap_put_noalloc(wget_stringmap_t *h, const char *key, const void *value)
{
	return wget_hashmap_put_noalloc(h, key, value);
}

/**
 * \param[in] h Stringmap to put data into
 * \param[in] key Key to insert into \p h
 * \param[in] value Value to insert into \p h
 * \param[in] valuesize Size of \p value
 * \return 0 if inserted a new entry, 1 if entry existed
 *
 * Insert a key/value pair into stringmap \p h.
 *
 * If \p key already exists it will not be cloned. In this case the value destructor function
 * will be called with the old value and the new value will be shallow cloned.
 *
 * If \p doesn't exist, both \p key and \p value will be shallow cloned.
 *
 * To realize a hashset (just keys without values), \p value may be %NULL.
 *
 * Neither \p h nor \p key must be %NULL.
 */
int wget_stringmap_put(wget_stringmap_t *h, const char *key, const void *value, size_t valuesize)
{
	return wget_hashmap_put(h, key, strlen(key) + 1, value, valuesize);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to search for
 * \param[out] value Value to be returned
 * \return 1 if \p key has been found, 0 if not found
 *
 * Get the value for a given key.
 *
 * Neither \p h nor \p key must be %NULL.
 */
#undef wget_stringmap_get
int wget_stringmap_get(const wget_stringmap_t *h, const char *key, void **value)
{
	return wget_hashmap_get(h, key, value);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to search for
 * \return 1 if \p key has been found, 0 if not found
 *
 * Check if \p key exists in \p h.
 */
int wget_stringmap_contains(const wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_contains(h, key);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to be removed
 * \return 1 if \p key has been removed, 0 if not found
 *
 * Remove \p key from stringmap \p h.
 *
 * If \p key is found, the key and value destructor functions are called
 * when removing the entry from the stringmap.
 */
int wget_stringmap_remove(wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_remove(h, key);
}

/**
 * \param[in] h Stringmap
 * \param[in] key Key to be removed
 * \return 1 if \p key has been removed, 0 if not found
 *
 * Remove \p key from stringmap \p h.
 *
 * Key and value destructor functions are *not* called when removing the entry from the stringmap.
 */
int wget_stringmap_remove_nofree(wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_remove(h, key);
}

/**
 * \param[in] h Stringmap to be free'd
 *
 * Remove all entries from stringmap \p h and free the stringmap instance.
 *
 * Key and value destructor functions are called for each entry in the stringmap.
 */
void wget_stringmap_free(wget_stringmap_t **h)
{
	wget_hashmap_free(h);
}

/**
 * \param[in] h Stringmap to be cleared
 *
 * Remove all entries from stringmap \p h.
 *
 * Key and value destructor functions are called for each entry in the stringmap.
 */
void wget_stringmap_clear(wget_stringmap_t *h)
{
	wget_hashmap_clear(h);
}

/**
 * \param[in] h Stringmap
 * \return Number of entries in stringmap \p h
 *
 * Return the number of entries in the stringmap \p h.
 */
int wget_stringmap_size(const wget_stringmap_t *h)
{
	return wget_hashmap_size(h);
}

/**
 * \param[in] h Stringmap
 * \param[in] browse Function to be called for each element of \p h
 * \param[in] ctx Context variable use as param to \p browse
 * \return Return value of the last call to \p browse
 *
 * Call function \p browse for each element of stringmap \p h or until \p browse
 * returns a value not equal to zero.
 *
 * \p browse is called with \p ctx and the pointer to the current element.
 *
 * The return value of the last call to \p browse is returned or 0 if either \p h or \p browse is %NULL.
 */
int wget_stringmap_browse(const wget_stringmap_t *h, wget_stringmap_browse_t browse, void *ctx)
{
	return wget_hashmap_browse(h, (wget_hashmap_browse_t)browse, ctx);
}

/**
 * \param[in] h Stringmap
 * \param[in] cmp Comparison function used to find keys
 *
 * Set the comparison function.
 */
void wget_stringmap_setcmpfunc(wget_stringmap_t *h, wget_stringmap_compare_t cmp)
{
	wget_hashmap_setcmpfunc(h, (wget_hashmap_compare_t)cmp);
}

/**
 * \param[in] h Stringmap
 * \param[in] hash Hash function used to hash keys
 *
 * Set the key hash function.
 *
 * The keys of all entries in the stringmap will be hashed again.
 */
void wget_stringmap_sethashfunc(wget_stringmap_t *h, wget_stringmap_hash_t hash)
{
	wget_hashmap_sethashfunc(h, (wget_hashmap_hash_t)hash);
}

/**
 * \param[in] h Stringmap
 * \param[in] destructor Destructor function for keys
 *
 * Set the key destructor function.
 *
 * Default is free().
 */
void wget_stringmap_set_key_destructor(wget_hashmap_t *h, wget_stringmap_key_destructor_t destructor)
{
	wget_hashmap_set_key_destructor(h, (wget_hashmap_key_destructor_t)destructor);
}

/**
 * \param[in] h Stringmap
 * \param[in] destructor Destructor function for values
 *
 * Set the value destructor function.
 *
 * Default is free().
 */
void wget_stringmap_set_value_destructor(wget_hashmap_t *h, wget_stringmap_value_destructor_t destructor)
{
	wget_hashmap_set_value_destructor(h, (wget_hashmap_value_destructor_t)destructor);
}

/**
 * \param[in] h Stringmap
 * \param[in] factor The load factor
 *
 * Set the load factor function.
 *
 * The load factor is determines when to resize the internal memory.
 * 0.75 means "resize if 75% or more of all slots are used".
 *
 * The resize strategy is set by wget_stringmap_set_growth_policy().
 *
 * The resize (and rehashing) occurs earliest on the next insertion of a new key.
 *
 * Default is 0.75.
 */
void wget_stringmap_set_load_factor(wget_stringmap_t *h, float factor)
{
	wget_hashmap_set_load_factor(h, factor);
}

/**
 * \param[in] h Stringmap
 * \param[in] off Stringmap growth factor
 *
 * Set the factor for resizing the stringmap when it's load factor is reached.
 *
 * The new size is 'factor * oldsize'. If the new size is less or equal 0,
 * the involved put function will do nothing and the internal state of
 * the stringmap will not change.
 *
 * Default is 2.
 */
void wget_stringmap_set_resize_factor(wget_stringmap_t *h, float factor)
{
	wget_hashmap_set_resize_factor(h, factor);
}

/**
 * \param[in] iter Stringmap iterator
 * \param[out] value Pointer to the value belonging to the returned key
 * \return Pointer to the key or NULL if no more elements left
 *
 * Returns the next key / value in the stringmap. If all key/value pairs have been
 * iterated over the function returns NULL and \p value is untouched.
 *
 * When iterating over a stringmap, the order of returned key/value pairs is not defined.
 */
void *wget_stringmap_iterator_next(wget_stringmap_iterator_t *h, char **value)
{
	return wget_hashmap_iterator_next(h, (void **) value);
}

/**@}*/
