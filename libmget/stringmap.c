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
 * stringmap routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <libmget.h>
#include "private.h"

// Paul Larson's hash function from Microsoft Research
static unsigned int G_GNUC_MGET_PURE hash_string(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)*key++;
		// h = (h << 6) ^ (h >> 26) ^ (unsigned char)*key++;

	return hash;
}

static unsigned int G_GNUC_MGET_PURE hash_string_nocase(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)tolower(*key++);

	return hash;
}

// create stringmap with initial size <max>
// the default hash function is Larson's

MGET_STRINGMAP *mget_stringmap_create(int max)
{
	return mget_hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string, (int (*)(const void *, const void *))strcmp);
}

MGET_STRINGMAP *mget_stringmap_create_nocase(int max)
{
	return mget_hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string_nocase, (int (*)(const void *, const void *))strcasecmp);
}

int mget_stringmap_put_noalloc(MGET_STRINGMAP *h, const char *key, const void *value)
{
	return mget_hashmap_put_noalloc(h, key, value);
}

int mget_stringmap_put(MGET_STRINGMAP *h, const char *key, const void *value, size_t valuesize)
{
	return mget_hashmap_put(h, key, strlen(key) + 1, value, valuesize);
}

void *mget_stringmap_get(const MGET_STRINGMAP *h, const char *key)
{
	return mget_hashmap_get(h, key);
}

int mget_stringmap_get_null(const MGET_STRINGMAP *h, const char *key, void **value)
{
	return mget_hashmap_get_null(h, key, value);
}

int mget_stringmap_contains(const MGET_STRINGMAP *h, const char *key)
{
	return mget_hashmap_contains(h, key);
}

void mget_stringmap_remove(MGET_STRINGMAP *h, const char *key)
{
	mget_hashmap_remove(h, key);
}

void mget_stringmap_remove_nofree(MGET_STRINGMAP *h, const char *key)
{
	mget_hashmap_remove(h, key);
}

void mget_stringmap_free(MGET_STRINGMAP **h)
{
	mget_hashmap_free(h);
}

void mget_stringmap_clear(MGET_STRINGMAP *h)
{
	mget_hashmap_clear(h);
}

int mget_stringmap_size(const MGET_STRINGMAP *h)
{
	return mget_hashmap_size(h);
}

int mget_stringmap_browse(const MGET_STRINGMAP *h, int (*browse)(const char *key, const void *value))
{
	return mget_hashmap_browse(h, (int (*)(const void *, const void *))browse);
}

void mget_stringmap_setcmpfunc(MGET_STRINGMAP *h, int (*cmp)(const char *key1, const char *key2))
{
	mget_hashmap_setcmpfunc(h, (int (*)(const void *, const void *))cmp);
}

void mget_stringmap_sethashfunc(MGET_STRINGMAP *h, unsigned int (*hash)(const char *key))
{
	mget_hashmap_sethashfunc(h, (unsigned int (*)(const void *))hash);
}

void mget_stringmap_setloadfactor(MGET_STRINGMAP *h, float factor)
{
	mget_hashmap_setloadfactor(h, factor);
}
