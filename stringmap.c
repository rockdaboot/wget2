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
 * stringmap routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "xalloc.h"
#include "log.h"
#include "hashmap.h"
#include "stringmap.h"

typedef struct ENTRY ENTRY;

struct STRINGMAP {
	HASHMAP
		*h;
};

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
static unsigned int hash_string(const char *key)
{
	unsigned int h = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		h = h * 101 + (unsigned char)*key++;
		// h = (h << 6) ^ (h >> 26) ^ (unsigned char)*key++;

	return h;
}

// create stringmap with initial size <max>
// the default hash function is Larson's

STRINGMAP *stringmap_create(int max)
{
	STRINGMAP *h = xmalloc(sizeof(STRINGMAP));
	h->h = hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string, (int (*)(const void *, const void *))strcmp);
	return h;
}

STRINGMAP *stringmap_nocase_create(int max)
{
	STRINGMAP *h = xmalloc(sizeof(STRINGMAP));
	h->h = hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string, (int (*)(const void *, const void *))strcasecmp);
	return h;
}

void *stringmap_put_noalloc(STRINGMAP *h, const char *key, const void *value)
{
	return hashmap_put_noalloc(h->h, key, value);
}

void *stringmap_put(STRINGMAP *h, const char *key, const void *value, size_t valuesize)
{
	return hashmap_put_noalloc(h->h, strdup(key), value ? xmemdup(value, valuesize) : NULL);
}

void *stringmap_put_ident(STRINGMAP *h, const char *key)
{
	char *keydup = strdup(key);
	return hashmap_put_noalloc(h->h, keydup, keydup);
}

void *stringmap_put_ident_noalloc(STRINGMAP *h, const char *key)
{
	return hashmap_put_noalloc(h->h, key, key);
}

void *stringmap_get(const STRINGMAP *h, const char *key)
{
	return hashmap_get(h->h, key);
}

void stringmap_remove(STRINGMAP *h, const char *key)
{
	if (h)
		hashmap_remove(h->h, key);
}

void stringmap_remove_nofree(STRINGMAP *h, const char *key)
{
	if (h)
		hashmap_remove(h->h, key);
}

void stringmap_free(STRINGMAP **h)
{
	if (h) {
		hashmap_free(&(*h)->h);
		xfree(*h);
	}
}

void stringmap_clear(STRINGMAP *h)
{
	hashmap_clear(h->h);
}

int stringmap_size(const STRINGMAP *h)
{
	return h ? hashmap_size(h->h): 0;
}

int stringmap_browse(const STRINGMAP *h, int (*browse)(const char *key, const void *value))
{
	if (h)
		hashmap_browse(h->h, (int (*)(const void *, const void *))browse);

	return 0;
}

void stringmap_setcmpfunc(STRINGMAP *h, int (*cmp)(const char *key1, const char *key2))
{
	if (h)
		hashmap_setcmpfunc(h->h, (int (*)(const void *, const void *))cmp);
}

void stringmap_sethashfunc(STRINGMAP *h, unsigned int (*hash)(const char *key))
{
	if (h)
		hashmap_sethashfunc(h->h, (unsigned int (*)(const void *))hash);
}

void stringmap_setloadfactor(STRINGMAP *h, float factor)
{
	if (h)
		hashmap_setloadfactor(h->h, factor);
}
