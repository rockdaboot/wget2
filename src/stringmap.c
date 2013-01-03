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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <libmget.h>

#include "xalloc.h"
#include "log.h"
#include "hashmap.h"
#include "stringmap.h"

typedef struct ENTRY ENTRY;

struct MGET_STRINGMAP {
	MGET_HASHMAP
		*h;
};

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
static unsigned int hash_string(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)*key++;
		// h = (h << 6) ^ (h >> 26) ^ (unsigned char)*key++;

	return hash;
}

static unsigned int hash_string_nocase(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)tolower(*key++);

	return hash;
}

// create stringmap with initial size <max>
// the default hash function is Larson's

MGET_STRINGMAP *stringmap_create(int max)
{
	MGET_STRINGMAP *h = xmalloc(sizeof(MGET_STRINGMAP));
	h->h = hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string, (int (*)(const void *, const void *))strcmp);
	return h;
}

MGET_STRINGMAP *stringmap_create_nocase(int max)
{
	MGET_STRINGMAP *h = xmalloc(sizeof(MGET_STRINGMAP));
	h->h = hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string_nocase, (int (*)(const void *, const void *))strcasecmp);
	return h;
}

int stringmap_put_noalloc(MGET_STRINGMAP *h, const char *key, const void *value)
{
	return hashmap_put_noalloc(h->h, key, value);
}

int stringmap_put(MGET_STRINGMAP *h, const char *key, const void *value, size_t valuesize)
{
	return hashmap_put(h->h, key, strlen(key) + 1, value, valuesize);
}

int stringmap_put_ident(MGET_STRINGMAP *h, const char *key)
{
	return hashmap_put_ident(h->h, key, strlen(key) + 1);
}

int stringmap_put_ident_noalloc(MGET_STRINGMAP *h, const char *key)
{
	return hashmap_put_noalloc(h->h, key, key);
}

void *stringmap_get(const MGET_STRINGMAP *h, const char *key)
{
	return hashmap_get(h->h, key);
}

void stringmap_remove(MGET_STRINGMAP *h, const char *key)
{
	if (h)
		hashmap_remove(h->h, key);
}

void stringmap_remove_nofree(MGET_STRINGMAP *h, const char *key)
{
	if (h)
		hashmap_remove(h->h, key);
}

void stringmap_free(MGET_STRINGMAP **h)
{
	if (h) {
		hashmap_free(&(*h)->h);
		xfree(*h);
	}
}

void stringmap_clear(MGET_STRINGMAP *h)
{
	hashmap_clear(h->h);
}

int stringmap_size(const MGET_STRINGMAP *h)
{
	return h ? hashmap_size(h->h): 0;
}

int stringmap_browse(const MGET_STRINGMAP *h, int (*browse)(const char *key, const void *value))
{
	if (h)
		hashmap_browse(h->h, (int (*)(const void *, const void *))browse);

	return 0;
}

void stringmap_setcmpfunc(MGET_STRINGMAP *h, int (*cmp)(const char *key1, const char *key2))
{
	if (h)
		hashmap_setcmpfunc(h->h, (int (*)(const void *, const void *))cmp);
}

void stringmap_sethashfunc(MGET_STRINGMAP *h, unsigned int (*hash)(const char *key))
{
	if (h)
		hashmap_sethashfunc(h->h, (unsigned int (*)(const void *))hash);
}

void stringmap_setloadfactor(MGET_STRINGMAP *h, float factor)
{
	if (h)
		hashmap_setloadfactor(h->h, factor);
}
