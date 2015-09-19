/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
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

#include <libwget.h>
#include "private.h"

// Paul Larson's hash function from Microsoft Research
static unsigned int G_GNUC_WGET_PURE hash_string(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)*key++;
		// h = (h << 6) ^ (h >> 26) ^ (unsigned char)*key++;

	return hash;
}

static unsigned int G_GNUC_WGET_PURE hash_string_nocase(const char *key)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*key)
		hash = hash * 101 + (unsigned char)tolower(*key++);

	return hash;
}

// create stringmap with initial size <max>
// the default hash function is Larson's

wget_stringmap_t *wget_stringmap_create(int max)
{
	return wget_hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string, (int (*)(const void *, const void *))strcmp);
}

wget_stringmap_t *wget_stringmap_create_nocase(int max)
{
	return wget_hashmap_create(max, -2, (unsigned int (*)(const void *))hash_string_nocase, (int (*)(const void *, const void *))strcasecmp);
}

int wget_stringmap_put_noalloc(wget_stringmap_t *h, const char *key, const void *value)
{
	return wget_hashmap_put_noalloc(h, key, value);
}

int wget_stringmap_put(wget_stringmap_t *h, const char *key, const void *value, size_t valuesize)
{
	return wget_hashmap_put(h, key, strlen(key) + 1, value, valuesize);
}

void *wget_stringmap_get(const wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_get(h, key);
}

int wget_stringmap_get_null(const wget_stringmap_t *h, const char *key, void **value)
{
	return wget_hashmap_get_null(h, key, value);
}

int wget_stringmap_contains(const wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_contains(h, key);
}

int wget_stringmap_remove(wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_remove(h, key);
}

int wget_stringmap_remove_nofree(wget_stringmap_t *h, const char *key)
{
	return wget_hashmap_remove(h, key);
}

void wget_stringmap_free(wget_stringmap_t **h)
{
	wget_hashmap_free(h);
}

void wget_stringmap_clear(wget_stringmap_t *h)
{
	wget_hashmap_clear(h);
}

int wget_stringmap_size(const wget_stringmap_t *h)
{
	return wget_hashmap_size(h);
}

int wget_stringmap_browse(const wget_stringmap_t *h, int (*browse)(void *ctx, const char *key, void *value), void *ctx)
{
	return wget_hashmap_browse(h, (int (*)(void *, const void *, void *))browse, ctx);
}

void wget_stringmap_setcmpfunc(wget_stringmap_t *h, int (*cmp)(const char *key1, const char *key2))
{
	wget_hashmap_setcmpfunc(h, (int (*)(const void *, const void *))cmp);
}

void wget_stringmap_sethashfunc(wget_stringmap_t *h, unsigned int (*hash)(const char *key))
{
	wget_hashmap_sethashfunc(h, (unsigned int (*)(const void *))hash);
}

void wget_stringmap_setloadfactor(wget_stringmap_t *h, float factor)
{
	wget_hashmap_setloadfactor(h, factor);
}

void wget_stringmap_set_value_destructor(wget_hashmap_t *h, void (*destructor)(void *value))
{
	wget_hashmap_set_value_destructor(h, destructor);
}
