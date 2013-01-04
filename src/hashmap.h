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
 * Header file for hashmap routines
 *
 * Changelog
 * 06.11.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_HASHMAP_H
#define _MGET_HASHMAP_H

#include <stddef.h>
#include <stdarg.h>

typedef struct MGET_HASHMAP MGET_HASHMAP;

MGET_HASHMAP
	*hashmap_create(int max, int off, unsigned int (*hash)(const void *), int (*cmp)(const void *, const void *)) G_GNUC_MGET_MALLOC;
int
	hashmap_put(MGET_HASHMAP *h, const void *key, size_t keysize, const void *value, size_t valuesize),
	hashmap_put_noalloc(MGET_HASHMAP *h, const void *key, const void *value),
	hashmap_put_ident(MGET_HASHMAP *h, const void *key, size_t keysize),
	hashmap_put_ident_noalloc(MGET_HASHMAP *h, const void *key),
	hashmap_size(const MGET_HASHMAP *h),
	hashmap_browse(const MGET_HASHMAP *h, int (*browse)(const void *key, const void *value)) G_GNUC_MGET_NONNULL((2));
void
	hashmap_free(MGET_HASHMAP **h),
	hashmap_clear(MGET_HASHMAP *h),
	*hashmap_get(const MGET_HASHMAP *h, const void *key),
	hashmap_remove(MGET_HASHMAP *h, const void *key),
	hashmap_remove_nofree(MGET_HASHMAP *h, const void *key),
	hashmap_setcmpfunc(MGET_HASHMAP *h, int (*cmp)(const void *key1, const void *key2)) G_GNUC_MGET_NONNULL_ALL,
	hashmap_sethashfunc(MGET_HASHMAP *h, unsigned int (*hash)(const void *key)) G_GNUC_MGET_NONNULL_ALL,
	hashmap_setloadfactor(MGET_HASHMAP *h, float factor) G_GNUC_MGET_NONNULL_ALL;

#endif /* _MGET_HASHMAP_H */
