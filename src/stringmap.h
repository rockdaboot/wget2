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
 * Header file for stringmap routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_STRINGMAP_H
#define _MGET_STRINGMAP_H

#include <stddef.h>
#include <stdarg.h>

typedef struct MGET_STRINGMAP MGET_STRINGMAP;

MGET_STRINGMAP
	*stringmap_create(int max) G_GNUC_MGET_MALLOC,
	*stringmap_create_nocase(int max) G_GNUC_MGET_MALLOC;
int
	stringmap_put(MGET_STRINGMAP *h, const char *key, const void *value, size_t valuesize),
	stringmap_put_noalloc(MGET_STRINGMAP *h, const char *key, const void *value),
	stringmap_put_ident(MGET_STRINGMAP *h, const char *key),
	stringmap_put_ident_noalloc(MGET_STRINGMAP *h, const char *key),
	stringmap_size(const MGET_STRINGMAP *h),
	stringmap_browse(const MGET_STRINGMAP *h, int (*browse)(const char *key, const void *value)) G_GNUC_MGET_NONNULL((2));
void
	stringmap_free(MGET_STRINGMAP **h),
	stringmap_clear(MGET_STRINGMAP *h),
	*stringmap_get(const MGET_STRINGMAP *h, const char *key),
	stringmap_remove(MGET_STRINGMAP *h, const char *key),
	stringmap_remove_nofree(MGET_STRINGMAP *h, const char *key),
	stringmap_setcmpfunc(MGET_STRINGMAP *h, int (*cmp)(const char *key1, const char *key2)) G_GNUC_MGET_NONNULL_ALL,
	stringmap_sethashfunc(MGET_STRINGMAP *h, unsigned int (*hash)(const char *key)) G_GNUC_MGET_NONNULL_ALL,
	stringmap_setloadfactor(MGET_STRINGMAP *h, float factor) G_GNUC_MGET_NONNULL_ALL;

#endif /* _MGET_STRINGMAP_H */
