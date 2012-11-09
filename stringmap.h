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

#include "mget.h"

typedef struct STRINGMAP STRINGMAP;

STRINGMAP
	*stringmap_create(int max) MALLOC,
	*stringmap_nocase_create(int max) MALLOC;
int
	stringmap_size(const STRINGMAP *h),
	stringmap_browse(const STRINGMAP *h, int (*browse)(const char *key, const void *value)) NONNULL(2);
void
	stringmap_free(STRINGMAP **h),
	stringmap_clear(STRINGMAP *h),
	*stringmap_get(const STRINGMAP *h, const char *key),
	*stringmap_put(STRINGMAP *h, const char *key, const void *value, size_t valuesize),
	*stringmap_put_noalloc(STRINGMAP *h, const char *key, const void *value),
	*stringmap_put_ident(STRINGMAP *h, const char *key),
	*stringmap_put_ident_noalloc(STRINGMAP *h, const char *key),
	stringmap_remove(STRINGMAP *h, const char *key),
	stringmap_remove_nofree(STRINGMAP *h, const char *key),
	stringmap_setcmpfunc(STRINGMAP *h, int (*cmp)(const char *key1, const char *key2)) NONNULL_ALL,
	stringmap_sethashfunc(STRINGMAP *h, unsigned int (*hash)(const char *key)) NONNULL_ALL,
	stringmap_setloadfactor(STRINGMAP *h, float factor) NONNULL_ALL;

#endif /* _MGET_STRINGMAP_H */
