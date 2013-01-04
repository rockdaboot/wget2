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
 * Header file for vector routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_VECTOR_H
#define _MGET_VECTOR_H

#include <stddef.h>
#include <stdarg.h>

typedef struct {
	int
		(*cmp)(const void *, const void *); // comparison function
	void
		**pl; // pointer to array of pointers to elements
	int
		max,     // allocated elements
		cur,     // number of elements in use
		off;     // number of elements to add if resize occurs
	char
		sorted; // 1=list is sorted, 0=list is not sorted
} VECTOR;

VECTOR
	*vec_create(int max, int off, int (*cmp)(const void *, const void *)) G_GNUC_MGET_MALLOC;
int
	vec_find(const VECTOR *v, const void *elem) G_GNUC_MGET_NONNULL((2)),
	vec_findext(const VECTOR *v, int start, int direction, int (*find)(void *)) G_GNUC_MGET_NONNULL((4)),
	vec_insert(VECTOR *v, const void *elem, size_t size, int pos) G_GNUC_MGET_NONNULL((2)),
	vec_insert_noalloc(VECTOR *v, const void *elem, int pos) G_GNUC_MGET_NONNULL((2)),
	vec_insert_sorted(VECTOR *v, const void *elem, size_t size) G_GNUC_MGET_NONNULL((2)),
	vec_insert_sorted_noalloc(VECTOR *v, const void *elem) G_GNUC_MGET_NONNULL((2)),
	vec_add(VECTOR *v, const void *elem, size_t size) G_GNUC_MGET_NONNULL((2)),
	vec_add_noalloc(VECTOR *v, const void *elem) G_GNUC_MGET_NONNULL((2)),
	vec_add_str(VECTOR *v, const char *s) G_GNUC_MGET_NONNULL((2)),
	vec_add_vprintf(VECTOR *v, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(2,0) G_GNUC_MGET_NONNULL((2)),
	vec_add_printf(VECTOR *v, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL((2)),
	vec_replace(VECTOR *v, const void *elem, size_t size, int pos) G_GNUC_MGET_NONNULL((2)),
	vec_move(VECTOR *v, int old_pos, int new_pos),
	vec_swap(VECTOR *v, int pos1, int pos2),
	vec_remove(VECTOR *v, int pos),
	vec_remove_nofree(VECTOR *v, int pos),
	vec_size(const VECTOR *v),
	vec_browse(const VECTOR *v, int (*browse)(void *elem)) G_GNUC_MGET_NONNULL((2));
void
	vec_free(VECTOR **v),
	vec_clear(VECTOR *v),
	vec_clear_nofree(VECTOR *v),
	*vec_get(const VECTOR *v, int pos),
	vec_setcmpfunc(VECTOR *v, int (*cmp)(const void *elem1, const void *elem2)) G_GNUC_MGET_NONNULL((2)),
	vec_sort(VECTOR *v);

#endif /* _MGET_VECTOR_H */
