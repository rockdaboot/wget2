/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * vector routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <wget.h>
#include "private.h"

struct _wget_vector_st {
	wget_vector_compare_t
		cmp; // comparison function
	wget_vector_destructor_t
		destructor; // element destructor function
	void
		**entry; // pointer to array of pointers to elements
	int
		max,     // allocated elements
		cur,     // number of elements in use
		off;     // number of elements to add if resize occurs
	unsigned char
		sorted : 1; // 1=list is sorted, 0=list is not sorted
};

// create vector with initial size <max>
// vector growth is specified by off:
//   positive values: increase vector by <off> entries on each resize
//   negative values: increase vector by *<-off>, e.g. -2 doubles the size on each resize
// cmp: comparison function for sorting/finding, also needed for vec_insert_sorted*()
//      or NULL if not needed.
// the vector plus content is freed by vec_free()

wget_vector_t *wget_vector_create(int max, int off, wget_vector_compare_t cmp)
{
	wget_vector_t *v = xcalloc(1, sizeof(wget_vector_t));

	v->entry = xmalloc(max * sizeof(void *));
	v->max = max;
	v->off = off;
	v->cmp = cmp;

	return v;
}

void wget_vector_deinit(wget_vector_t *v)
{
	if(v)
		wget_xfree(v->entry);
}

static int G_GNUC_WGET_NONNULL((2)) _vec_insert_private(wget_vector_t *v, const void *elem, size_t size, int pos, int replace, int alloc)
{
	void *elemp;

	if (pos < 0 || !v || pos > v->cur) return -1;

	if (alloc) {
		elemp = xmalloc(size);
		memcpy(elemp, elem, size);
	} else {
		elemp = (void *)elem;
	}

	if (!replace) {
		if (v->max == v->cur) {
			if (v->off > 0) {
				v->entry = xrealloc(v->entry, (v->max += v->off) * sizeof(void *));
			} else if (v->off<-1) {
				v->entry = xrealloc(v->entry, (v->max *= -v->off) * sizeof(void *));
			} else {
				if (alloc)
					free(elemp);
				return -1;
			}
		}

		memmove(&v->entry[pos + 1], &v->entry[pos], (v->cur - pos) * sizeof(void *));
		v->cur++;
	}

	v->entry[pos] = elemp;

	if (v->cmp) {
		if (v->cur == 1) v->sorted = 1;
		else if (v->cur > 1 && v->sorted) {
			if (pos == 0) {
				if (v->cmp(elem, v->entry[1]) > 0) v->sorted = 0;
			} else if (pos == v->cur - 1) {
				if (v->cmp(elem, v->entry[v->cur - 2]) < 0) v->sorted = 0;
			} else {
				if (v->cmp(elem, v->entry[pos - 1]) < 0 ||
					v->cmp(elem, v->entry[pos + 1]) > 0) {
					v->sorted = 0;
				}
			}
		}
	}

	return pos; // return position of new element
}

int wget_vector_insert(wget_vector_t *v, const void *elem, size_t size, int pos)
{
	return _vec_insert_private(v, elem, size, pos, 0, 1);
}

int wget_vector_insert_noalloc(wget_vector_t *v, const void *elem, int pos)
{
	return _vec_insert_private(v, elem, 0, pos, 0, 0);
}

static int G_GNUC_WGET_NONNULL((2)) _vec_insert_sorted_private(wget_vector_t *v, const void *elem, size_t size, int alloc)
{
	int m = 0;

	if (!v) return -1;

	if (!v->cmp)
		return _vec_insert_private(v, elem, size, v->cur, 0, alloc);

	if (!v->sorted) wget_vector_sort(v);
	// vec_sort will leave v->sorted alone if it fails, so check again
	if (v->sorted) {
		// binary search for element
		int l = 0, r = v->cur - 1, res = 0;

		while (l <= r) {
			m = (l + r) / 2;
			if ((res = v->cmp(elem, v->entry[m])) > 0) l = m + 1;
			else if (res < 0) r = m - 1;
			else return _vec_insert_private(v, elem, size, m, 0, alloc);
		}
		if (res > 0) m++;
	}
	return _vec_insert_private(v, elem, size, m, 0, alloc);
}

int wget_vector_insert_sorted(wget_vector_t *v, const void *elem, size_t size)
{
	return _vec_insert_sorted_private(v, elem, size, 1);
}

int wget_vector_insert_sorted_noalloc(wget_vector_t *v, const void *elem)
{
	return _vec_insert_sorted_private(v, elem, 0, 0);
}

int wget_vector_add(wget_vector_t *v, const void *elem, size_t size)
{
	return v ? _vec_insert_private(v, elem, size, v->cur, 0, 1) : -1;
}

int wget_vector_add_noalloc(wget_vector_t *v, const void *elem)
{
	return v ? _vec_insert_private(v, elem, 0, v->cur, 0, 0) : -1;
}

static int _wget_vector_replace(wget_vector_t *v, const void *elem, size_t size, int pos, int alloc)
{
	if (!v || pos < 0 || pos >= v->cur) return -1;

	if (v->destructor)
		v->destructor(v->entry[pos]);

	xfree(v->entry[pos]);

	return _vec_insert_private(v, elem, size, pos, 1, alloc); // replace existing entry
}

int wget_vector_replace(wget_vector_t *v, const void *elem, size_t size, int pos)
{
	return _wget_vector_replace(v, elem, size, pos, 1);
}

int wget_vector_replace_noalloc(wget_vector_t *v, const void *elem, int pos)
{
	return _wget_vector_replace(v, elem, 0, pos, 0);
}

int wget_vector_add_vprintf(wget_vector_t *v, const char *fmt, va_list args)
{
	return wget_vector_add_noalloc(v, wget_vaprintf(fmt, args));
}

int wget_vector_add_printf(wget_vector_t *v, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int len = wget_vector_add_vprintf(v, fmt, args);
	va_end(args);

	return len;
}

int wget_vector_add_str(wget_vector_t *v, const char *s)
{
	return wget_vector_add(v, s, strlen(s) + 1);
}

static int _vec_remove_private(wget_vector_t *v, int pos, int free_entry)
{
	if (pos < 0 || !v || pos >= v->cur) return -1;

	if (free_entry) {
		if (v->destructor)
			v->destructor(v->entry[pos]);

		xfree(v->entry[pos]);
	}

	memmove(&v->entry[pos], &v->entry[pos + 1], (v->cur - pos - 1) * sizeof(void *));
	v->cur--;

	return pos;
}

int wget_vector_remove(wget_vector_t *v, int pos)
{
	return _vec_remove_private(v, pos, 1);
}

int wget_vector_remove_nofree(wget_vector_t *v, int pos)
{
	return _vec_remove_private(v, pos, 0);
}

int wget_vector_move(wget_vector_t *v, int old_pos, int new_pos)
{
	void *tmp;

	if (!v) return -1;
	if (old_pos < 0 || old_pos >= v->cur) return -1;
	if (new_pos < 0 || new_pos >= v->cur) return -1;
	if (old_pos == new_pos) return 0;

	if (v->sorted && v->cmp && v->cmp(v->entry[old_pos], v->entry[new_pos]))
		v->sorted = 0;

	if (old_pos < new_pos) {
		tmp = v->entry[old_pos];
		memmove(&v->entry[old_pos], &v->entry[old_pos + 1], (new_pos - old_pos) * sizeof(void *));
		v->entry[new_pos] = tmp;
	} else {
		tmp = v->entry[old_pos];
		memmove(&v->entry[new_pos + 1], &v->entry[new_pos], (old_pos - new_pos) * sizeof(void *));
		v->entry[new_pos] = tmp;
	}

	return 0;
}

int wget_vector_swap(wget_vector_t *v, int pos1, int pos2)
{
	void *tmp;

	if (!v) return -1;
	if (pos1 < 0 || pos1 >= v->cur) return -1;
	if (pos2 < 0 || pos2 >= v->cur) return -1;
	if (pos1 == pos2) return 0;

	tmp = v->entry[pos1];
	v->entry[pos1] = v->entry[pos2];
	v->entry[pos2] = tmp;

	if (v->sorted && v->cmp && v->cmp(v->entry[pos1], v->entry[pos2]))
		v->sorted = 0;

	return 0;
}

void wget_vector_free(wget_vector_t **v)
{
	if (v && *v) {
		if ((*v)->entry) {
			wget_vector_clear(*v);
			xfree((*v)->entry);
		}
		xfree(*v);
	}
}

// remove all elements

void wget_vector_clear(wget_vector_t *v)
{
	if (v) {
		int it;

		if (v->destructor) {
			for (it = 0; it < v->cur; it++) {
				v->destructor(v->entry[it]);
				xfree(v->entry[it]);
			}
		} else {
			for (it = 0; it < v->cur; it++)
				xfree(v->entry[it]);
		}

		v->cur = 0;
	}
}

void wget_vector_clear_nofree(wget_vector_t *v)
{
	if (v) {
		int it;

		for (it = 0; it < v->cur; it++)
			v->entry[it] = NULL;
		v->cur = 0;
	}
}

int wget_vector_size(const wget_vector_t *v)
{
	return v ? v->cur : 0;
}

void *wget_vector_get(const wget_vector_t *v, int pos)
{
	if (pos < 0 || !v || pos >= v->cur) return NULL;

	return v->entry[pos];
}

int wget_vector_browse(const wget_vector_t *v, wget_vector_browse_t browse, void *ctx)
{
	if (v) {
		int it, ret;

		for (it = 0; it < v->cur; it++)
			if ((ret = browse(ctx, v->entry[it])) != 0)
				return ret;
	}

	return 0;
}

void wget_vector_setcmpfunc(wget_vector_t *v, wget_vector_compare_t cmp)
{
	if (v) {
		v->cmp = cmp;

		if (v->cur == 1)
			v->sorted = 1;
		else
			v->sorted = 0;
	}
}

void wget_vector_set_destructor(wget_vector_t *v, wget_vector_destructor_t destructor)
{
	if (v)
		v->destructor = destructor;
}

static int G_GNUC_WGET_NONNULL_ALL _compare(const void *p1, const void *p2, void *v)
{
	return ((wget_vector_t *)v)->cmp(*((void **)p1), *((void **)p2));
}

void wget_vector_sort(wget_vector_t *v)
{
	if (v && v->cmp) {
		qsort_r(v->entry, v->cur, sizeof(void *), _compare, v);
		v->sorted = 1;
	}
}

// Find first entry that matches the specified element,
// using the compare function of the vector

int wget_vector_find(const wget_vector_t *v, const void *elem)
{
	if (v && v->cmp) {
		if (v->cur == 1) {
			if (v->cmp(elem, v->entry[0]) == 0) return 0;
		} else if (v->sorted) {
			int l, r, m;
			int res;

			// binary search for element (exact match)
			for (l = 0, r = v->cur - 1; l <= r;) {
				m = (l + r) / 2;
				if ((res = v->cmp(elem, v->entry[m])) > 0) l = m + 1;
				else if (res < 0) r = m - 1;
				else return m;
			}
		} else {
			int it;

			// linear search for element
			for (it = 0; it < v->cur; it++)
				if (v->cmp(elem, v->entry[it]) == 0) return it;
		}
	}

	return -1; // not found
}

int wget_vector_contains(const wget_vector_t *v, const void *elem)
{
	return wget_vector_find(v, elem) >= 0;
}

// Find entry, starting at specified position, scanning in the specified
// direction (0=up, 1=down) and using a custom function which returns 0
// when a matching element is passed to it.

int wget_vector_findext(const wget_vector_t *v, int start, int direction, wget_vector_find_t find)
{

	if (v) {
		if (direction) { // down
			if (start < v->cur) {
				for (int it = start; it >= 0; it--)
					if (find(v->entry[it]) == 0) return it;
			}
		} else { // up
			if (start >= 0) {
				for (int it = start; it < v->cur; it++)
					if (find(v->entry[it]) == 0) return it;
			}
		}
	}

	return -1;
}
