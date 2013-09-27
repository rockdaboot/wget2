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
 * vector routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libmget.h>
#include "private.h"

struct _MGET_VECTOR {
	int
		(*cmp)(const void *, const void *); // comparison function
	void
		(*destructor)(void *); // element destructor function
	void
		**pl; // pointer to array of pointers to elements
	int
		max,     // allocated elements
		cur,     // number of elements in use
		off;     // number of elements to add if resize occurs
	char
		sorted; // 1=list is sorted, 0=list is not sorted
};

// create vector with initial size <max>
// vector growth is specified by off:
//   positive values: increase vector by <off> entries on each resize
//   negative values: increase vector by *<-off>, e.g. -2 doubles the size on each resize
// cmp: comparison function for sorting/finding, also needed for vec_insert_sorted*()
//      or NULL if not needed.
// the vector plus content is freed by vec_free()

MGET_VECTOR *mget_vector_create(int max, int off, int (*cmp)(const void *, const void *))
{
	MGET_VECTOR *v = xcalloc(1, sizeof(MGET_VECTOR));

	v->pl = xmalloc(max * sizeof(void *));
	v->max = max;
	v->off = off;
	v->cmp = cmp;

	return v;
}

static int G_GNUC_MGET_NONNULL((2)) _vec_insert_private(MGET_VECTOR *v, const void *elem, size_t size, int pos, int replace, int alloc)
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
				v->pl = xrealloc(v->pl, (v->max += v->off) * sizeof(void *));
			} else if (v->off<-1) {
				v->pl = xrealloc(v->pl, (v->max *= -v->off) * sizeof(void *));
			} else {
				if (alloc)
					free(elemp);
				return -1;
			}
		}

		memmove(&v->pl[pos + 1], &v->pl[pos], (v->cur - pos) * sizeof(void *));
		v->cur++;
	}

	v->pl[pos] = elemp;

	if (v->cmp) {
		if (v->cur == 1) v->sorted = 1;
		else if (v->cur > 1 && v->sorted) {
			if (pos == 0) {
				if (v->cmp(elem, v->pl[1]) > 0) v->sorted = 0;
			} else if (pos == v->cur - 1) {
				if (v->cmp(elem, v->pl[v->cur - 2]) < 0) v->sorted = 0;
			} else {
				if (v->cmp(elem, v->pl[pos - 1]) < 0 ||
					v->cmp(elem, v->pl[pos + 1]) > 0) {
					v->sorted = 0;
				}
			}
		}
	}

	return pos; // return position of new element
}

int mget_vector_insert(MGET_VECTOR *v, const void *elem, size_t size, int pos)
{
	return _vec_insert_private(v, elem, size, pos, 0, 1);
}

int mget_vector_insert_noalloc(MGET_VECTOR *v, const void *elem, int pos)
{
	return _vec_insert_private(v, elem, 0, pos, 0, 0);
}

static int G_GNUC_MGET_NONNULL((2)) _vec_insert_sorted_private(MGET_VECTOR *v, const void *elem, size_t size, int alloc)
{
	int m = 0;

	if (!v) return -1;

	if (!v->cmp)
		return _vec_insert_private(v, elem, size, v->cur, 0, alloc);

	if (!v->sorted) mget_vector_sort(v);
	// vec_sort will leave v->sorted alone if it fails, so check again
	if (v->sorted) {
		// binary search for element
		int l = 0, r = v->cur - 1, res = 0;

		while (l <= r) {
			m = (l + r) / 2;
			if ((res = v->cmp(elem, v->pl[m])) > 0) l = m + 1;
			else if (res < 0) r = m - 1;
			else return _vec_insert_private(v, elem, size, m, 0, alloc);
		}
		if (res > 0) m++;
	}
	return _vec_insert_private(v, elem, size, m, 0, alloc);
}

int mget_vector_insert_sorted(MGET_VECTOR *v, const void *elem, size_t size)
{
	return _vec_insert_sorted_private(v, elem, size, 1);
}

int mget_vector_insert_sorted_noalloc(MGET_VECTOR *v, const void *elem)
{
	return _vec_insert_sorted_private(v, elem, 0, 0);
}

int mget_vector_add(MGET_VECTOR *v, const void *elem, size_t size)
{
	return _vec_insert_private(v, elem, size, v->cur, 0, 1);
}

int mget_vector_add_noalloc(MGET_VECTOR *v, const void *elem)
{
	return _vec_insert_private(v, elem, 0, v->cur, 0, 0);
}

int mget_vector_replace(MGET_VECTOR *v, const void *elem, size_t size, int pos)
{
	if (!v || pos < 0 || pos >= v->cur) return -1;

	if (v->destructor)
		v->destructor(v->pl[pos]);

	xfree(v->pl[pos]);

	return _vec_insert_private(v, elem, size, pos, 1, 1); // replace existing entry
}

int mget_vector_add_vprintf(MGET_VECTOR *v, const char *fmt, va_list args)
{
	char *buf;

	if (vasprintf(&buf, fmt, args) != -1)
		return mget_vector_add_noalloc(v, buf);

	return -1;
}

int mget_vector_add_printf(MGET_VECTOR *v, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	return mget_vector_add_vprintf(v, fmt, args);
	va_end(args);
}

int mget_vector_add_str(MGET_VECTOR *v, const char *s)
{
	if (s)
		return mget_vector_add(v, s, strlen(s) + 1);
	else
		return -1;
}

static int _vec_remove_private(MGET_VECTOR *v, int pos, int free_entry)
{
	if (pos < 0 || !v || pos >= v->cur) return -1;

	if (free_entry) {
		if (v->destructor)
			v->destructor(v->pl[pos]);

		xfree(v->pl[pos]);
	}

	memmove(&v->pl[pos], &v->pl[pos + 1], (v->cur - pos - 1) * sizeof(void *));
	v->cur--;

	return pos;
}

int mget_vector_remove(MGET_VECTOR *v, int pos)
{
	return _vec_remove_private(v, pos, 1);
}

int mget_vector_remove_nofree(MGET_VECTOR *v, int pos)
{
	return _vec_remove_private(v, pos, 0);
}

int mget_vector_move(MGET_VECTOR *v, int old_pos, int new_pos)
{
	void *tmp;

	if (!v) return -1;
	if (old_pos < 0 || old_pos >= v->cur) return -1;
	if (new_pos < 0 || new_pos >= v->cur) return -1;
	if (old_pos == new_pos) return 0;

	if (v->sorted && v->cmp && v->cmp(v->pl[old_pos], v->pl[new_pos]))
		v->sorted = 0;

	if (old_pos < new_pos) {
		tmp = v->pl[old_pos];
		memmove(&v->pl[old_pos], &v->pl[old_pos + 1], (new_pos - old_pos) * sizeof(void *));
		v->pl[new_pos] = tmp;
	} else {
		tmp = v->pl[old_pos];
		memmove(&v->pl[new_pos + 1], &v->pl[new_pos], (old_pos - new_pos) * sizeof(void *));
		v->pl[new_pos] = tmp;
	}

	return 0;
}

int mget_vector_swap(MGET_VECTOR *v, int pos1, int pos2)
{
	void *tmp;

	if (!v) return -1;
	if (pos1 < 0 || pos1 >= v->cur) return -1;
	if (pos2 < 0 || pos2 >= v->cur) return -1;
	if (pos1 == pos2) return 0;

	tmp = v->pl[pos1];
	v->pl[pos1] = v->pl[pos2];
	v->pl[pos2] = tmp;

	if (v->sorted && v->cmp && v->cmp(v->pl[pos1], v->pl[pos2]))
		v->sorted = 0;

	return 0;
}

void mget_vector_free(MGET_VECTOR **v)
{
	if (v && *v) {
		if ((*v)->pl) {
			mget_vector_clear(*v);
			xfree((*v)->pl);
		}
		xfree(*v);
	}
}

// remove all elements

void mget_vector_clear(MGET_VECTOR *v)
{
	if (v) {
		int it;

		if (v->destructor) {
			for (it = 0; it < v->cur; it++) {
				v->destructor(v->pl[it]);
				xfree(v->pl[it]);
			}
		} else {
			for (it = 0; it < v->cur; it++)
				xfree(v->pl[it]);
		}

		v->cur = 0;
	}
}

void mget_vector_clear_nofree(MGET_VECTOR *v)
{
	if (v) {
		int it;

		for (it = 0; it < v->cur; it++)
			v->pl[it] = NULL;
		v->cur = 0;
	}
}

int mget_vector_size(const MGET_VECTOR *v)
{
	return v ? v->cur : 0;
}

void *mget_vector_get(const MGET_VECTOR *v, int pos)
{
	if (pos < 0 || !v || pos >= v->cur) return NULL;

	return v->pl[pos];
}

int mget_vector_browse(const MGET_VECTOR *v, int (*browse)(void *elem))
{
	if (v) {
		int it, ret;

		for (it = 0; it < v->cur; it++)
			if ((ret = browse(v->pl[it])) != 0)
				return ret;
	}

	return 0;
}

void mget_vector_setcmpfunc(MGET_VECTOR *v, int (*cmp)(const void *elem1, const void *elem2))
{
	if (v) {
		v->cmp = cmp;

		if (v->cur == 1)
			v->sorted = 1;
		else
			v->sorted = 0;
	}
}

void mget_vector_set_destructor(MGET_VECTOR *v, void (*destructor)(void *elem))
{
	if (v)
		v->destructor = destructor;
}

#if defined(__clang__)
void qsort_r (void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void *arg) G_GNUC_MGET_NONNULL((1,4));

static int G_GNUC_MGET_NONNULL_ALL _compare(const void *p1, const void *p2, void *v)
{
	return ((MGET_VECTOR *)v)->cmp(*((void **)p1), *((void **)p2));
}
#endif

void mget_vector_sort(MGET_VECTOR *v)
{
/*
 * without the intermediate _compare function below, v->cmp must take 'const void **elem{1|2}'
 * but than, the other calls to v->cmp must change as well
 *
 * to work lock-less (e.g. with a mutex), we need 'nested functions' (GCC, Intel, IBM)
 * or BLOCKS (clang) or the GNU libc extension qsort_r()
 *
 */
#if !defined(__clang__)
	int G_GNUC_MGET_NONNULL_ALL _compare(const void *p1, const void *p2)
	{
		return v->cmp(*((void **)p1), *((void **)p2));
	}

	if (v && v->cmp) {
		qsort(v->pl, v->cur, sizeof(void *), _compare);
		v->sorted = 1;
	}
#else
/*
	// this should work as soon as the qsort_b() function is available ;-)
	if (v && v->cmp) {
		int (^_compare)(const void *, const void *) = ^ int (const void *p1, const void *p2) {
			return v->cmp(*((void **)p1), *((void **)p2));
		};

		qsort_b(v->pl, v->cur, sizeof(void *), _compare);
		v->sorted = 1;
	}
*/
	if (v && v->cmp) {
		qsort_r(v->pl, v->cur, sizeof(void *), _compare, v);
		v->sorted = 1;
	}
#endif

}

// Find first entry that matches spth specified element,
// using the compare function of the vector

int mget_vector_find(const MGET_VECTOR *v, const void *elem)
{
	if (v && v->cmp) {
		if (v->cur == 1) {
			if (v->cmp(elem, v->pl[0]) == 0) return 0;
		} else if (v->sorted) {
			int l, r, m;
			int res;

			// binary search for element (exact match)
			for (l = 0, r = v->cur - 1; l <= r;) {
				m = (l + r) / 2;
				if ((res = v->cmp(elem, v->pl[m])) > 0) l = m + 1;
				else if (res < 0) r = m - 1;
				else return m;
			}
		} else {
			int it;

			// linear search for element
			for (it = 0; it < v->cur; it++)
				if (v->cmp(elem, v->pl[it]) == 0) return it;
		}
	}

	return -1; // not found
}

// Find entry, starting at specified position, scanning in the specified
// direction (0=up, 1=down) and using a custom function which returns 0
// when a matching element is passed to it.

int mget_vector_findext(const MGET_VECTOR *v, int start, int direction, int (*find)(void *))
{

	if (v) {
		int it;

		switch (direction) {
		case 0: // up
			if (start >= 0) {
				for (it = start; it < v->cur; it++)
					if (find(v->pl[it]) == 0) return it;
			}
			break;
		case 1: // down
			if (start < v->cur) {
				for (it = start; it >= 0; it--)
					if (find(v->pl[it]) == 0) return it;
			}
			break;
		}
	}

	return -1;
}
