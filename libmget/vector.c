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

struct _mget_vector_st {
	int
		(*cmp)(const void *, const void *); // comparison function
	void
		(*destructor)(void *); // element destructor function
	void
		**entry; // pointer to array of pointers to elements
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

mget_vector_t *mget_vector_create(int max, int off, int (*cmp)(const void *, const void *))
{
	mget_vector_t *v = xcalloc(1, sizeof(mget_vector_t));

	v->entry = xmalloc(max * sizeof(void *));
	v->max = max;
	v->off = off;
	v->cmp = cmp;

	return v;
}

static int G_GNUC_MGET_NONNULL((2)) _vec_insert_private(mget_vector_t *v, const void *elem, size_t size, int pos, int replace, int alloc)
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

int mget_vector_insert(mget_vector_t *v, const void *elem, size_t size, int pos)
{
	return _vec_insert_private(v, elem, size, pos, 0, 1);
}

int mget_vector_insert_noalloc(mget_vector_t *v, const void *elem, int pos)
{
	return _vec_insert_private(v, elem, 0, pos, 0, 0);
}

static int G_GNUC_MGET_NONNULL((2)) _vec_insert_sorted_private(mget_vector_t *v, const void *elem, size_t size, int alloc)
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
			if ((res = v->cmp(elem, v->entry[m])) > 0) l = m + 1;
			else if (res < 0) r = m - 1;
			else return _vec_insert_private(v, elem, size, m, 0, alloc);
		}
		if (res > 0) m++;
	}
	return _vec_insert_private(v, elem, size, m, 0, alloc);
}

int mget_vector_insert_sorted(mget_vector_t *v, const void *elem, size_t size)
{
	return _vec_insert_sorted_private(v, elem, size, 1);
}

int mget_vector_insert_sorted_noalloc(mget_vector_t *v, const void *elem)
{
	return _vec_insert_sorted_private(v, elem, 0, 0);
}

int mget_vector_add(mget_vector_t *v, const void *elem, size_t size)
{
	return v ? _vec_insert_private(v, elem, size, v->cur, 0, 1) : -1;
}

int mget_vector_add_noalloc(mget_vector_t *v, const void *elem)
{
	return v ? _vec_insert_private(v, elem, 0, v->cur, 0, 0) : -1;
}

static int _mget_vector_replace(mget_vector_t *v, const void *elem, size_t size, int pos, int alloc)
{
	if (!v || pos < 0 || pos >= v->cur) return -1;

	if (v->destructor)
		v->destructor(v->entry[pos]);

	xfree(v->entry[pos]);

	return _vec_insert_private(v, elem, size, pos, 1, alloc); // replace existing entry
}

int mget_vector_replace(mget_vector_t *v, const void *elem, size_t size, int pos)
{
	return _mget_vector_replace(v, elem, size, pos, 1);
}

int mget_vector_replace_noalloc(mget_vector_t *v, const void *elem, int pos)
{
	return _mget_vector_replace(v, elem, 0, pos, 0);
}

int mget_vector_add_vprintf(mget_vector_t *v, const char *fmt, va_list args)
{
	char *buf;

	if (vasprintf(&buf, fmt, args) != -1)
		return mget_vector_add_noalloc(v, buf);

	return -1;
}

int mget_vector_add_printf(mget_vector_t *v, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int len = mget_vector_add_vprintf(v, fmt, args);
	va_end(args);

	return len;
}

int mget_vector_add_str(mget_vector_t *v, const char *s)
{
	if (s)
		return mget_vector_add(v, s, strlen(s) + 1);
	else
		return -1;
}

static int _vec_remove_private(mget_vector_t *v, int pos, int free_entry)
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

int mget_vector_remove(mget_vector_t *v, int pos)
{
	return _vec_remove_private(v, pos, 1);
}

int mget_vector_remove_nofree(mget_vector_t *v, int pos)
{
	return _vec_remove_private(v, pos, 0);
}

int mget_vector_move(mget_vector_t *v, int old_pos, int new_pos)
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

int mget_vector_swap(mget_vector_t *v, int pos1, int pos2)
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

void mget_vector_free(mget_vector_t **v)
{
	if (v && *v) {
		if ((*v)->entry) {
			mget_vector_clear(*v);
			xfree((*v)->entry);
		}
		xfree(*v);
	}
}

// remove all elements

void mget_vector_clear(mget_vector_t *v)
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

void mget_vector_clear_nofree(mget_vector_t *v)
{
	if (v) {
		int it;

		for (it = 0; it < v->cur; it++)
			v->entry[it] = NULL;
		v->cur = 0;
	}
}

int mget_vector_size(const mget_vector_t *v)
{
	return v ? v->cur : 0;
}

void *mget_vector_get(const mget_vector_t *v, int pos)
{
	if (pos < 0 || !v || pos >= v->cur) return NULL;

	return v->entry[pos];
}

int mget_vector_browse(const mget_vector_t *v, int (*browse)(void *ctx, void *elem), void *ctx)
{
	if (v) {
		int it, ret;

		for (it = 0; it < v->cur; it++)
			if ((ret = browse(ctx, v->entry[it])) != 0)
				return ret;
	}

	return 0;
}

void mget_vector_setcmpfunc(mget_vector_t *v, int (*cmp)(const void *elem1, const void *elem2))
{
	if (v) {
		v->cmp = cmp;

		if (v->cur == 1)
			v->sorted = 1;
		else
			v->sorted = 0;
	}
}

void mget_vector_set_destructor(mget_vector_t *v, void (*destructor)(void *elem))
{
	if (v)
		v->destructor = destructor;
}

#if HAVE_QSORT_R_BSD
static int G_GNUC_MGET_NONNULL_ALL _compare(void *v, const void *p1, const void *p2)
{
	return ((mget_vector_t *)v)->cmp(*((void **)p1), *((void **)p2));
}
#elif HAVE_QSORT_R
static int G_GNUC_MGET_NONNULL_ALL _compare(const void *p1, const void *p2, void *v)
{
	return ((mget_vector_t *)v)->cmp(*((void **)p1), *((void **)p2));
}
#else
// fallback to non-reentrant code (e.g. for OpenBSD <= 5.8)
static mget_vector_t *_v;
static int G_GNUC_MGET_NONNULL_ALL _compare(const void *p1, const void *p2)
{
	return _v->cmp(*((void **)p1), *((void **)p2));
}
#endif

void mget_vector_sort(mget_vector_t *v)
{
/*
 * Without the intermediate _compare function below, v->cmp must take 'const void **elem{1|2}'
 * but than, the other calls to v->cmp must change as well.
 *
 * To work lock-less (e.g. with a mutex), we need 'nested functions' (GCC, Intel, IBM)
 * or BLOCKS (clang) or the GNU libc extension qsort_r().
 * Using BLOCKS would also need a qsort_b() function...
 *
 */
#if HAVE_QSORT_R_BSD
	if (v && v->cmp) {
		qsort_r(v->entry, v->cur, sizeof(void *), v, _compare);
		v->sorted = 1;
	}
#elif HAVE_QSORT_R
	if (v && v->cmp) {
		qsort_r(v->entry, v->cur, sizeof(void *), _compare, v);
		v->sorted = 1;
	}
#else
	// fallback to non-reentrant code (e.g. for OpenBSD <= 5.8)
	if (v && v->cmp) {
		static mget_thread_mutex_t
			mutex = MGET_THREAD_MUTEX_INITIALIZER;

		mget_thread_mutex_lock(&mutex);
		_v = v;
		qsort(v->entry, v->cur, sizeof(void *), _compare);
		v->sorted = 1;
		mget_thread_mutex_unlock(&mutex);
	}

#endif

/*
	// trampoline version (e.g. gcc, but not on OpenBSD !)
	int G_GNUC_MGET_NONNULL_ALL _compare(const void *p1, const void *p2)
	{
		return v->cmp(*((void **)p1), *((void **)p2));
	}

	if (v && v->cmp) {
		qsort(v->entry, v->cur, sizeof(void *), _compare);
		v->sorted = 1;
	}

	#error You need gcc or qsort_r() to build Mget
	// this should work as soon as the qsort_b() function is available ;-)
	if (v && v->cmp) {
		int (^_compare)(const void *, const void *) = ^ int (const void *p1, const void *p2) {
			return v->cmp(*((void **)p1), *((void **)p2));
		};

		qsort_b(v->pl, v->cur, sizeof(void *), _compare);
		v->sorted = 1;
	}
*/
}

// Find first entry that matches the specified element,
// using the compare function of the vector

int mget_vector_find(const mget_vector_t *v, const void *elem)
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

int mget_vector_contains(const mget_vector_t *v, const void *elem)
{
	return mget_vector_find(v, elem) >= 0;
}

// Find entry, starting at specified position, scanning in the specified
// direction (0=up, 1=down) and using a custom function which returns 0
// when a matching element is passed to it.

int mget_vector_findext(const mget_vector_t *v, int start, int direction, int (*find)(void *))
{

	if (v) {
		int it;

		switch (direction) {
		case 0: // up
			if (start >= 0) {
				for (it = start; it < v->cur; it++)
					if (find(v->entry[it]) == 0) return it;
			}
			break;
		case 1: // down
			if (start < v->cur) {
				for (it = start; it >= 0; it--)
					if (find(v->entry[it]) == 0) return it;
			}
			break;
		}
	}

	return -1;
}
