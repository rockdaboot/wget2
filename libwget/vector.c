/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
		cur;     // number of elements in use
	bool
		sorted : 1; // 1=list is sorted, 0=list is not sorted
	float
		resize_factor; // factor to calculate new vector size
};

/**
 * \file
 * \brief Vector functions
 * \defgroup libwget-vector Vector functions
 * @{
 *
 * Functions to realize vectors (growable arrays).
 */

/**
 * \param[in] max Initial number of pre-allocated entries.
 * \param[in] cmp Comparison function for sorting/finding/sorted insertion or %NULL.
 * \return New vector instance
 *
 * Create a new vector instance, to be free'd after use with wget_vector_free().
 */
wget_vector_t *wget_vector_create(int max, wget_vector_compare_t cmp)
{
	wget_vector_t *v = xcalloc(1, sizeof(wget_vector_t));

	v->entry = xmalloc(max * sizeof(void *));
	v->max = max;
	v->resize_factor = 2;
	v->cmp = cmp;

	return v;
}

/**
 * \param[in] v Vector
 * \param[in] factor Vector growth factor
 *
 * Set the factor for resizing the vector when it is full.
 *
 * The new size is 'factor * oldsize'. If the new size is less or equal the old size,
 * the involved insertion function will return an error and the internal state of
 * the vector will not change.
 *
 * Default is 2.
 */
void wget_vector_set_resize_factor(wget_vector_t *v, float factor)
{
	if (v)
		v->resize_factor = factor;
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
			int newsize = (int) (v->max * v->resize_factor);

			if (newsize <= v->max) {
				if (alloc)
					free(elemp);
				return -1;
			}

			v->max = newsize;
			v->entry = xrealloc(v->entry, v->max * sizeof(void *));
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

/**
 * \param[in] v Vector where \p elem is inserted into
 * \param[in] elem Element to insert into \p v
 * \param[in] size Size of \p elem
 * \param[in] pos Position to insert \p elem at
 * \return Index of inserted element or -1 on error
 *
 * Insert \p elem of given \p size at index \p pos.
 *
 * \p elem is cloned / copied (shallow).
 *
 * An error is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
int wget_vector_insert(wget_vector_t *v, const void *elem, size_t size, int pos)
{
	return _vec_insert_private(v, elem, size, pos, 0, 1);
}

/**
 * \param[in] v Vector where \p elem is inserted into
 * \param[in] elem Element to insert into \p v
 * \param[in] pos Position to insert \p elem at
 * \return Index of inserted element or -1 on error
 *
 * Insert \p elem of at index \p pos.
 *
 * \p elem is *not* cloned, the vector takes 'ownership' of the element.
 *
 * An error is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
int wget_vector_insert_noalloc(wget_vector_t *v, const void *elem, int pos)
{
	return _vec_insert_private(v, elem, 0, pos, 0, 0);
}

static int G_GNUC_WGET_NONNULL((2)) _vec_insert_sorted_private(wget_vector_t *v, const void *elem, size_t size, int alloc)
{
	if (!v) return -1;

	if (!v->cmp)
		return _vec_insert_private(v, elem, size, v->cur, 0, alloc);

	if (!v->sorted)
		wget_vector_sort(v);

	// binary search for element
	int l = 0, r = v->cur - 1, m = 0, res = 0;

	while (l <= r) {
		m = (l + r) / 2;
		if ((res = v->cmp(elem, v->entry[m])) > 0) l = m + 1;
		else if (res < 0) r = m - 1;
		else return _vec_insert_private(v, elem, size, m, 0, alloc);
	}
	if (res > 0) m++;

	return _vec_insert_private(v, elem, size, m, 0, alloc);
}

/**
 * \param[in] v Vector where \p elem is inserted into
 * \param[in] elem Element to insert into \p v
 * \param[in] size Size of \p elem
 * \return Index of inserted element or -1 on error
 *
 * Insert \p elem of given \p size at a position that keeps the sort order of the elements.
 * If the vector has no comparison function, \p elem will be inserted as the last element.
 * If the elements in the vector are not sorted, they will be sorted after returning from this function.
 *
 * \p elem is cloned / copied (shallow).
 *
 * An error is returned if \p v is %NULL.
 */
int wget_vector_insert_sorted(wget_vector_t *v, const void *elem, size_t size)
{
	return _vec_insert_sorted_private(v, elem, size, 1);
}

/**
 * \param[in] v Vector where \p elem is inserted into
 * \param[in] elem Element to insert into \p v
 * \return Index of inserted element or -1 on error
 *
 * Insert \p elem of at a position that keeps the sort order of the elements.
 * If the vector has no comparison function, \p elem will be inserted as the last element.
 * If the elements in the vector are not sorted, they will be sorted after returning from this function.
 *
 * \p elem is *not* cloned, the vector takes 'ownership' of the element.
 *
 * An error is returned if \p v is %NULL.
 */
int wget_vector_insert_sorted_noalloc(wget_vector_t *v, const void *elem)
{
	return _vec_insert_sorted_private(v, elem, 0, 0);
}

/**
 * \param[in] v Vector where \p elem is appended to
 * \param[in] elem Element to append to a \p v
 * \param[in] size Size of \p elem
 * \return Index of appended element or -1 on error
 *
 * Append \p elem of given \p size to vector \p v.
 *
 * \p elem is cloned / copied (shallow).
 *
 * An error is returned if \p v is %NULL.
 */
int wget_vector_add(wget_vector_t *v, const void *elem, size_t size)
{
	return v ? _vec_insert_private(v, elem, size, v->cur, 0, 1) : -1;
}

/**
 * \param[in] v Vector where \p elem is appended to
 * \param[in] elem Element to append to a \p v
 * \return Index of appended element or -1 on error
 *
 * Append \p elem to vector \p v.
 *
 * \p elem is *not* cloned, the vector takes 'ownership' of the element.
 *
 * An error is returned if \p v is %NULL.
 */
int wget_vector_add_noalloc(wget_vector_t *v, const void *elem)
{
	return v ? _vec_insert_private(v, elem, 0, v->cur, 0, 0) : -1;
}

/**
 * \param[in] v Vector where \p s is appended to
 * \param[in] s String to append to \p v
 * \return Index of appended element or -1 on error
 *
 * Append string \p s as an element to vector \p v.
 *
 * \p s is cloned / copied.
 *
 * An error is returned if \p v or \p s is %NULL.
 */
int wget_vector_add_str(wget_vector_t *v, const char *s)
{
	return v && s ? _vec_insert_private(v, s, strlen(s) + 1, v->cur, 0, 1) : -1;
}

/**
 * \param[in] v Vector where \p s is appended to
 * \param[in] fmt Printf-like format string
 * \param[in] args Arguments for the \p fmt
 * \return Index of appended element or -1 on error
 *
 * Construct string in a printf-like manner and append it as an element to vector \p v.
 *
 * An error is returned if \p v or \p fmt is %NULL.
 */
int wget_vector_add_vprintf(wget_vector_t *v, const char *fmt, va_list args)
{
	return v && fmt ? _vec_insert_private(v, wget_vaprintf(fmt, args), 0, v->cur, 0, 0) : -1;
}

/**
 * \param[in] v Vector where \p s is appended to
 * \param[in] fmt Printf-like format string
 * \param[in] ... Arguments for the \p fmt
 * \return Index of appended element or -1 on error
 *
 * Construct string in a printf-like manner and append it as an element to vector \p v.
 *
 * An error is returned if \p v or \p fmt is %NULL.
 */
int wget_vector_add_printf(wget_vector_t *v, const char *fmt, ...)
{
	if (!v || !fmt)
		return -1;

	va_list args;

	va_start(args, fmt);
	int pos = _vec_insert_private(v, wget_vaprintf(fmt, args), 0, v->cur, 0, 0);
	va_end(args);

	return pos;
}

static int _wget_vector_replace(wget_vector_t *v, const void *elem, size_t size, int pos, int alloc)
{
	if (!v || pos < 0 || pos >= v->cur)
		return -1;

	if (v->destructor)
		v->destructor(v->entry[pos]);

	xfree(v->entry[pos]);

	return _vec_insert_private(v, elem, size, pos, 1, alloc); // replace existing entry
}

/**
 * \param[in] v Vector where \p elem is inserted
 * \param[in] elem Element to insert into \p v
 * \param[in] size Size of \p elem
 * \param[in] pos Position to insert \p elem at
 * \return Index of inserted element (same as \p pos) or -1 on error
 *
 * Replace the element at position \p pos with \p elem of given \p size.
 * If the vector has an element destructor function, this is called.
 * The old element is free'd.
 *
 * \p elem is cloned / copied (shallow).
 *
 * An error is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
int wget_vector_replace(wget_vector_t *v, const void *elem, size_t size, int pos)
{
	return _wget_vector_replace(v, elem, size, pos, 1);
}

/**
 * \param[in] v Vector where \p elem is inserted
 * \param[in] elem Element to insert into \p v
 * \param[in] pos Position to insert \p elem at
 * \return Index of inserted element (same as \p pos) or -1 on error
 *
 * Replace the element at position \p pos with \p elem.
 * If the vector has an element destructor function, this is called.
 * The old element is free'd.
 *
 * \p elem is *not* cloned, the vector takes 'ownership' of the element.
 *
 * An error is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
int wget_vector_replace_noalloc(wget_vector_t *v, const void *elem, int pos)
{
	return _wget_vector_replace(v, elem, 0, pos, 0);
}

static int _vec_remove_private(wget_vector_t *v, int pos, int free_entry)
{
	if (pos < 0 || !v || pos >= v->cur)
		return -1;

	if (free_entry) {
		if (v->destructor)
			v->destructor(v->entry[pos]);

		xfree(v->entry[pos]);
	}

	memmove(&v->entry[pos], &v->entry[pos + 1], (v->cur - pos - 1) * sizeof(void *));
	v->cur--;

	return pos;
}

/**
 * \param[in] v Vector to remove an element from
 * \param[in] pos Position of element to remove
 * \return Index of removed element (same as \p pos) or -1 on error
 *
 * Remove the element at position \p pos.
 * If the vector has an element destructor function, this is called.
 * The element is free'd.
 *
 * An error is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
int wget_vector_remove(wget_vector_t *v, int pos)
{
	return _vec_remove_private(v, pos, 1);
}

/**
 * \param[in] v Vector to remove an element from
 * \param[in] pos Position of element to remove
 * \return Index of removed element (same as \p pos) or -1 on error
 *
 * Remove the element at position \p pos.
 * No element destructor function is called, the element is not free'd.
 *
 * An error is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
int wget_vector_remove_nofree(wget_vector_t *v, int pos)
{
	return _vec_remove_private(v, pos, 0);
}

/**
 * \param[in] v Vector to act on
 * \param[in] old_pos Position to move element from
 * \param[in] new_pos Position to move element to
 * \return Index of new position (same as \p new_pos) or -1 on error
 *
 * Move the element at position \p old_pos to \p new_pos.
 *
 * Other elements may change the position.
 *
 * An error is returned if \p v is %NULL or either \p old_pos or
 * \p new_pos is out of range (< 0 or > # of entries).
 */
int wget_vector_move(wget_vector_t *v, int old_pos, int new_pos)
{
	if (!v) return -1;
	if (old_pos < 0 || old_pos >= v->cur) return -1;
	if (new_pos < 0 || new_pos >= v->cur) return -1;
	if (old_pos == new_pos) return new_pos;

	if (v->sorted && v->cmp && v->cmp(v->entry[old_pos], v->entry[new_pos]))
		v->sorted = 0;

	if (old_pos < new_pos) {
		void *tmp = v->entry[old_pos];
		memmove(&v->entry[old_pos], &v->entry[old_pos + 1], (new_pos - old_pos) * sizeof(void *));
		v->entry[new_pos] = tmp;
	} else {
		void *tmp = v->entry[old_pos];
		memmove(&v->entry[new_pos + 1], &v->entry[new_pos], (old_pos - new_pos) * sizeof(void *));
		v->entry[new_pos] = tmp;
	}

	return new_pos;
}

/**
 * \param[in] v Vector to act on
 * \param[in] pos1 Position of element one
 * \param[in] pos2 Position of element two
 * \return Index of second position (same as \p pos2) or -1 on error
 *
 * Swap the two elements at position \p pos1 and \p pos2.
 *
 * An error is returned if \p v is %NULL or either \p pos1 or
 * \p pos2 is out of range (< 0 or > # of entries).
 */
int wget_vector_swap(wget_vector_t *v, int pos1, int pos2)
{
	if (!v) return -1;
	if (pos1 < 0 || pos1 >= v->cur) return -1;
	if (pos2 < 0 || pos2 >= v->cur) return -1;
	if (pos1 == pos2) return pos2;

	void *tmp = v->entry[pos1];
	v->entry[pos1] = v->entry[pos2];
	v->entry[pos2] = tmp;

	if (v->sorted && v->cmp && v->cmp(v->entry[pos1], v->entry[pos2]))
		v->sorted = 0;

	return pos2;
}

/**
 * \param[in] v Vector to be free'd
 *
 * Free the vector \p v and it's contents.
 *
 * For each element the destructor function is called and the element free'd thereafter.
 * Then the vector itself is free'd and set to %NULL.
 */
void wget_vector_free(wget_vector_t **v)
{
	if (v && *v) {
		wget_vector_clear(*v);
		xfree((*v)->entry);
		xfree(*v);
	}
}

/**
 * \param[in] v Vector to be cleared
 *
 * Free all elements of the vector \p v but not the vector itself.
 *
 * For each element the destructor function is called and the element free'd thereafter.
 * The vector is then empty and can be reused.
 */
void wget_vector_clear(wget_vector_t *v)
{
	if (v) {
		if (v->destructor) {
			for (int it = 0; it < v->cur; it++) {
				v->destructor(v->entry[it]);
				xfree(v->entry[it]);
			}
		} else {
			for (int it = 0; it < v->cur; it++)
				xfree(v->entry[it]);
		}

		v->cur = 0;
	}
}

/**
 * \param[in] v Vector to be cleared
 *
 * Remove all elements of the vector \p v without free'ing them.
 * The caller is responsible to care for the elements.
 *
 * The vector is then empty and can be reused.
 */
void wget_vector_clear_nofree(wget_vector_t *v)
{
	if (v) {
		for (int it = 0; it < v->cur; it++)
			v->entry[it] = NULL;
		v->cur = 0;
	}
}

/**
 * \param[in] v Vector
 * \return The number of elements in the vector \p v
 *
 * Retrieve the number of elements of the vector \p v.
 * If \p v is %NULL, 0 is returned.
 */
int wget_vector_size(const wget_vector_t *v)
{
	return v ? v->cur : 0;
}

/**
 * \param[in] v Vector
 * \param[in] pos Position of element to retrieve
 * \return The element at position \p pos or %NULL on error
 *
 * Retrieve the element at position \p pos.
 *
 * %NULL is returned if \p v is %NULL or \p pos is out of range (< 0 or > # of entries).
 */
void *wget_vector_get(const wget_vector_t *v, int pos)
{
	if (pos < 0 || !v || pos >= v->cur)
		return NULL;

	return v->entry[pos];
}

/**
 * \param[in] v Vector
 * \param[in] browse Function to be called for each element of \p v
 * \param[in] ctx Context variable use as param to \p browse
 * \return Return value of the last call to \p browse
 *
 * Call function \p browse for each element of vector \p v or until \p browse
 * returns a value not equal to zero.
 *
 * \p browse is called with \p ctx and the pointer to the current element.
 *
 * The return value of the last call to \p browse is returned or 0 if \p v is %NULL.
 */
int wget_vector_browse(const wget_vector_t *v, wget_vector_browse_t browse, void *ctx)
{
	if (v) {
		for (int ret, it = 0; it < v->cur; it++)
			if ((ret = browse(ctx, v->entry[it])) != 0)
				return ret;
	}

	return 0;
}

/**
 * \param[in] v Vector
 * \param[in] cmp Function to compare elements
 *
 * Set the compare function used by wget_vector_sort().
 */
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

/**
 * \param[in] v Vector
 * \param[in] destructor Function to be called for element destruction
 *
 * Set the destructor function that is called for each element to be removed.
 * It should not free the element (pointer) itself.
 */
void wget_vector_set_destructor(wget_vector_t *v, wget_vector_destructor_t destructor)
{
	if (v)
		v->destructor = destructor;
}

static int G_GNUC_WGET_NONNULL_ALL _compare(const void *p1, const void *p2, void *v)
{
	return ((wget_vector_t *)v)->cmp(*((void **)p1), *((void **)p2));
}

/**
 * \param[in] v Vector
 *
 * Sort the elements in vector \p v using the compare function.
 * Do nothing if \p v is %NULL or the compare function is not set.
 */
void wget_vector_sort(wget_vector_t *v)
{
	if (v && v->cmp) {
		qsort_r(v->entry, v->cur, sizeof(void *), _compare, v);
		v->sorted = 1;
	}
}

/**
 * \param[in] v Vector
 * \param[in] elem Element to search for
 * \return Index of the found element or -1 if not found
 *
 * Searches for the given element using the compare function of the vector.
 *
 * Returns -1 if \p v is %NULL or if the compare function is not set.
 */
int wget_vector_find(const wget_vector_t *v, const void *elem)
{
	if (v && v->cmp) {
		if (v->cur == 1) {
			if (v->cmp(elem, v->entry[0]) == 0) return 0;
		} else if (v->sorted) {
			// binary search for element (exact match)
			for (int l = 0, r = v->cur - 1; l <= r;) {
				int res, m = (l + r) / 2;
				if ((res = v->cmp(elem, v->entry[m])) > 0) l = m + 1;
				else if (res < 0) r = m - 1;
				else return m;
			}
		} else {
			// linear search for element
			for (int it = 0; it < v->cur; it++)
				if (v->cmp(elem, v->entry[it]) == 0) return it;
		}
	}

	return -1; // not found
}

/**
 * \param[in] v Vector
 * \param[in] elem Element to check for
 * \return 1 if element exists, else 0
 *
 * Checks whether the element \p elem exists or not.
 */
int wget_vector_contains(const wget_vector_t *v, const void *elem)
{
	return wget_vector_find(v, elem) >= 0;
}

/**
 * \param[in] v Vector
 * \param[in] start Index to start search from
 * \param[in] direction Direction of search
 * \param[in] find Function to be called for each element
 * \return Index of the found element or -1 if not found
 *
 * Call \p find for each element starting at \p start.
 * If \p find returns 0 the current index is returned.
 *
 * Returns -1 if \p v is %NULL or if the \p find didn't return 0.
 */
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

/**@}*/
