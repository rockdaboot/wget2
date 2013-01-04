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
 * You should have received a copy of the GNU General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Double linked list routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <libmget.h>
#include "../include/libmget.h"

#include <xalloc.h>

/**
 * SECTION:libmget
 * @short_description: Double linked list routines
 * @title: libmget list routines
 * @stability: stable
 * @include: libmget.h
 *
 * Double linked lists provide fast insertion and removal and
 * iteration in either direction.
 *
 * Each entry has pointers to the next and the previous entry.
 * Iteration can be done by calling the mget_list_browse() function,
 * so the list structure doesn't need to be exposed.
 *
 * This datatype is used by the Mget tool to implement the job queue.
 *
 * See mget_list_append() for an example on how to use lists.
 */

struct _MGET_LISTNODE {
	MGET_LIST
		*next,
		*prev;
};

/**
 * mget_list_append:
 * @list: Pointer to Pointer to a double linked list.
 * @data: Pointer to data to be inserted.
 * @size: Size of data in bytes.
 *
 * Append an entry to the end of the list.
 * @size bytes at @data will be copied and appended to the list.
 *
 * A pointer to the new element will be returned.
 * It must be freed by mget_list_remove() or implicitely by mget_list_free().
 *
 * Returns: Pointer to the new element.
 *
 * <example>
 * <title>Example Usage</title>
 * <programlisting>
 *	MGET_LIST *list = NULL;
 *	struct mystruct mydata1 = { .x = 1, .y = 25 };
 *	struct mystruct mydata2 = { .x = 5, .y = 99 };
 *	struct mystruct *data;
 *
 *	mget_list_append(&list, &mydata1, sizeof(mydata1)); // append mydata1 to list
 *	mget_list_append(&list, &mydata2, sizeof(mydata2)); // append mydata2 to list
 *
 *	data = mget_list_getfirst(list);
 *	printf("data=(%d,%d)\n", data->x, data->y); // prints 'data=(1,25)'
 *
 *	mget_list_remove(&list, data);
 *
 *	data = mget_list_getfirst(list);
 *	printf("data=(%d,%d)\n", data->x, data->y); // prints 'data=(5,99)'
 *
 *	mget_list_free(&list);
 * </programlisting>
 * </example>
 */
void *
mget_list_append(MGET_LIST **list, const void *data, size_t size)
{
	// allocate space for node and data in one row
	MGET_LIST *node = xmalloc(sizeof(MGET_LIST) + size);

	memcpy(node + 1, data, size);

	if (!*list) {
		// <*list> is an empty list
		*list = node;
		node->next = node->prev = node;
	} else {
		node->next = *list;
		node->prev = (*list)->prev;
		(*list)->prev->next = node;
		(*list)->prev = node;
	}

	return node + 1;
}

/**
 * mget_list_prepend:
 * @list: Pointer to Pointer to a double linked list.
 * @data: Pointer to data to be inserted.
 * @size: Size of data in bytes.
 *
 * Insert an entry at the beginning of the list.
 * @size bytes at @data will be copied and prepended to the list.
 *
 * A pointer to the new element will be returned.
 * It must be freed by mget_list_remove() or implicitely by mget_list_free().
 *
 * Returns: Pointer to the new element.
 */
void *mget_list_prepend(MGET_LIST **list, const void *data, size_t size)
{
	if (!*list) {
		return mget_list_append(list, data, size);
	} else {
		return mget_list_append(&(*list)->prev, data, size);
	}
}

/**
 * mget_list_remove:
 * @list: Pointer to Pointer to a double linked list.
 * @elem: Pointer to a list element returned by mget_list_append() or mget_list_prepend().
 *
 * Remove an entry from the list.
 */
void mget_list_remove(MGET_LIST **list, void *elem)
{
	MGET_LIST *node = ((MGET_LIST *)elem) - 1;

	if (node->prev == node->next && node == node->prev) {
		// removing the last node in the list
		if (list && *list && node == *list)
			*list = NULL;
	} else {
		node->prev->next = node->next;
		node->next->prev = node->prev;
		if (list && *list && node == *list)
			*list = node->next;
	}
	xfree(node);
}

/**
 * mget_list_getfirst:
 * @list: Pointer to a double linked list.
 *
 * Returns: Pointer to the first element of the list or %NULL if the list is empty.
 */
void *mget_list_getfirst(const MGET_LIST *list)
{
	return (void *)(list ? list + 1 : list);
}

/**
 * mget_list_getlast:
 * @list: Pointer to a double linked list.
 *
 * Returns: Pointer to the last element of the list or %NULL if the list is empty.
 */
void *mget_list_getlast(const MGET_LIST *list)
{
	return (void *)(list ? list->prev + 1 : list);
}

/**
 * mget_list_browse:
 * @list: Pointer to a double linked list.
 * @browse: Pointer to callback function which is called for every element in the list.
 * If the callback functions returns a value not equal to zero, browsing is stopped and
 * this value will be returned by mget_list_browse.
 * @context: The context handle that will be passed to the callback function.
 *
 * Returns: The return value of the last call to the browse function.
 *
 * <example>
 *  <title>Example Usage</title>
 *  <programlisting>
 * // assume that list contains C strings.
 * MGET_LIST *list = NULL;
 * static int print_elem(void *context, const char *elem)
 * {
 *	  printf("%s\n",elem);
 *	  return 0;
 * }
 *
 * void dump(MGET_LIST *list)
 * {
 *	  mget_list_browse(list, (int(*)(void *, void *))print_elem, NULL);
 * }
 *  </programlisting>
 * </example>
 */
int mget_list_browse(const MGET_LIST *list, int (*browse)(void *context, void *elem), void *context)
{
	int ret = 0;

	if (list) {
		const MGET_LIST *end = list->prev, *cur = list;

		while ((ret = browse(context, (void *)(cur + 1))) == 0 && cur != end)
			cur = cur->next;
	}

	return ret;
}

/**
 * mget_list_free:
 * @list: Pointer to Pointer to a double linked list.
 *
 * Freeing the list and it's entry.
 */
void mget_list_free(MGET_LIST **list)
{
	while (*list)
		mget_list_remove(list, *list + 1);
}

/*
void mget_list_dump(const MGET_LIST *list)
{
	if (list) {
		const MGET_LIST *cur = list;

		do {
			log_printf("%p: next %p prev %p\n", cur, cur->next, cur->prev);
			cur = cur->next;
		} while (cur != list);
	} else
		log_printf("empty\n");
}
*/
