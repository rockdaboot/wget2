/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Circular doubly linked list routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Circular doubly linked list routines
 * \defgroup libwget-list Circular doubly linked list
 * @{
 *
 * Circular doubly linked lists provide fast insertion, removal and
 * iteration in either direction.
 *
 * Each element has pointers to the next and the previous element.<br>
 * Iteration can be done by calling the wget_list_browse() function,
 * so the list structure doesn't need to be exposed.
 *
 * This datatype is used by the Wget2 tool to implement the job queue (append and remove).
 *
 * See wget_list_append() for an example on how to use lists.
 */

struct wget_list_st {
	wget_list
		*next,
		*prev;
};

/**
 * \param[in] list Pointer to Pointer to a circular doubly linked list
 * \param[in] data Pointer to data to be inserted
 * \param[in] size Size of data in bytes
 * \return Pointer to the new element or NULL if memory allocation failed
 *
 * Append an element to the end of the list.<br>
 * \p size bytes at \p data will be copied and appended to the list.
 *
 * A pointer to the new element will be returned.
 *
 * \note The returned pointer must be freed by wget_list_remove() or implicitly by wget_list_free().
 *
 * Example:
 *
 * \code{.c}
 *	wget_list *list = NULL;
 *	struct mystruct mydata1 = { .x = 1, .y = 25 };
 *	struct mystruct mydata2 = { .x = 5, .y = 99 };
 *	struct mystruct *data;
 *
 *	wget_list_append(&list, &mydata1, sizeof(mydata1)); // append mydata1 to list
 *	wget_list_append(&list, &mydata2, sizeof(mydata2)); // append mydata2 to list
 *
 *	data = wget_list_getfirst(list);
 *	printf("data=(%d,%d)\n", data->x, data->y); // prints 'data=(1,25)'
 *
 *	wget_list_remove(&list, data);
 *
 *	data = wget_list_getfirst(list);
 *	printf("data=(%d,%d)\n", data->x, data->y); // prints 'data=(5,99)'
 *
 *	wget_list_free(&list);
 * \endcode
 */
void *
wget_list_append(wget_list **list, const void *data, size_t size)
{
	// allocate space for node and data in one row
	wget_list *node = wget_malloc(sizeof(wget_list) + size);

	if (!node)
		return NULL;

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
 * \param[in] list Pointer to Pointer to a circular doubly linked list
 * \param[in] data Pointer to data to be inserted
 * \param[in] size Size of data in bytes
 * \return Pointer to the new element or NULL if memory allocation failed
 *
 * Insert an entry at the beginning of the list.
 * \p size bytes at \p data will be copied and prepended to the list.
 *
 * A pointer to the new element will be returned.
 * It must be freed by wget_list_remove() or implicitly by wget_list_free().
 */
void *wget_list_prepend(wget_list **list, const void *data, size_t size)
{
	if (!*list) {
		return wget_list_append(list, data, size);
	} else {
		return wget_list_append(&(*list)->prev, data, size);
	}
}

/**
 * \param[in] list Pointer to Pointer to a circular doubly linked list
 * \param[in] elem Pointer to a list element returned by wget_list_append() or wget_list_prepend()
 *
 * Remove an element from the list.
 */
void wget_list_remove(wget_list **list, void *elem)
{
	if (!*list)
		return;

	wget_list *node = ((wget_list *)elem) - 1;

	if (node == node->prev) {
		// removing the last node in the list
		*list = NULL;
	} else {
		node->prev->next = node->next;
		node->next->prev = node->prev;
		if (node == *list)
			*list = node->next;
	}
	xfree(node);
}

/**
 * \param[in] list Pointer to a circular doubly linked list
 * \return Pointer to the first element of the list or %NULL if the list is empty
 *
 * Get the first element of a list.
 */
void *wget_list_getfirst(const wget_list *list)
{
	return (void *)(list ? list + 1 : list);
}

/**
 * \param[in] list Pointer to a circular doubly linked list
 * \return Pointer to the last element of the list or %NULL if the list is empty
 *
 * Get the last element of a list.
 */
void *wget_list_getlast(const wget_list *list)
{
	return (void *)(list ? list->prev + 1 : list);
}

/**
 * \param[in] elem Pointer to an element of a linked list
 * \return Pointer to the next element of the list or %NULL if the list is empty
 *
 * Get the next element of a list.
 */
void *wget_list_getnext(const void *elem)
{
	if (elem) {
		wget_list *node = ((wget_list *)elem) - 1;
		return node->next + 1;
	}
	return NULL;
}

/**
 * \param[in] list Pointer to a circular doubly linked list
 * \param[in] browse Pointer to callback function which is called for every element in the list.
 *  If the callback functions returns a value not equal to zero, browsing is stopped and
 *  this value will be returned by wget_list_browse.
 * \param[in] context The context handle that will be passed to the callback function
 * \return The return value of the last call to the browse function or -1 if \p list is NULL (empty)
 *
 * Iterate through all entries of the \p list and call the function \p browse for each.
 *
 *
 * \code{.c}
 * // assume that list contains C strings.
 * wget_list *list = NULL;
 *
 * static int print_elem(void *context, const char *elem)
 * {
 *	  printf("%s\n",elem);
 *	  return 0;
 * }
 *
 * void dump(WGET_LIST *list)
 * {
 *	  wget_list_browse(list, (wget_list_browse_t)print_elem, NULL);
 * }
 * \endcode
 */
int wget_list_browse(const wget_list *list, wget_list_browse_fn *browse, void *context)
{
	if (!list)
		return -1;

	int ret;
	const wget_list *end = list->prev, *cur = list;

	while ((ret = browse(context, (void *)(cur + 1))) == 0 && cur != end)
		cur = cur->next;

	return ret;
}

/**
 * \param[in] list Pointer to Pointer to a circular doubly linked list
 *
 * Freeing the list and it's entry.
 */
void wget_list_free(wget_list **list)
{
	while (*list)
		wget_list_remove(list, *list + 1);
}

/*
void wget_list_dump(const WGET_LIST *list)
{
	if (list) {
		const wget_list *cur = list;

		do {
			debug_printf("%p: next %p prev %p\n", cur, cur->next, cur->prev);
			cur = cur->next;
		} while (cur != list);
	} else
		debug_printf("empty\n");
}
*/

/**@}*/
