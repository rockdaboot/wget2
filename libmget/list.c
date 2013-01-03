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

#include <xalloc.h>

/**
 * SECTION:libmget
 * @short_description: Double linked list routines
 * @title: libmget list routines
 * @stability: stable
 * @include: libmget.h
 *
 * Double linked lists are used by Mget to implement the job queue.\n
 * Fast insertion and removal, that's all we need here.
 *
 * See mget_list_append() for an example on how to use lists.
 **/

typedef struct _MGET_LISTNODE _MGET_LISTNODE;

struct _MGET_LISTNODE {
	_MGET_LISTNODE
		*next,
		*prev;
};

/**
 * mget_list_append:
 * @list Pointer to a double linked list.
 * @data Pointer to data to be inserted.
 * @size Size of data in bytes.
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
 *
 **/
void *mget_list_append(_MGET_LISTNODE **list, const void *data, size_t size)
{
	// allocate space for node and data in one row
	_MGET_LISTNODE *node = xmalloc(sizeof(_MGET_LISTNODE) + size);

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
 * @list Pointer to a double linked list.
 * @data Pointer to data to be inserted.
 * @size Size of data in bytes.
 *
 * Insert an entry at the beginning of the list.
 * @size bytes at @data will be copied and prepended to the list.
 *
 * A pointer to the new element will be returned.
 * It must be freed by mget_list_remove() or implicitely by mget_list_free().
 *
 * Returns: Pointer to the new element.
 *
 */
void *mget_list_prepend(_MGET_LISTNODE **list, const void *data, size_t size)
{
	if (!*list) {
		return mget_list_append(list, data, size);
	} else {
		return mget_list_append(&(*list)->prev, data, size);
	}
}

void mget_list_remove(_MGET_LISTNODE **list, void *elem)
{
	_MGET_LISTNODE *node = ((_MGET_LISTNODE *)elem) - 1;

	if (node->prev == node->next && node == node->prev) {
		// last node in list
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

void *mget_list_getfirst(const _MGET_LISTNODE *list)
{
	return (void *)(list + 1);
}

void *mget_list_getlast(const _MGET_LISTNODE *list)
{
	return (void *)(list->prev + 1);
}

int mget_list_browse(const MGET_LIST *list, int (*browse)(void *context, void *elem), void *context)
{
	int ret = 0;

	if (list) {
		const _MGET_LISTNODE *end = list->prev, *cur = list;

		while ((ret = browse(context, (void *)(cur + 1))) == 0 && cur != end)
			cur = cur->next;
	}

	return ret;
}

void mget_list_free(MGET_LIST **list)
{
	while (*list)
		mget_list_remove(list, ((_MGET_LISTNODE *) * list) + 1);
}

/*
void mget_list_dump(const MGET_LIST *list)
{
	if (list) {
		const _MGET_LISTNODE *cur = list;

		do {
			log_printf("%p: next %p prev %p\n", cur, cur->next, cur->prev);
			cur = cur->next;
		} while (cur != list);
	} else
		log_printf("empty\n");
}
*/
