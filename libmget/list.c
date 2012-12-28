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
 * List datastructure routines
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

typedef struct LISTNODE LISTNODE;

struct LISTNODE {
	LISTNODE
		*next,
		*prev;
};

void *list_append(LISTNODE **list, const void *elem, size_t size)
{
	// allocate space for node and data in one row
	LISTNODE *node = xmalloc(sizeof(LISTNODE) + size);

	memcpy(node + 1, elem, size);

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

void *list_prepend(LISTNODE **list, const void *elem, size_t size)
{
	if (!*list) {
		return list_append(list, elem, size);
	} else {
		return list_append(&(*list)->prev, elem, size);
	}
}

void list_remove(LISTNODE **list, void *elem)
{
	LISTNODE *node = ((LISTNODE *)elem) - 1;

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

void *list_getfirst(const LISTNODE *list)
{
	return (void *)(list + 1);
}

void *list_getlast(const LISTNODE *list)
{
	return (void *)(list->prev + 1);
}

int list_browse(const LIST *list, int (*browse)(void *context, void *elem), void *context)
{
	int ret = 0;

	if (list) {
		const LISTNODE *end = list->prev, *cur = list;

		while ((ret = browse(context, (void *)(cur + 1))) == 0 && cur != end)
			cur = cur->next;
	}

	return ret;
}

void list_free(LIST **list)
{
	while (*list)
		list_remove(list, ((LISTNODE *) * list) + 1);
}

/*
void list_dump(const LIST *list)
{
	if (list) {
		const LISTNODE *cur = list;

		do {
			log_printf("%p: next %p prev %p\n", cur, cur->next, cur->prev);
			cur = cur->next;
		} while (cur != list);
	} else
		log_printf("empty\n");
}
*/
