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
 * Header file for list datastructure routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_LIST_H
#define _MGET_LIST_H

#include <stddef.h>

#include "mget.h"

typedef struct LISTNODE LIST;

void
	*list_append(LIST **list, const void *elem, size_t size) NONNULL_ALL,
	*list_prepend(LIST **list, const void *elem, size_t size) NONNULL_ALL,
	list_remove(LIST **list, void *elem);
void
	*list_getfirst(const LIST *list) CONST NONNULL_ALL,
	*list_getlast(const LIST *list) CONST NONNULL_ALL,
	list_free(LIST **list) NONNULL_ALL;
int
	list_browse(const LIST *list, int (*browse)(void *context, void *elem), void *context) NONNULL(2);


#endif /* _MGET_LIST_H */
