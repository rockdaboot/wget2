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
 * Header file for memory buffer routines
 *
 * Changelog
 * 22.08.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_BUFFER_H
#define _MGET_BUFFER_H

#include <stddef.h>

typedef struct {
	char
		*data;
	size_t
		length;
	size_t
		size;
	char
		allocated;
} buffer_t;


buffer_t
	*buffer_alloc(size_t size);
void
	buffer_init(buffer_t *buf, char *data, size_t size),
	buffer_ensure_capacity(buffer_t *buf, size_t size),
	buffer_free(buffer_t **buf),
	buffer_free_data(buffer_t *buf);
int
	buffer_append(buffer_t *buf, const void *data, size_t length);


#endif /* _MGET_BUFFER_H */
