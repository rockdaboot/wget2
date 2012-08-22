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
 * Memory buffer datastructure routines
 *
 * Changelog
 * 22.08.2012  Tim Ruehsen  created
 *
 */

#include <stdlib.h>
#include <string.h>

#include "xalloc.h"
#include "log.h"
#include "buffer.h"

//#define ALIGNMENT 16
//#define PADDING(n) ((n) + (ALIGNMENT - (n)%ALIGNMENT))

void buffer_init(buffer_t *buf, char *data, size_t size)
{
	buf->data = data;
	buf->length = 0;
	buf->size = size;
	buf->allocated = 0;

	if (buf->data)
		*buf->data = 0; // always 0 terminate data to allow string functions
}

buffer_t *buffer_alloc(size_t size)
{
	buffer_t *buf = xmalloc(sizeof(buffer_t));

	buffer_init(buf, xmalloc(size + 1), size);

	buf->allocated = 1;

	return buf;
}

static void _buffer_realloc(buffer_t *buf, size_t size)
{
	const char *old_data = buf->data;

	buf->size = buf->size ? (size / buf->size + 1) * buf->size : size;
	buf->data = xmalloc(buf->size + 1);

	if (old_data) {
		if (buf->length)
			memcpy(buf->data, old_data, buf->length);
		xfree(old_data);
	}

	*buf->data = 0; // always 0 terminate data to allow string functions
}

void buffer_ensure_capacity(buffer_t *buf, size_t size)
{
	if (buf->size < size)
		_buffer_realloc(buf, size);
}

void buffer_free(buffer_t **buf)
{
	if (buf && *buf) {
		xfree((*buf)->data);
		(*buf)->size = (*buf)->length = 0;

		if ((*buf)->allocated)
			xfree(*buf);
	}
}

void buffer_free_data(buffer_t *buf)
{
	if (buf) {
		xfree(buf->data);
		buf->size = buf->length = 0;
	}
}

int buffer_append(buffer_t *buf, const void *data, size_t length)
{
	if (buf->size < buf->length + length)
		_buffer_realloc(buf, buf->length + length);

	memcpy(buf->data + buf->length, data, length);
	buf->length += length;
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return 0;
}
