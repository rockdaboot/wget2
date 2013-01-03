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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libmget.h>

#include "xalloc.h"
#include "utils.h"
#include "buffer.h"

//#define ALIGNMENT 16
//#define PADDING(n) ((n) + (ALIGNMENT - (n)%ALIGNMENT))

mget_buffer_t *buffer_init(mget_buffer_t *buf, char *data, size_t size)
{
	if (!buf) {
		buf = xmalloc(sizeof(mget_buffer_t));
		buf->release_buf = 1;
	} else
		buf->release_buf = 0;

	if (data) {
		if (likely(size))
			buf->size = size - 1;
		buf->data = data;
		buf->release_data = 0;
		*buf->data = 0; // always 0 terminate data to allow string functions
	} else {
		if (!size)
			size = 128;
		buf->size = size;
		buf->data = xmalloc(size + 1);
		buf->release_data = 1;
		*buf->data = 0; // always 0 terminate data to allow string functions
	}

	buf->length = 0;

	return buf;
}

mget_buffer_t *buffer_alloc(size_t size)
{
	return buffer_init(NULL, NULL, size);
}

void buffer_realloc(mget_buffer_t *buf, size_t size)
{
	const char *old_data = buf->data;

	buf->size = size;
	// buf->size = buf->size ? (size / buf->size + 1) * buf->size : size;
	buf->data = xmalloc(buf->size + 1);

	if (likely(old_data)) {
		if (buf->length)
			memcpy(buf->data, old_data, buf->length + 1);
		else
			*buf->data = 0; // always 0 terminate data to allow string functions

		if (buf->release_data)
			xfree(old_data);
	} else
		*buf->data = 0; // always 0 terminate data to allow string functions

	buf->release_data = 1;
}

void buffer_ensure_capacity(mget_buffer_t *buf, size_t size)
{
	if (buf->size < size)
		buffer_realloc(buf, size);
}

void buffer_free(mget_buffer_t **buf)
{
	if (likely(buf && *buf)) {
		if ((*buf)->release_data) {
			xfree((*buf)->data);
			(*buf)->release_data = 0;
		}

		if ((*buf)->release_buf)
			xfree(*buf);
	}
}

void buffer_deinit(mget_buffer_t *buf)
{
	buffer_free(&buf);
}

void buffer_free_data(mget_buffer_t *buf)
{
	if (likely(buf)) {
		if (buf->release_data) {
			xfree(buf->data);
			buf->release_data = 0;
		}
	}
}

size_t buffer_memcpy(mget_buffer_t *buf, const void *data, size_t length)
{
	buf->length = 0;

	return buffer_memcat(buf, data, length);
}

size_t buffer_memcat(mget_buffer_t *buf, const void *data, size_t length)
{
	if (length) {
		if (buf->size < buf->length + length)
			buffer_realloc(buf, buf->size * 2 + length);

		memcpy(buf->data + buf->length, data, length);
		buf->length += length;
	}
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return buf->length;
}

size_t buffer_strcpy(mget_buffer_t *buf, const char *s)
{
	buf->length = 0;

	return buffer_strcat(buf, s);
}

size_t buffer_strcat(mget_buffer_t *buf, const char *s)
{
	size_t length = strlen(s);

	if (length) {
		if (buf->size < buf->length + length)
			buffer_realloc(buf, buf->size * 2 + length);

		strcpy(buf->data + buf->length, s);
		buf->length += length;
	} else
		buf->data[buf->length] = 0;

	return buf->length;
}

size_t buffer_bufcpy(mget_buffer_t *buf, mget_buffer_t *src)
{
	return buffer_memcpy(buf, src->data, src->length);
}

size_t buffer_bufcat(mget_buffer_t *buf, mget_buffer_t *src)
{
	return buffer_memcat(buf, src->data, src->length);
}

size_t buffer_memset(mget_buffer_t *buf, char c, size_t length)
{
	buf->length = 0;

	return buffer_memset_append(buf, c, length);
}

size_t buffer_memset_append(mget_buffer_t *buf, char c, size_t length)
{
	if (likely(length)) {
		if (unlikely(buf->size < buf->length + length))
			buffer_realloc(buf, buf->size * 2 + length);

		memset(buf->data + buf->length, c, length);
		buf->length += length;
	}
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return buf->length;
}
