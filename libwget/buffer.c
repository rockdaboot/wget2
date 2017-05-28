/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Memory buffer data structure routines
 *
 * Changelog
 * 22.08.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <wget.h>
#include "private.h"

wget_buffer_t *wget_buffer_init(wget_buffer_t *buf, char *data, size_t size)
{
	if (!buf) {
		buf = xmalloc(sizeof(wget_buffer_t));
		buf->release_buf = 1;
	} else
		buf->release_buf = 0;

	if (data && likely(size)) {
		buf->size = size - 1;
		buf->data = data;
		*buf->data = 0; // always 0 terminate data to allow string functions
		buf->release_data = 0;
	} else {
		if (!size)
			size = 128;
		buf->size = size;
		buf->data = xmalloc(size + 1);
		*buf->data = 0; // always 0 terminate data to allow string functions
		buf->release_data = 1;
	}

	buf->length = 0;

	return buf;
}

wget_buffer_t *wget_buffer_alloc(size_t size)
{
	return wget_buffer_init(NULL, NULL, size);
}

static void _buffer_realloc(wget_buffer_t *buf, size_t size)
{
	const char *old_data = buf->data;

	buf->size = size;
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

void wget_buffer_ensure_capacity(wget_buffer_t *buf, size_t size)
{
	if (buf->size < size)
		_buffer_realloc(buf, size);
}

void wget_buffer_deinit(wget_buffer_t *buf)
{
	if (likely(buf)) {
		if (buf->release_data) {
			xfree(buf->data);
			buf->release_data = 0;
		}

		if (buf->release_buf)
			xfree(buf);
	}
}

void wget_buffer_free(wget_buffer_t **buf)
{
	if (likely(buf)) {
		wget_buffer_deinit(*buf);
		*buf = NULL;
	}
}

void wget_buffer_free_data(wget_buffer_t *buf)
{
	if (likely(buf)) {
		if (buf->release_data) {
			xfree(buf->data);
			buf->release_data = 0;
			buf->size = 0;
		}
	}
}

void wget_buffer_reset(wget_buffer_t *buf)
{
	buf->length = 0;
	*buf->data = 0;
}

size_t wget_buffer_memcpy(wget_buffer_t *buf, const void *data, size_t length)
{
	buf->length = 0;

	return wget_buffer_memcat(buf, data, length);
}

size_t wget_buffer_memcat(wget_buffer_t *buf, const void *data, size_t length)
{
	if (length) {
		if (buf->size < buf->length + length)
			_buffer_realloc(buf, buf->size * 2 + length);

		memcpy(buf->data + buf->length, data, length);
		buf->length += length;
	}
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return buf->length;
}

size_t wget_buffer_strcpy(wget_buffer_t *buf, const char *s)
{
	buf->length = 0;

	return wget_buffer_memcat(buf, s, strlen(s));
}

size_t wget_buffer_strcat(wget_buffer_t *buf, const char *s)
{
	return wget_buffer_memcat(buf, s, strlen(s));
}

size_t wget_buffer_bufcpy(wget_buffer_t *buf, wget_buffer_t *src)
{
	return wget_buffer_memcpy(buf, src->data, src->length);
}

size_t wget_buffer_bufcat(wget_buffer_t *buf, wget_buffer_t *src)
{
	return wget_buffer_memcat(buf, src->data, src->length);
}

size_t wget_buffer_memset(wget_buffer_t *buf, char c, size_t length)
{
	buf->length = 0;

	return wget_buffer_memset_append(buf, c, length);
}

size_t wget_buffer_memset_append(wget_buffer_t *buf, char c, size_t length)
{
	if (likely(length)) {
		if (unlikely(buf->size < buf->length + length))
			_buffer_realloc(buf, buf->size * 2 + length);

		memset(buf->data + buf->length, c, length);
		buf->length += length;
	}
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return buf->length;
}

char *wget_buffer_trim(wget_buffer_t *buf)
{
	if (buf->length) {
		char *start = buf->data;
		char *end = start + buf->length - 1;

		if (isspace(*end)) {
			// skip trailing spaces
			for (; isspace(*end) && end >= start; end--)
				;
			end[1] = 0;
			buf->length = (size_t) (end - start + 1);
		}

		if (isspace(*start)) {
			// skip leading spaces
			for (; isspace(*start) && end >= start; start++)
				;
			buf->length = (size_t) (end - start + 1);
			memmove(buf->data, start, buf->length + 1); // include trailing 0
		}
	}

	return buf->data;
}
