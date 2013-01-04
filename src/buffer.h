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
 * Header file for memory/string buffer routines
 *
 * Changelog
 * 22.08.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_BUFFER_H
#define _MGET_BUFFER_H

#include <stddef.h>
#include <stdarg.h>

typedef struct {
	char
		*data; // pointer to internal memory
	size_t
		length; // number of bytes in 'data'
	size_t
		size; // capacity of 'data' (terminating 0 byte doesn't count here)
	unsigned int
		release_data : 1, // 'data' has been malloc'ed and must be freed
		release_buf : 1; // buffer_t structure has been malloc'ed and must be freed
} mget_buffer_t;


mget_buffer_t
	*buffer_init(mget_buffer_t *buf, char *data, size_t size),
	*buffer_alloc(size_t size);
void
	buffer_ensure_capacity(mget_buffer_t *buf, size_t size) G_GNUC_MGET_NONNULL((1)),
	buffer_deinit(mget_buffer_t *buf) G_GNUC_MGET_NONNULL((1)),
	buffer_free(mget_buffer_t **buf) G_GNUC_MGET_NONNULL((1)),
	buffer_free_data(mget_buffer_t *buf) G_GNUC_MGET_NONNULL((1)),
	buffer_realloc(mget_buffer_t *buf, size_t size) G_GNUC_MGET_NONNULL((1));
size_t
	buffer_memcpy(mget_buffer_t *buf, const void *data, size_t length) G_GNUC_MGET_NONNULL((1,2)),
	buffer_memcat(mget_buffer_t *buf, const void *data, size_t length) G_GNUC_MGET_NONNULL((1,2)),
	buffer_strcpy(mget_buffer_t *buf, const char *s) G_GNUC_MGET_NONNULL((1,2)),
	buffer_strcat(mget_buffer_t *buf, const char *s) G_GNUC_MGET_NONNULL((1,2)),
	buffer_bufcpy(mget_buffer_t *buf, mget_buffer_t *src) G_GNUC_MGET_NONNULL((1,2)),
	buffer_bufcat(mget_buffer_t *buf, mget_buffer_t *src) G_GNUC_MGET_NONNULL((1,2)),
	buffer_memset(mget_buffer_t *buf, char c, size_t length) G_GNUC_MGET_NONNULL((1)),
	buffer_memset_append(mget_buffer_t *buf, char c, size_t length) G_GNUC_MGET_NONNULL((1)),

	buffer_vprintf_append(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0),
	buffer_printf_append(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3),
	buffer_vprintf(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0),
	buffer_printf(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3),

	buffer_vprintf_append2(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0),
	buffer_printf_append2(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3),
	buffer_vprintf2(mget_buffer_t *buf, const char *fmt, va_list args) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,0),
	buffer_printf2(mget_buffer_t *buf, const char *fmt, ...) G_GNUC_MGET_NONNULL((1,2)) G_GNUC_MGET_PRINTF_FORMAT(2,3);


#endif /* _MGET_BUFFER_H */
