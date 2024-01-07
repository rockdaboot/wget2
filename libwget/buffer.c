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

/**
 * \file
 * \brief Buffer management functions
 * \defgroup libwget-buffer Buffer management functions
 * @{
 *
 * A buffer (represented with an opaque `wget_buffer`) is a managed memory area.
 *
 * Apart from a pointer to a raw chunk of memory (`char *`), it also has some metadata attached
 * such as the length of the buffer and the actual occupied positions.
 *
 * Actually, when we talk about the **length** of the buffer, we refer to the actual number of bytes stored
 * in it by the user. On the other hand, the **size** is the total number of slots in the buffer, either occupied
 * or not.
 *
 * The stored data is always 0-terminated, so you safely use it with standard string functions.
 *
 * The functions here allow you to easily work with buffers, providing shortcuts to commonly used
 * memory and string management operations and avoiding usual pitfalls, such as buffer overflows.
 * They provide a higher-level abstraction to working with memory than the @link libwget-mem memory management functions@endlink.
 *
 * If your application uses memory allocation functions that may return %NULL values (e.g. like the standard libc functions),
 * you have to check the `error` value before using the result. If set, it indicates that a memory allocation failure
 * occurred during internal (re-)allocation.
 *
 * Example with wget_buffer on the stack (initial 16 bytes heap allocation)
 * ```
 * wget_buffer buf;
 *
 * wet_buffer_init(&buf, NULL, 16);
 *
 * wget_buffer_strcpy(&buf, "A");
 * wget_buffer_strcat(&buf, "B");
 * wget_buffer_memcat(&buf, "C", 1);
 * wget_buffer_memset_append(&buf, 'D', 1);
 * wget_buffer_printf_append(&buf, "%s", "E");
 *
 * // buf.data now contains the 0-terminated string "ABCDE"
 * printf("buf.data = %s\n", buf.data);
 *
 * wget_buffer_deinit(&buf);
 * ```
 *
 * Example with wget_buffer on the stack and 16 bytes initial stack buffer (no heap allocation is needed)
 * ```
 * wget_buffer buf;
 * char sbuf[16];
 *
 * wet_buffer_init(&buf, sbuf, sizeof(sbuf));
 *
 * wget_buffer_strcpy(&buf, "A");
 * wget_buffer_strcat(&buf, "B");
 * wget_buffer_memcat(&buf, "C", 1);
 * wget_buffer_memset_append(&buf, 'D', 1);
 * wget_buffer_printf_append(&buf, "%s", "E");
 *
 * // buf.data now contains the 0-terminated string "ABCDE"
 * printf("buf.data = %s\n", buf.data);
 *
 * wget_buffer_deinit(&buf);
 * ```
 *
 * Example on how to check for memory failure and how to transfer buffer data
 * ```
 * wget_buffer buf;
 *
 * wet_buffer_init(&buf, NULL, 16);
 *
 * wget_buffer_strcpy(&buf, "A");
 * wget_buffer_strcat(&buf, "B");
 * wget_buffer_memcat(&buf, "C", 1);
 * wget_buffer_memset_append(&buf, 'D', 1);
 * wget_buffer_printf_append(&buf, "%s", "E");
 *
 *	if (buf.error)
 *		panic("No memory !");
 *
 *	// transfer ownership away from wget_buffer
 *	char *ret = buf.data;
 *	buf.data = NULL; // avoid double frees
 *
 * wget_buffer_deinit(&buf);
 *
 *	return ret; // the caller must free() this value after use
 * ```
 */

/**
 * \param[in] buf Pointer to the buffer that should become initialized.
 * \param[in] data Initial contents of the buffer. Might be NULL.
 * \param[in] size Initial length of the buffer. Might be zero (will default to 128 bytes).
 * \return WGET_E_SUCCESS or WGET_E_MEMORY in case of a memory allocation failure.
 *
 * Create a new buffer.
 *
 * If \p data is NULL, the buffer will be empty, but it will be pre-allocated with \p size bytes.
 * This will make future operations on the buffer faster since there will be less re-allocations needed.
 *
 * <b>If \p size is zero, the buffer will be pre-allocated with 128 bytes.</b>
 *
 * You may provide some \p data to fill the buffer with it. The contents of the \p data pointer
 * are not copied, but rather the pointer itself is referenced directly within the buffer. If you modify the contents
 * of \p data, those changes will be reflected in the buffer as they both point to the same memory area.
 *
 * Apart from that, there are other concerns you should keep in mind if you provide your own \p data here:
 *
 *  - wget_buffer_deinit() _will not_ free that memory when you call it. So if you provide
 * a \p data pointer, you must free it yourself before your program ends.
 *  - wget_buffer_realloc() will also not free that memory. It will allocate a new buffer and copy the contents
 *  there, but will not touch the old buffer. The new buffer _will_ be freed by these functions since it's been
 *  allocated by libwget internally and thus it knows it can be freed without harm.
 *
 * If an existing buffer is provided in \p buf, it will be initialized with the provided \p data and \p size
 * according to the rules stated above.
 */
int wget_buffer_init(wget_buffer *buf, char *data, size_t size)
{
	if (data && likely(size)) {
		buf->size = size - 1;
		buf->data = data;
		*buf->data = 0; // always 0 terminate data to allow string functions
		buf->release_data = 0;
	} else {
		if (!size)
			size = 127;
		buf->size = size;
		if (!(buf->data = wget_malloc(size + 1))) {
			buf->error = 1;
			return WGET_E_MEMORY;
		}
		*buf->data = 0; // always 0 terminate data to allow string functions
		buf->release_data = 1;
	}

	buf->error = 0;
	buf->release_buf = 0;
	buf->length = 0;

	return WGET_E_SUCCESS;
}

/**
 * \param[in] size Initial length of the buffer.
 * \return A new buffer.
 *
 * Allocates a new buffer of size \p size bytes.
 *
 * The buffer will be pre-allocated with that many bytes, all zeros.
 *
 * This is equivalent to wget_buffer_init(NULL, NULL, size).
 */
wget_buffer *wget_buffer_alloc(size_t size)
{
	wget_buffer *buf;

	if (!(buf = wget_malloc(sizeof(wget_buffer))))
		return NULL;

	if (wget_buffer_init(buf, NULL, size) < 0) {
		xfree(buf);
		return NULL;
	}

	buf->release_buf = 1;

	return buf;
}

static int buffer_realloc(wget_buffer *buf, size_t size)
{
	char *old_data = buf->data;

	if (buf->release_data)
		buf->data = wget_realloc(buf->data, size + 1);
	else
		buf->data = wget_malloc(size + 1);

	if (!buf->data) {
		buf->data = old_data;
		buf->error = 1;
		return WGET_E_MEMORY;
	}

	if (!buf->release_data) {
		if (likely(old_data) && buf->length)
			memcpy(buf->data, old_data, buf->length + 1);
		else
			*buf->data = 0; // always 0 terminate data to allow string functions

		buf->release_data = 1;
	}

	buf->size = size;

	return WGET_E_SUCCESS;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] size Total size (in bytes) required in the buffer
 * \return WGET_E_SUCCESS on success, else WGET_E_MEMORY if the memory allocation failed
 *
 * Make sure the buffer \p buf has at least a **size** of \p size bytes.
 *
 * If the buffer's size is less than that, it will automatically enlarge it
 * (with wget_buffer_realloc()) to make it at least as long.
 */
int wget_buffer_ensure_capacity(wget_buffer *buf, size_t size)
{
	if (likely(buf)) {
		if (buf->size < size)
			return buffer_realloc(buf, size);
	}

	return WGET_E_SUCCESS;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 *
 * Free the buffer, and all its contents.
 *
 * If you provided your own data when calling wget_buffer_init() (you passed a non-NULL \p data pointer)
 * then **that buffer will not be freed**. As stated in the description of wget_buffer_init() you
 * must free that buffer yourself: this function will only free the `wget_buffer` structure.
 *
 * Similarly, if you provided your own buffer when calling wget_buffer_init() (\p buf was non-NULL)
 * the buffer (the `wget_buffer` structure) **will not** be freed, and the data might or might not be freed
 * depending on the above condition.
 */
void wget_buffer_deinit(wget_buffer *buf)
{
	if (buf->release_data) {
		xfree(buf->data);
		buf->release_data = 0;
	}

	if (buf->release_buf)
		wget_free(buf); // do not use xfree() since buf is NONNULL
}

/**
 * \param[in] buf A double pointer to a buffer
 *
 * Free the buffer, and all its contents.
 *
 * It behaves like wget_buffer_deinit() but it also sets the \p buf pointer to NULL.
 *
 * This function is equivalent to:
 *
 *     wget_buffer_deinit(*buf);
 *     *buf = NULL;
 */
void wget_buffer_free(wget_buffer **buf)
{
	if (likely(buf && *buf)) {
		wget_buffer_deinit(*buf);
		*buf = NULL;
	}
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 *
 * Release the buffer's data, but keep the buffer itself (the `wget_buffer` structure).
 *
 * The **length** of the buffer will be maintained, but after this function succeeds, the **size**
 * will obviously be zero.
 *
 * The same rules that apply to wget_buffer_deinit() also apply here: if you provided your own data
 * when calling wget_buffer_init() (ie. \p data was non-NULL) then **that data will not be freed**, and this
 * function will essentially be a no-op.
 */
void wget_buffer_free_data(wget_buffer *buf)
{
	if (likely(buf)) {
		if (buf->release_data) {
			xfree(buf->data);
			buf->release_data = 0;
			buf->size = 0;
		}
	}
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 *
 * This function is lighter than wget_buffer_free_data(). It does not free the data buffer, it just
 * sets its first byte to zero, as well as the length.
 *
 * This function is equivalent to:
 *
 *     buf->length = 0;
 *     *buf->data = 0;
 */
void wget_buffer_reset(wget_buffer *buf)
{
	if (likely(buf)) {
		buf->length = 0;
		*buf->data = 0;
	}
}

/**
 * \param[in] buf  A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] data A pointer to the data to be copied
 * \param[in] length How many bytes from \p data (starting at the beginning) should be copied
 * \return The new length of the buffer after copying the data
 *
 * Copy the contents in the pointer \p data to the buffer \p buf,
 * clobbering the previous contents.
 *
 * The first \p length bytes of \p data are written to \p buf.
 * The content of \p buf is overwritten with the new \p data.
 *
 * If the buffer is not large enough to store that amount of data,
 * it is enlarged automatically at least \p length bytes (with wget_buffer_realloc()).
 */
size_t wget_buffer_memcpy(wget_buffer *buf, const void *data, size_t length)
{
	if (unlikely(!buf))
		return 0;

	buf->length = 0;

	return wget_buffer_memcat(buf, data, length);
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] data A pointer to the data to be appended
 * \param[in] length How many bytes of \p data should be written to \p buf
 * \return The new length of the buffer after appending the data
 *
 * Append the provided \p data to the end of the buffer \p buf (preserving contents).
 *
 * If there's not enough space in \p buf, it is enlarged automatically
 * (with wget_buffer_realloc()) at least \p length bytes, so that the whole
 * data can be written.
 */
size_t wget_buffer_memcat(wget_buffer *buf, const void *data, size_t length)
{
	if (unlikely(!buf))
		return 0;

	if (likely(length)) {
		if (buf->size < buf->length + length)
			if (buffer_realloc(buf, buf->size * 2 + length) != WGET_E_SUCCESS)
				return buf->length;

		if (likely(data))
			memcpy(buf->data + buf->length, data, length);
		else
			memset(buf->data + buf->length, 0, length);
		buf->length += length;
	}
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return buf->length;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] s A NULL-terminated string
 * \return The new length of the buffer after copying the string
 *
 * Copy the NULL-terminated string \p s to the buffer \p buf,
 * overwriting its original contents.
 *
 * If the buffer is not large enough it is enlarged automatically.
 *
 * This is essentially equivalent to:
 *
 *     buf->length = 0;
 *     wget_buffer_memcat(buf, s, strlen(s));
 */
size_t wget_buffer_strcpy(wget_buffer *buf, const char *s)
{
	if (likely(buf))
		buf->length = 0;

	return wget_buffer_memcat(buf, s, likely(s) ? strlen(s) : 0);
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] s A NULL-terminated string
 * \return The new length of the buffer after appending the string
 *
 * Append the NULL-terminated string \p s to the end of the buffer  \p buf
 * (preserving its contents).
 *
 * If the buffer is not large enough it is enlarged automatically.
 *
 * This is essentially equivalent to calling wget_buffer_memcat() with length equal to `strlen(s)`:
 *
 *     wget_buffer_memcat(buf, s, strlen(s));
 */
size_t wget_buffer_strcat(wget_buffer *buf, const char *s)
{
	return wget_buffer_memcat(buf, s, likely(s) ? strlen(s) : 0);
}

/**
 * \param[in] buf The destination buffer
 * \param[in] src The source buffer
 * \return The new length of the destination buffer \p buf after copying the contents of \p src
 *
 * Copy the contents of the buffer \p src in the buffer \p buf,
 * clobbering its previous contents.
 *
 * If the buffer \p buf is not large enough it is enlarged automatically.
 *
 * This is equivalent to:
 *
 *     wget_buffer_memcpy(buf, src->data, src->length);
 */
size_t wget_buffer_bufcpy(wget_buffer *buf, wget_buffer *src)
{
	if (likely(src))
		return wget_buffer_memcpy(buf, src->data, src->length);
	else
		return wget_buffer_memcpy(buf, NULL, 0);
}

/**
 * \param[in] buf The destination buffer
 * \param[in] src The source buffer
 * \return The new length of the destination buffer \p buf after appending the contents of \p src
 *
 * Append the contents of the buffer \p src to the end of the buffer \p buf.
 *
 * If the buffer \p buf is not large enough it is enlarged automatically.
 *
 * This is equivalent to:
 *
 *     wget_buffer_memcat(buf, src->data, src->length);
 */
size_t wget_buffer_bufcat(wget_buffer *buf, wget_buffer *src)
{
	if (likely(src))
		return wget_buffer_memcat(buf, src->data, src->length);
	else
		return wget_buffer_memcat(buf, NULL, 0);
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] c The byte to be copied at the end of the buffer
 * \param[in] length How many times will the byte \p c be copied.
 * \return The new length of the buffer \p buf.
 *
 * Copy the byte \p c repeatedly \p length times **starting at the beginning of the buffer**,
 * so the first \p length bytes of the buffer are overwritten.
 *
 * If there's not enough space in \p buf, it is enlarged automatically
 * (with wget_buffer_realloc()) at least \p length bytes.
 */
size_t wget_buffer_memset(wget_buffer *buf, char c, size_t length)
{
	if (likely(buf))
		buf->length = 0;

	return wget_buffer_memset_append(buf, c, length);
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] c The byte to be copied at the end of the buffer
 * \param[in] length How many times will the byte \p c be copied.
 * \return The new length of the buffer \p buf.
 *
 * Copy the byte \p c at the end of the buffer \p buf repeatedly \p length times.
 *
 * If there's not enough space in \p buf, it is enlarged automatically
 * (with wget_buffer_realloc()) at least \p length bytes.
 */
size_t wget_buffer_memset_append(wget_buffer *buf, char c, size_t length)
{
	if (unlikely(!buf))
		return 0;

	if (likely(length)) {
		if (unlikely(buf->size < buf->length + length))
			if (buffer_realloc(buf, buf->size * 2 + length) != WGET_E_SUCCESS)
				return buf->length;

		memset(buf->data + buf->length, c, length);
		buf->length += length;
	}
	buf->data[buf->length] = 0; // always 0 terminate data to allow string functions

	return buf->length;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \return The buffer's new contents
 *
 * Remove all leading and trailing whitespace from the buffer \p buf.
 *
 * The transformation is done in-place, that is, the buffer's original content is overwritten
 * with the new trimmed content.
 */
char *wget_buffer_trim(wget_buffer *buf)
{
	if (unlikely(!buf))
		return NULL;

	while (buf->length > 0 && isspace(buf->data[buf->length - 1])) {
		buf->length--;
	}
	buf->data[buf->length] = 0;

	size_t spaces = 0;
	while (buf->length > 0 && isspace(buf->data[spaces]))
		spaces++;

	if (spaces) {
		buf->length -= spaces;
		/* Include trailing 0 */
		memmove(buf->data, buf->data + spaces, buf->length + 1);
	}

	return buf->data;
}
/** @} */
