/*
 * Copyright (c) 2016-2024 Free Software Foundation, Inc.
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
 * printf-style routines using buffer functions
 *
 * Changelog
 * 13.01.2016  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Libwget printf functions
 * \defgroup libwget-printf Libwget printf functions
 * @{
 *
 * This is a collection of printf-style functions that are used with libwget and/or Wget2 code.
 * They may be useful to other developers that is why they are exported.
 */

/**
 * \param[in] strp Pointer to hold the string output
 * \param[in] fmt Printf-like format specifier
 * \param[in] args va_list of arguments
 * \return Length of the string returned via \p strp or `(size_t) -1` on error
 *
 * Prints arguments to allocated memory and 0-terminates it. The string is returned via the first argument.
 * It has to be free()'d by the caller when it is no longer needed.
 */
size_t wget_vasprintf(char **strp, const char *fmt, va_list args)
{
	wget_buffer buf;

	wget_buffer_init(&buf, NULL, 128);

	size_t len = wget_buffer_vprintf(&buf, fmt, args);

	if (unlikely(buf.error)) {
		xfree(buf.data);
		return (size_t) -1;
	}

	if (strp) {
		// shrink memory to real usage
		*strp = wget_realloc(buf.data, len + 1);
	} else {
		// behave like C99/POSIX snprintf - just return the length
		xfree(buf.data);
	}

	return len;
}

/**
 * \param[in] strp Pointer to hold the string output
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 * \return Length of the string returned via \p strp
 *
 * Prints arguments to allocated memory and 0-terminates it. The string is returned via the first argument.
 * It has to be free()'d by the caller when it is no longer needed.
 */
size_t wget_asprintf(char **strp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	size_t len = wget_vasprintf(strp, fmt, args);
	va_end(args);

	return len;
}

/**
 * \param[in] fmt Printf-like format specifier
 * \param[in] args va_list of arguments
 * \return Pointer to 0-terminated string in memory
 *
 * Prints arguments to memory and returns a pointer to allocated and 0-terminated chunk of memory.
 * The return value has to be free()'d by the caller when it is no longer needed.
 */
char *wget_vaprintf(const char *fmt, va_list args)
{
	char *s = NULL;

	wget_vasprintf(&s, fmt, args);

	return s;
}

/**
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 * \return Pointer to 0-terminated string in memory
 *
 * Prints arguments to memory and returns a pointer to allocated and 0-terminated chunk of memory.
 * The return value has to be free()'d by the caller when it is no longer needed.
 */
char *wget_aprintf(const char *fmt, ...)
{
	va_list args;
	char *s = NULL;

	va_start(args, fmt);
	wget_vasprintf(&s, fmt, args);
	va_end(args);

	return s;
}

/**
 * \param[in] fp FILE pointer
 * \param[in] fmt Printf-like format specifier
 * \param[in] args List of arguments
 * \return Number of bytes written or -1 on error
 *
 * Prints arguments to stream \p fp and returns number of bytes written.
 */
size_t wget_vfprintf(FILE *fp, const char *fmt, va_list args)
{
	wget_buffer buf;
	char sbuf[1024];
	size_t rc;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	size_t len = wget_buffer_vprintf(&buf, fmt, args);

	if (unlikely(buf.error)) {
		wget_buffer_deinit(&buf);
		return (size_t) -1;
	}

	if (len > 0)
		rc = fwrite(buf.data, 1, len, fp);
	else
		rc = 0;

	wget_buffer_deinit(&buf);

	return rc;
}

/**
 * \param[in] fp FILE pointer
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 * \return Number of bytes written or -1 on error
 *
 * Prints arguments to stream \p fp and returns number of bytes written.
 */
size_t wget_fprintf(FILE *fp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	size_t rc = wget_vfprintf(fp, fmt, args);
	va_end(args);

	return rc;
}

/**
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 * \return Number of bytes written or -1 on error
 *
 * Prints arguments to `stdout` and returns number of bytes written.
 */
size_t wget_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	size_t rc = wget_vfprintf(stdout, fmt, args);
	va_end(args);

	return rc;
}

/**
 * \param[in] str Destination buffer
 * \param[in] size Size of \p str
 * \param[in] fmt Printf-like format specifier
 * \param[in] args List of arguments
 * \return Number of bytes written, or, on truncation, that would have been written
 *
 * Prints arguments to buffer \p str and returns number of bytes written,
 * or on truncation: that would have been written.
 *
 * If \p str is %NULL the return value are the number of bytes that would have been written.
 */
size_t wget_vsnprintf(char *str, size_t size, const char *fmt, va_list args)
{
	wget_buffer buf;

	wget_buffer_init(&buf, str, size);

	size_t len = wget_buffer_vprintf(&buf, fmt, args);

	if (unlikely(buf.error)) {
		wget_buffer_deinit(&buf);
		return (size_t) -1;
	}

	if (str) {
		if (buf.data == str) {
			buf.data = NULL;
		} else if (len < size) {
			memcpy(str, buf.data, len + 1);
		} else {
			memcpy(str, buf.data, size - 1);
			str[size - 1] = 0;
		}
	}

	wget_buffer_deinit(&buf);

	return len;
}

/**
 * \param[in] str Destination buffer
 * \param[in] size Size of \p str
 * \param[in] fmt Printf-like format specifier
 * \param[in] ... List of arguments
 * \return Number of bytes written, or, on truncation, that would have been written
 *
 * Prints arguments to buffer \p str and returns number of bytes written,
 * or on truncation: that would have been written.
 *
 * If \p str is %NULL the return value are the number of bytes that would have been written.
 */
size_t wget_snprintf(char *str, size_t size, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	size_t len = wget_vsnprintf(str, size, fmt, args);
	va_end(args);

	return len;
}

/**@}*/
