/*
 * Copyright(c) 2016 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * printf-style routines using buffer functions
 *
 * Changelog
 * 13.01.2016  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <libwget.h>
#include "private.h"

/**
 * SECTION:libwget-printf
 * @short_description: Wget printf functions
 * @title: libwget-printf
 * @stability: stable
 * @include: libwget.h
 *
 * This is a collection of printf-style functions that are used with libwget and/or Wget code.
 * They may be useful to other developers that is why they are exported.
 */

/**
 * wget_vasprintf:
 * @strp: Pointer to hold the string output
 * @fmt: Printf-like format string
 * @ap: va_list object
 *
 * Prints arguments to allocated memory and 0-terminates it. The string is returned via the first argument.
 * It has to be free()'d by the caller when it is no longer needed.
 *
 * Returns: Length of the string returned via @strp.
 */
size_t wget_vasprintf(char **strp, const char *fmt, va_list args)
{
	wget_buffer_t buf;

	wget_buffer_init(&buf, NULL, 128);

	size_t len = wget_buffer_vprintf(&buf, fmt, args);

	if (strp) {
		// shrink memory to real usage
		*strp = xrealloc(buf.data, len + 1);
	} else {
		// behave like C99/POSIX snprintf - just return the length
		xfree(buf.data);
	}

	return len;
}

/**
 * wget_asprintf:
 * @strp: Pointer to hold the string output
 * @fmt: Printf-like format string
 * @...: List of arguments
 *
 * Prints arguments to allocated memory and 0-terminates it. The string is returned via the first argument.
 * It has to be free()'d by the caller when it is no longer needed.
 *
 * Returns: Length of the string returned via @strp.
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
 * wget_str_vasprintf:
 * @fmt: Printf-like format string
 * @ap: va_list object
 *
 * Prints arguments to memory and returns a pointer to allocated and 0-terminated chunk of memory
 * or %NULL on error. The return value has to be free()'d by the caller when it is no longer needed.
 *
 * Returns: Pointer to 0-terminated string in memory.
 */
char *wget_str_vasprintf(const char *fmt, va_list args)
{
	char *s;

	wget_vasprintf(&s, fmt, args);

	return s;
}

/**
 * wget_str_asprintf:
 * @fmt: Printf-like format string
 * @...: List of arguments
 *
 * Prints arguments to memory and returns a pointer to allocated and 0-terminated chunk of memory
 * or %NULL on error. The return value has to be free()'d by the caller when it is no longer needed.
 *
 * Returns: Pointer to 0-terminated string in memory.
 */
char *wget_str_asprintf(const char *fmt, ...)
{
	va_list args;
	char *s;

	va_start(args, fmt);
	wget_vasprintf(&s, fmt, args);
	va_end(args);

	return s;
}
