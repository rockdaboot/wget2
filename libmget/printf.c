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
 * printf style routines
 *
 * Changelog
 * 11.06.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include <libmget.h>
#include "private.h"

#ifndef HAVE_DPRINTF

int vasprintf(char **buf, const char *fmt, va_list args)
{
	size_t len;
	char sbuf[4096];
	va_list args2;

	// vsnprintf destroys args, so we need a copy for the fallback cases
	va_copy(args2, args);

	// first try without malloc
	len = (ssize_t)vsnprintf(sbuf, sizeof(sbuf), fmt, args);

	if (len<sizeof(sbuf)) {
		// string fits into static buffer
		*buf = xmalloc(len + 1);
		strcpy(*buf, sbuf);
	} else if ((ssize_t)len != -1) {
		// POSIX compliant or glibc >= 2.1
		*buf = xmalloc(len + 1);
		len = vsnprintf(*buf, len + 1, fmt, args2);
	} else {
		// oldstyle with ugly try-and-error fallback (maybe just truncate the msg ?)
		size_t size = sizeof(sbuf)*2;
		*buf = NULL;

		do {
			xfree(*buf);
			*buf = xmalloc((size *= 2));
			va_copy(args, args2);
			len = vsnprintf(*buf, size, fmt, args);
		} while ((ssize_t)len == -1);
	}

	return(int)len;
}

int asprintf(char **buf, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	return vasprintf(buf, fmt, args);
	va_end(args);
}

#endif

// this is similar to vasprintf, but with buffer reuse

size_t vbsprintf(char **buf, size_t *bufsize, const char *fmt, va_list args)
{
	size_t len;
	va_list args2;

	// vsnprintf destroys args, so we need a copy for the fallback cases
	va_copy(args2, args);

	// first try without malloc
	len = (size_t)vsnprintf(*buf, *bufsize, fmt, args);

	if (len >= *bufsize) {
		// POSIX compliant or glibc >= 2.1
		xfree(*buf);
		*buf = xmalloc((*bufsize = len + 1));
		len = vsnprintf(*buf, *bufsize, fmt, args2);
	} else if ((ssize_t)len == -1) {
		// oldstyle with ugly try-and-error fallback (maybe just truncate the msg ?)
		*buf = NULL;
		do {
			xfree(*buf);
			*buf = xmalloc((*bufsize *= 2));
			va_copy(args, args2);
			len = vsnprintf(*buf, *bufsize, fmt, args);
		} while ((ssize_t)len == -1);
	}

	return len;
}

size_t bsprintf(char **buf, size_t *bufsize, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	return vbsprintf(buf, bufsize, fmt, args);
	va_end(args);
}

#ifndef HAVE_DPRINTF

// just a fallback, if dprintf/vdprintf do not exist

int vdprintf(int fd, const char *fmt, va_list args)
{
	size_t len, nbytes;
	ssize_t ret;
	char sbuf[4096], *buf = NULL;
	va_list args2;

	// vsnprintf destroys args, so we need a copy for the fallback cases
	va_copy(args2, args);

	// first try without malloc
	len = (ssize_t)vsnprintf(sbuf, sizeof(sbuf), fmt, args);

	if (len<sizeof(sbuf)) {
		// string fits into static buffer - most likely case
		buf = sbuf;
	} else if ((ssize_t)len != -1) {
		// POSIX compliant or glibc >= 2.1
		buf = xmalloc(len + 1);
		len = vsnprintf(buf, len + 1, fmt, args2);
	} else {
		// oldstyle with ugly try-and-error fallback (maybe just truncate the msg ?)
		size_t size = sizeof(sbuf)*2;

		do {
			xfree(buf);
			buf = xmalloc((size *= 2));
			va_copy(args, args2);
			len = vsnprintf(buf, size, fmt, args);
		} while ((ssize_t)len == -1);
	}

	for (nbytes = 0; nbytes < len; nbytes += ret) {
		if ((ret = write(fd, buf + nbytes, len - nbytes)) < 0)
			break;
	}

	if (buf != sbuf)
		xfree(buf);

	return(int)len;
}

int dprintf(int fd, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	return vdprintf(fd, fmt, args);
	va_end(args);
}
#endif // HAVE_DPRINTF
