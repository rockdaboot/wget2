/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
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

// just a fallback, if dprintf/vdprintf do not exist

int vdprintf(int fd, const char *fmt, va_list args)
{
	size_t nbytes;
	ssize_t ret;
	char sbuf[4096];
	mget_buffer_t buf;

	mget_buffer_init(&buf, sbuf, sizeof(sbuf));
	mget_buffer_vprintf2(&buf, fmt, args);

	for (nbytes = 0; nbytes < buf.length; nbytes += ret) {
		if ((ret = write(fd, buf.data + nbytes, buf.length - nbytes)) < 0)
			break;
	}

	mget_buffer_deinit(&buf);

	return (ret < 0 ? (int ) ret : (int) buf.length);
}

int dprintf(int fd, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int rc = vdprintf(fd, fmt, args);
	va_end(args);

	return rc;
}
#endif // HAVE_DPRINTF
