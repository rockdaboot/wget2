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
 * Header file for memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen  extracted from utils.h
 *
 */

#ifndef _MGET_XALLOC_H
#define _MGET_XALLOC_H

#include <stddef.h>
#include <stdlib.h> // needed for free()
#include <string.h> // needed for memcpy()

#include "mget.h"

#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

void
	*xmalloc(size_t size) MALLOC ALLOC_SIZE(1),
	*xcalloc(size_t nmemb, size_t size) MALLOC ALLOC_SIZE(1,2),
	*xrealloc(void *ptr, size_t size) ALLOC_SIZE(2),
	*xmemdup(const void *s, size_t n) MALLOC ALLOC_SIZE(2) NONNULL_ALL;
char
	*strndup(const char *s, size_t n) MALLOC NONNULL_ALL;

#endif /* _MGET_XALLOC_H */
