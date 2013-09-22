/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of Mget.
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
 * Mget header file
 *
 * Changelog
 * 11.01.2013  Tim Ruehsen  created
 *
 */

#ifndef _MGET_MGET_H
#define _MGET_MGET_H

#include <stddef.h>
#include <stdlib.h> // needed for free()

// I try to never leave freed pointers hanging around
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

void set_exit_status(int status);
const char * G_GNUC_MGET_NONNULL_ALL get_local_filename(MGET_IRI *iri);

#endif /* _MGET_SSL_H */
