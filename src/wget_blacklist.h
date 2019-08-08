/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for IRI blacklist routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#ifndef SRC_WGET_BLACKLIST_H
#define SRC_WGET_BLACKLIST_H

#include <wget.h>

void blacklist_init(void);
void blacklist_exit(void);
int in_blacklist(wget_iri *iri) WGET_GCC_NONNULL_ALL;
int blacklist_size(void) WGET_GCC_PURE;
wget_iri *blacklist_add(wget_iri *iri);
void blacklist_print(void);
void blacklist_free(void);

#endif /* SRC_WGET_BLACKLIST_H */
