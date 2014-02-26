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
 * Header file for IRI blacklist routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_BLACKLIST_H
#define _MGET_BLACKLIST_H

#include <libmget.h>

int
	in_blacklist(mget_iri_t *iri) G_GNUC_MGET_NONNULL_ALL;
mget_iri_t
	*blacklist_add(mget_iri_t *iri);
void
	blacklist_print(void),
	blacklist_free(void);

#endif /* _MGET_BLACKLIST_H */
