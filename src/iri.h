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
 * Header file for IRI/URI routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 * Resources:
 * RFC3986 / RFC3987
 *
 */

#ifndef _MGET_IRI_H
#define _MGET_IRI_H

#include <stddef.h>
#include "buffer.h"

extern const char
	* const iri_schemes[];

#define IRI_SCHEME_HTTP    (iri_schemes[0])
#define IRI_SCHEME_HTTPS   (iri_schemes[1])
#define IRI_SCHEME_FTP     (iri_schemes[2])
#define IRI_SCHEME_DEFAULT IRI_SCHEME_HTTP

typedef struct {
	const char
		*uri,      // pointer to original URI string
		*display,
		*scheme,
		*userinfo,
		*password,
		*host, // unescaped
		*port,
		*path, // unescaped
		*query, // unescaped
		*fragment, // unescaped
		*connection_part; // helper, e.g. http://www.example.com:8080
} IRI;

void
	iri_test(void),
	iri_free(IRI **iri),
	iri_set_defaultpage(const char *page);
int
	iri_isgendelim(char c) CONST,
	iri_issubdelim(char c) CONST,
	iri_isreserved(char c) CONST,
	iri_isunreserved(char c) CONST,
	iri_isunreserved_path(char c) CONST,
	iri_compare(IRI *iri1, IRI *iri2) PURE NONNULL_ALL;
IRI
	*iri_parse(const char *s) MALLOC;
const char
	*iri_get_connection_part(IRI *iri),
	*iri_relative_to_absolute(IRI *base, const char *val, size_t len, buffer_t *buf),
	*iri_escape(const char *src, buffer_t *buf) NONNULL_ALL,
	*iri_escape_path(const char *src, buffer_t *buf) NONNULL_ALL,
	*iri_escape_query(const char *src, buffer_t *buf) NONNULL_ALL,
	*iri_get_escaped_host(const IRI *iri, buffer_t *buf) NONNULL_ALL,
	*iri_get_escaped_resource(const IRI *iri, buffer_t *buf) NONNULL_ALL,
	*iri_get_escaped_path(const IRI *iri, buffer_t *buf) NONNULL_ALL,
	*iri_get_escaped_query(const IRI *iri, buffer_t *buf) NONNULL_ALL,
	*iri_get_escaped_fragment(const IRI *iri, buffer_t *buf) NONNULL_ALL,
	*iri_get_escaped_file(const IRI *iri, buffer_t *buf) NONNULL_ALL;

#endif /* _MGET_IRI_H */
