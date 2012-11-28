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
 * Header file for list datastructure routines
 *
 * Changelog
 * 30.10.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_COOKIE_H
#define _MGET_COOKIE_H

#include <time.h>

#include "mget.h"
#include "iri.h"
#include "vector.h"

typedef struct {
	const char
		*name,
		*value,
		*domain,
		*path;
	time_t
		expires, // time of expiration (format YYYYMMDDHHMMSS)
		maxage, // like expires, but precedes it if set
		last_access,
		creation;
	unsigned int
		domain_dot : 1, // for compatibility with Netscape cookie format
		normalized : 1,
		persistent : 1,
		host_only : 1,
		secure_only : 1, // cookie should be used over secure connections only (TLS/HTTPS)
		http_only : 1; // just use the cookie via HTTP/HTTPS protocol
} HTTP_COOKIE;

void
	cookie_init_cookie(HTTP_COOKIE *cookie) NONNULL_ALL,
	cookie_free_cookies(void),
	cookie_normalize_cookies(const IRI *iri, const VECTOR *cookies) NONNULL((1)),
	cookie_store_cookie(HTTP_COOKIE *cookie) NONNULL_ALL,
	cookie_store_cookies(VECTOR *cookies) NONNULL((1)),
	cookie_free_public_suffixes(void);
int
	cookie_free_cookie(HTTP_COOKIE *cookie) NONNULL_ALL,
	cookie_normalize_cookie(const IRI *iri, HTTP_COOKIE *cookie) NONNULL((2)),
	cookie_save(const char *fname, int keep_session_cookies) NONNULL_ALL,
	cookie_load(const char *fname) NONNULL_ALL,
	cookie_load_public_suffixes(const char *fname) NONNULL_ALL;
char
	*cookie_create_request_header(const IRI *iri) NONNULL_ALL;

int
	cookie_suffix_match(const char *domain) NONNULL_ALL;

#endif /* _MGET_COOKIE_H */
