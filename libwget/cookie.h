/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for cookie code
 */

#ifndef LIBWGET_COOKIE_H
#define LIBWGET_COOKIE_H

#include <stdbool.h>
#include <stdint.h>
#include <wget.h>

struct wget_cookie_st {
	const char *
		name;
	const char *
		value;
	const char *
		domain;
	const char *
		path;
	int64_t
		expires; // time of expiration (format YYYYMMDDHHMMSS)
	int64_t
		maxage; // like expires, but precedes it if set
	int64_t
		last_access;
	int64_t
		creation;
	unsigned int
		sort_age; // need for sorting on Cookie: header construction
	bool
		domain_dot : 1, // for compatibility with Netscape cookie format
		normalized : 1,
		persistent : 1,
		host_only : 1,
		secure_only : 1, // cookie should be used over secure connections only (TLS/HTTPS)
		http_only : 1; // just use the cookie via HTTP/HTTPS protocol
};

WGET_GCC_NONNULL_ALL
bool cookie_domain_match(const char *domain, const char *host);

WGET_GCC_NONNULL((1))
bool cookie_path_match(const char *cookie_path, const char *request_path);

void cookie_free(void *cookie);

#endif /* LIBWGET_COOKIE_H */
