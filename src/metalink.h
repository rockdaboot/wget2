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
 * Header file for Metalink routines
 *
 * Changelog
 * 10.07.2012  Tim Ruehsen  created (refactored from mget.c)
 *
 * Resources:
 * RFC 5854 - The Metalink Download Description Format
 * RFC 6249 Metalink/HTTP: Mirrors and Hashes
 * RFC 5988 Link HTTP Header update
 * RFC 3864 Link HTTP Header
 * RFC 3230 Digest HTTP Header
 *
 * http://download.services.openoffice.org/files/stable/
 * http://go-oo.mirrorbrain.org/evolution/stable/Evolution-2.24.0.exe
 *
 */

#ifndef _MGET_METALINK_H
#define _MGET_METALINK_H

#include "http.h"
#include "mget.h"

void
	metalink4_parse(int sockfd, HTTP_RESPONSE *resp) NONNULL((2));

#endif /* _MGET_METALINK_H */
