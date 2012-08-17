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
 * Header file for gnutls SSL/TLS routines
 *
 * Changelog
 * 03.08.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_GNUTLS_H
#define _MGET_GNUTLS_H

#include <stddef.h>

#include "mget.h"

void
	ssl_init(void),
	ssl_deinit(void),
	*ssl_open(int sockfd, const char *hostname, int connect_timeout),
	ssl_close(void **session),
	ssl_set_check_certificate(char value);

ssize_t
	ssl_read_timeout(void *session, char *buf, size_t count, int timeout),
	ssl_write_timeout(void *session, const char *buf, size_t count, int timeout);

#endif /* _MGET_NET_H */
