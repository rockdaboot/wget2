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
 * Header file for network routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_NET_H
#define _MGET_NET_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "mget.h"

typedef struct TCP *tcp_t;

void
	tcp_close(tcp_t *tcp),
	tcp_set_timeout(tcp_t tcp, int timeout),
	tcp_set_connect_timeout(int timeout),
	tcp_set_dns_timeout(int timeout),
	tcp_set_dns_caching(int caching),
	tcp_set_debug(int debug);
struct addrinfo
	*tcp_resolve(const char *restrict name, const char *restrict port);
tcp_t
	tcp_connect(struct addrinfo *addrinfo, const char *hostname);
ssize_t
	tcp_send(tcp_t tcp, const char *fmt, ...) PRINTF_FORMAT(2,3),
	tcp_write(tcp_t tcp, const char *buf, size_t count),
	tcp_read(tcp_t tcp, char *buf, size_t count);

#endif /* _MGET_NET_H */
