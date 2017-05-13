/*
 * Copyright(c) 2015 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Header file for private net structures
 *
 * Changelog
 * 23.02.2015  Tim Ruehsen
 *
 */

#ifndef _LIBWGET_NET_H
# define _LIBWGET_NET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

struct wget_tcp_st {
	void *
		ssl_session;
	struct addrinfo *
		addrinfo;
	struct addrinfo *
		bind_addrinfo;
	struct addrinfo *
		connect_addrinfo; // needed for TCP_FASTOPEN delayed connect
	const char *
		ssl_hostname; // if set, do SSL hostname checking
	int
		sockfd,
		// timeouts in milliseconds
		// there is no real 'connect timeout', since connects are async
		dns_timeout,
		connect_timeout,
		timeout, // read and write timeouts are the same
		family,
		preferred_family,
		protocol; // WGET_PROTOCOL_HTTP1_1, WGET_PROTOCOL_HTTP2_0
	unsigned char
		ssl : 1,
		passive : 1,
		caching : 1,
		addrinfo_allocated : 1,
		bind_addrinfo_allocated : 1,
		tls_false_start : 1,
		tcp_fastopen : 1, // do we use TCP_FASTOPEN or not
		first_send : 1; // TCP_FASTOPEN's first packet is sent different
};

#endif /* _LIBWGET_NET_H */
