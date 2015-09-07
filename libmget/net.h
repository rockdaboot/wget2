/*
 * Copyright(c) 2015 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for private net structures
 *
 * Changelog
 * 23.02.2015  Tim Ruehsen
 *
 */

#ifndef _LIBMGET_NET_H
#define _LIBMGET_NET_H

#ifndef __WIN32
# ifdef __VMS
#  include "vms_ip.h"
# else /* def __VMS */
#  include <netdb.h>
# endif /* def __VMS [else] */
# include <sys/socket.h>
# include <netinet/tcp.h>
# include <netinet/in.h>
# ifndef __BEOS__
#  include <arpa/inet.h>
# endif
#else
# include <winsock2.h>
# include <ws2tcpip.h>
#endif /* not WINDOWS */

struct mget_tcp_st {
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
		protocol; // MGET_PROTOCOL_HTTP1_1, MGET_PROTOCOL_HTTP2_0
	unsigned int
		ssl : 1,
		passive : 1,
		caching : 1,
		addrinfo_allocated : 1,
		bind_addrinfo_allocated : 1,
		tcp_fastopen : 1, // do we use TCP_FASTOPEN or not
		first_send : 1; // TCP_FASTOPEN's first packet is sent different
};

#endif /* _LIBMGET_NET_H */
