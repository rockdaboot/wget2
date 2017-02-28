/*
 * Copyright(c) 2016 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * IP address helper routines
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief IP address functions
 * \defgroup libwget-ip IP address functions
 * @{
 *
 * Routines to check IP address formats.
 */

/**
 * \param[in] host Host/IP String
 * \param[in] family IP address family
 * \return
 * 1 if \p host matches is of \p family<br>
 * 0 if \p host does not match \p family<br>
 *
 * This functions checks if \p host matches the given \p family or not.
 */
int wget_ip_is_family(const char *host, int family)
{
	struct sockaddr_storage dst;

	if (!host)
		return 0;

	switch (family) {
	case WGET_NET_FAMILY_IPV4:
		return inet_pton(AF_INET, host, (struct in_addr *) &dst);
	case WGET_NET_FAMILY_IPV6:
		return inet_pton(AF_INET6, host, (struct in6_addr *) &dst);
	default:
		return 0;
	}
}

/**@}*/
