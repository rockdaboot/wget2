/*
 * Copyright (c) 2016-2024 Free Software Foundation, Inc.
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

#include <config.h>

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
 * \param[in] host Host/IP string
 * \param[in] family IP address family
 * \return
 * 1 if \p host matches is of \p family<br>
 * 0 if \p host does not match \p family<br>
 *
 * This functions checks if \p host matches the given \p family or not.
 */
bool wget_ip_is_family(const char *host, int family)
{
	struct sockaddr_storage dst;

	if (!host)
		return false;

	switch (family) {
	case WGET_NET_FAMILY_IPV4:
		return inet_pton(AF_INET, host, (struct in_addr *) &dst) == 1;
	case WGET_NET_FAMILY_IPV6:
		return inet_pton(AF_INET6, host, (struct in6_addr *) &dst) == 1;
	default:
		return false;
	}
}

/* Not finished, currently not needed
int wget_ip_is_ip(const char *addr)
{
	if (!addr)
		return 0;

	return wget_ip_is_family(addr, WGET_NET_FAMILY_IPV4) || wget_ip_is_family(addr, WGET_NET_FAMILY_IPV6);
}

int wget_ip_parse_cidr(const char *s, wget_network_addr_t *addr)
{
	if (!s)
		return -1;

	const char *p;
	int mask_bits = 32;
	uint32_t mask = 0xFFFFFFFF;

	if ((p = strchr(s, "/"))) {
		if ((c_isdigit(p[1]) && p[2] == 0)
			|| (p[1] >= '1' && p[1] <= '3' && isdigit(p[2]) && p[3] == 0))
		{
			mask_bits = atoi(p + 1);

			if (mask_bits > 32)
				return -1;

			if (mask_bits == 0)
				mask = 0;
			else if (mask_bits < 32)
				mask = mask << (32 - mask_bits);
		} else
			return -1;
	}

	return wget_ip_is_family(addr, WGET_NET_FAMILY_IPV4) || wget_ip_is_family(addr, WGET_NET_FAMILY_IPV6);
}
*/

/**@}*/
