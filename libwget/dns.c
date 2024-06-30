/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * resolver routines
 */

#include <config.h>

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Functions for resolving names/IPs
 * \defgroup libwget-dns DNS resolver functions
 *
 * @{
 *
 * DNS Resolver functions.
 *
 */

struct wget_dns_st
{
	wget_dns_cache
		*cache;
	wget_thread_mutex
		mutex;
	wget_dns_stats_callback
		*stats_callback;
	void
		*stats_ctx;
	wget_dns_stats_data
		stats;
	int
		timeout;
};
static wget_dns default_dns = {
	.timeout = -1,
};

static bool
	initialized;

static void dns_exit(void)
{
	if (initialized) {
		wget_thread_mutex_destroy(&default_dns.mutex);
		initialized = false;
	}
}

INITIALIZER(dns_init)
{
	if (!initialized) {
		wget_thread_mutex_init(&default_dns.mutex);
		initialized = true;
		atexit(dns_exit);
	}
}

/**
 * \param[out] dns Pointer to return newly allocated and initialized wget_dns instance
 * \return WGET_E_SUCCESS if OK, WGET_E_MEMORY if out-of-memory or WGET_E_INVALID
 *   if the mutex initialization failed.
 *
 * Allocates and initializes a wget_dns instance.
 * \p dns may be NULL for the purpose of initializing the global structures.
 */
int wget_dns_init(wget_dns **dns)
{
	dns_init();

	if (!dns)
		return WGET_E_SUCCESS;

	wget_dns *_dns = wget_calloc(1, sizeof(wget_dns));

	if (!_dns)
		return WGET_E_MEMORY;

	if (wget_thread_mutex_init(&_dns->mutex)) {
		xfree(_dns);
		return WGET_E_INVALID;
	}

	_dns->timeout = -1;
	*dns = _dns;

	return WGET_E_SUCCESS;
}

/**
 * \param[in/out] dns Pointer to wget_dns instance that will be freed and NULLified.
 *
 * Free the resources allocated by wget_dns_init().
 * \p dns may be NULL for the purpose of freeing the global structures.
 */
void wget_dns_free(wget_dns **dns)
{
	if (!dns) {
		dns_exit();
		return;
	}

	if (*dns) {
		wget_thread_mutex_destroy(&(*dns)->mutex);
		xfree(*dns);
	}
}

/**
 * \param[in] dns The wget_dns instance to set the timeout
 * \param[in] timeout The timeout value.
 *
 * Set the timeout (in milliseconds) for the DNS queries.
 *
 * This is the maximum time to wait until we get a response from the server.
 *
 * Warning: For standard getaddrinfo() a timeout can't be set in a portable way.
 * So this functions currently is a no-op.
 *
 * The following two values are special:
 *
 *  - `0`: No timeout, immediate.
 *  - `-1`: Infinite timeout. Wait indefinitely.
 */
void wget_dns_set_timeout(wget_dns *dns, int timeout)
{
	(dns ? dns : &default_dns)->timeout = timeout;
}

/**
 * \param[in] dns A `wget_dns` instance, created by wget_dns_init().
 * \param[in] cache A `wget_dns_cache` instance
 *
 * Enable or disable DNS caching for the DNS instance provided.
 *
 * The DNS cache is kept internally in memory, and is used in wget_dns_resolve() to speed up DNS queries.
 */
void wget_dns_set_cache(wget_dns *dns, wget_dns_cache *cache)
{
	(dns ? dns : &default_dns)->cache = cache;
}

/**
 * \param[in] dns A `wget_dns` instance, created by wget_dns_init().
 * \return 1 if DNS caching is enabled, 0 otherwise.
 *
 * Tells whether DNS caching is enabled or not.
 *
 * You can enable and disable DNS caching with wget_dns_set_caching().
 */
wget_dns_cache *wget_dns_get_cache(wget_dns *dns)
{
	return (dns ? dns : &default_dns)->cache;
}

/*
 * Reorder address list so that addresses of the preferred family will come first.
 */
static struct addrinfo *sort_preferred(struct addrinfo *addrinfo, int preferred_family)
{
	struct addrinfo *preferred = NULL, *preferred_tail = NULL;
	struct addrinfo *unpreferred = NULL, *unpreferred_tail = NULL;

	for (struct addrinfo *ai = addrinfo; ai;) {
		if (ai->ai_family == preferred_family) {
			if (preferred_tail)
				preferred_tail->ai_next = ai;
			else
				preferred = ai; // remember the head of the list

			preferred_tail = ai;
			ai = ai->ai_next;
			preferred_tail->ai_next = NULL;
		} else {
			if (unpreferred_tail)
				unpreferred_tail->ai_next = ai;
			else
				unpreferred = ai; // remember the head of the list

			unpreferred_tail = ai;
			ai = ai->ai_next;
			unpreferred_tail->ai_next = NULL;
		}
	}

	/* Merge preferred + not preferred */
	if (preferred) {
		preferred_tail->ai_next = unpreferred;
		return preferred;
	} else {
		return unpreferred;
	}
}

static int getaddrinfo_merging(const char *host, const char *s_port, struct addrinfo *hints, struct addrinfo **out_addr)
{
	if (!*out_addr)
		return getaddrinfo(host, s_port, hints, out_addr);

	// Get to the tail of the list
	struct addrinfo *ai_tail = *out_addr;
	while (ai_tail->ai_next)
		ai_tail = ai_tail->ai_next;

	return getaddrinfo(host, s_port, hints, &ai_tail->ai_next);
}

// we can't provide a portable way of respecting a DNS timeout
static int resolve(int family, int flags, const char *host, uint16_t port, struct addrinfo **out_addr)
{
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = 0,
		.ai_flags = AI_ADDRCONFIG | flags
	};
	char s_port[NI_MAXSERV];

	*out_addr = NULL;

	if (port) {
		hints.ai_flags |= AI_NUMERICSERV;

		wget_snprintf(s_port, sizeof(s_port), "%hu", port);
		if (host) {
			if (family == AF_INET6)
				debug_printf("resolving [%s]:%s...\n", host, s_port);
			else
				debug_printf("resolving %s:%s...\n", host, s_port);
		} else
			debug_printf("resolving :%s...\n", s_port);
	} else {
		debug_printf("resolving %s...\n", host);
	}

	int ret;

	/*
	 * .ai_socktype = 0, which would give us all the available socket types,
	 * is not a valid option on Windows. Hence, we call getaddrinfo() twice with SOCK_STREAM
	 * and SOCK_DGRAM, and merge the two lists.
	 * See: https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-addrinfoa
	 */
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo_merging(host, port ? s_port : NULL, &hints, out_addr)) != 0)
		return ret;

	hints.ai_socktype = SOCK_DGRAM;
	if ((ret = getaddrinfo_merging(host, port ? s_port : NULL, &hints, out_addr)) != 0) {
		if (*out_addr)
			freeaddrinfo(*out_addr);
	}

	return ret;
}

/**
 *
 * \param[in] ip IP address of name
 * \param[in] name Domain name, part of the cache's lookup key
 * \param[in] port Port number, part of the cache's lookup key
 * \return 0 on success, < 0 on error
 *
 * Assign an IP address to the name+port key in the DNS cache.
 * The \p name should be lowercase.
 */
int wget_dns_cache_ip(wget_dns *dns, const char *ip, const char *name, uint16_t port)
{
	int rc, family;
	struct addrinfo *ai;

	if (!dns || !dns->cache || !name)
		return WGET_E_INVALID;

	if (wget_ip_is_family(ip, WGET_NET_FAMILY_IPV4)) {
		family = AF_INET;
	} else if (wget_ip_is_family(ip, WGET_NET_FAMILY_IPV6)) {
		family = AF_INET6;
	} else
		return WGET_E_INVALID;

	if ((rc = resolve(family, AI_NUMERICHOST, ip, port, &ai)) != 0) {
		if (family == AF_INET6)
			error_printf(_("Failed to resolve '[%s]:%d': %s\n"), ip, port, gai_strerror(rc));
		else
			error_printf(_("Failed to resolve '%s:%d': %s\n"), ip, port, gai_strerror(rc));
		return WGET_E_UNKNOWN;
	}

	if ((rc = wget_dns_cache_add(dns->cache, name, port, &ai)) < 0) {
		freeaddrinfo(ai);
		return rc;
	}

	return WGET_E_SUCCESS;
}

/**
 * \param[in] dns A `wget_dns` instance, created by wget_dns_init().
 * \param[in] host Hostname
 * \param[in] port TCP destination port
 * \param[in] family Protocol family AF_INET or AF_INET6
 * \param[in] preferred_family Preferred protocol family AF_INET or AF_INET6
 * \return A `struct addrinfo` structure (defined in libc's `<netdb.h>`). Must be freed by the caller with `wget_dns_freeaddrinfo()`.
 *
 * Resolve a host name into its IPv4/IPv6 address.
 *
 * **family**: Desired address family for the returned addresses. This will typically be `AF_INET` or `AF_INET6`,
 * but it can be any of the values defined in `<socket.h>`. Additionally, `AF_UNSPEC` means you don't care: it will
 * return any address family that can be used with the specified \p host and \p port. If **family** is different
 * than `AF_UNSPEC` and the specified family is not found, _that's an error condition_ and thus wget_dns_resolve() will return NULL.
 *
 * **preferred_family**: Tries to resolve addresses of this family if possible. This is only honored if **family**
 * (see point above) is `AF_UNSPEC`.
 *
 *  The returned `addrinfo` structure must be freed with `wget_dns_freeaddrinfo()`.
 */
struct addrinfo *wget_dns_resolve(wget_dns *dns, const char *host, uint16_t port, int family, int preferred_family)
{
	struct addrinfo *addrinfo = NULL;
	int rc = 0;
	char adr[NI_MAXHOST], sport[NI_MAXSERV];
	long long before_millisecs = 0;
	wget_dns_stats_data stats;

	if (!dns)
		dns = &default_dns;

	if (dns->stats_callback)
		before_millisecs = wget_get_timemillis();

	// get the IP address for the server
	for (int tries = 0, max = 3; tries < max; tries++) {
		if (dns->cache) {
			if ((addrinfo = wget_dns_cache_get(dns->cache, host, port)))
				return addrinfo;

			// prevent multiple address resolutions of the same host
			wget_thread_mutex_lock(dns->mutex);

			// now try again
			if ((addrinfo = wget_dns_cache_get(dns->cache, host, port))) {
				wget_thread_mutex_unlock(dns->mutex);
				return addrinfo;
			}
		}

		addrinfo = NULL;

		rc = resolve(family, 0, host, port, &addrinfo);
		if (rc == 0 || rc != EAI_AGAIN)
			break;

		if (tries < max - 1) {
			if (dns->cache)
				wget_thread_mutex_unlock(dns->mutex);
			wget_millisleep(100);
		}
	}

	if (dns->stats_callback) {
		long long after_millisecs = wget_get_timemillis();
		stats.dns_secs = after_millisecs - before_millisecs;
		stats.hostname = host;
		stats.port = port;
	}

	if (rc) {
		error_printf(_("Failed to resolve '%s' (%s)\n"),
				(host ? host : ""), gai_strerror(rc));

		if (dns->cache)
			wget_thread_mutex_unlock(dns->mutex);

		if (dns->stats_callback) {
			stats.ip = NULL;
			dns->stats_callback(dns, &stats, dns->stats_ctx);
		}

		return NULL;
	}

	if (family == AF_UNSPEC && preferred_family != AF_UNSPEC)
		addrinfo = sort_preferred(addrinfo, preferred_family);

	if (dns->stats_callback) {
		if (getnameinfo(addrinfo->ai_addr, addrinfo->ai_addrlen, adr, sizeof(adr), sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
			stats.ip = adr;
		else
			stats.ip = "???";

		dns->stats_callback(dns, &stats, dns->stats_ctx);
	}

	/* Finally, print the address list to the debug pipe if enabled */
	if (wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG))) {
		for (struct addrinfo *ai = addrinfo; ai; ai = ai->ai_next) {
			if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
				if (ai->ai_family == AF_INET6)
					debug_printf("has [%s]:%s\n", adr, sport);
				else
					debug_printf("has %s:%s\n", adr, sport);
			} else
				debug_printf("has ??? (%s)\n", gai_strerror(rc));
		}
	}

	if (dns->cache) {
		/*
		 * In case of a race condition the already existing addrinfo is returned.
		 * The addrinfo argument given to wget_dns_cache_add() will be freed in this case.
		 */
		rc = wget_dns_cache_add(dns->cache, host, port, &addrinfo);
		wget_thread_mutex_unlock(dns->mutex);
		if ( rc < 0) {
			freeaddrinfo(addrinfo);
			return NULL;
		}
	}

	return addrinfo;
}

/**
 * \param[in] dns A `wget_dns` instance, created by wget_dns_init().
 * \param[in/out] addrinfo Value returned by `c`
 *
 * Release addrinfo, previously returned by `wget_dns_resolve()`.
 * If the underlying \p dns uses caching, just the reference/pointer is set to %NULL.
 */
void wget_dns_freeaddrinfo(wget_dns *dns, struct addrinfo **addrinfo)
{
	if (addrinfo && *addrinfo) {
		if (!dns)
			dns = &default_dns;

		if (!dns->cache) {
			freeaddrinfo(*addrinfo);
			*addrinfo = NULL;
		} else {
			// addrinfo is cached and gets freed later when the DNS cache is freed
			*addrinfo = NULL;
		}
	}
}

/**
 * \param[in] dns A `wget_dns` instance, created by wget_dns_init().
 * \param[in] fn A `wget_dns_stats_callback` callback function to receive resolve statistics data
 * \param[in] ctx Context data given to \p fn
 *
 * Set callback function to be called once DNS statistics for a host are collected
 */
void wget_dns_set_stats_callback(wget_dns *dns, wget_dns_stats_callback *fn, void *ctx)
{
	if (!dns)
		dns = &default_dns;

	dns->stats_callback = fn;
	dns->stats_ctx = ctx;
}

/** @} */
