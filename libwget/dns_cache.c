/*
 * Copyright(c) 2017-2018 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Functions for DNS caching
 * \defgroup libwget-dns-caching DNS caching
 *
 * @{
 *
 * DNS cache management functions.
 *
 */

/* Resolver / DNS cache entry */
struct _dns_entry {
	const char *
		host;
	struct addrinfo *
		addrinfo;
	uint16_t
		port;
};

/* Resolver / DNS cache container */
static wget_hashmap_t
	*dns_cache;
static wget_thread_mutex_t
	dns_mutex;
static bool
	initialized;

static void __attribute__ ((constructor)) _wget_dns_cache_init(void)
{
	if (!initialized) {
		wget_thread_mutex_init(&dns_mutex);
		initialized = 1;
	}
}

static void __attribute__ ((destructor)) _wget_dns_cache_exit(void)
{
	if (initialized) {
		wget_thread_mutex_destroy(&dns_mutex);
		initialized = 0;
	}
}

/**
 * Initialize the internal mutex needed for thread-safety operations on
 * the cache entry container (hashmap).
 * If you don't use multi-threading, you don't have to call this function.
 *
 * The initialization is normally automatically during library construction.
 * But some systems doesn't support library constructors, also static linking doesn't do.
 * That's where this function is needed.
 */
void wget_dns_cache_init(void)
{
	_wget_dns_cache_init();
}

/**
 * Free the internal mutex allocated by wget_dns_cache_init().
 */
void wget_dns_cache_exit(void)
{
	_wget_dns_cache_exit();
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int G_GNUC_WGET_PURE _hash_dns(const struct _dns_entry *entry)
{
	unsigned int hash = entry->port;
	const unsigned char *p = (unsigned char *) entry->host;

	while (*p)
		hash = hash * 101 + *p++;

	return hash;
}

static int G_GNUC_WGET_PURE _compare_dns(const struct _dns_entry *a1, const struct _dns_entry *a2)
{
	if (a1->port < a2->port)
		return -1;
	if (a1->port > a2->port)
		return 1;

	return wget_strcasecmp(a1->host, a2->host);
}

static void _free_dns(struct _dns_entry *entry)
{
	freeaddrinfo(entry->addrinfo);
	xfree(entry);
}

/**
 * \param[in] host Hostname to look up
 * \param[in] port Port to look up
 * \return The cached addrinfo structure or NULL if not found
 */
struct addrinfo *wget_dns_cache_get(const char *host, uint16_t port)
{
	if (dns_cache) {
		struct _dns_entry *entryp, entry = { .host = host, .port = port };

		wget_thread_mutex_lock(dns_mutex);
		entryp = wget_hashmap_get(dns_cache, &entry);
		wget_thread_mutex_unlock(dns_mutex);

		if (entryp) {
			// DNS cache entry found
			debug_printf("Found dns cache entry %s:%d\n", entryp->host, entryp->port);
			return entryp->addrinfo;
		}
	}

	return NULL;
}

/**
 * \param[in] host Hostname part of the key
 * \param[in] port Port part of the key
 * \param[in] addrinfo Addrinfo structure to cache
 * \return The cached addrinfo structure or NULL on error
 */
struct addrinfo *wget_dns_cache_add(const char *host, uint16_t port, struct addrinfo *addrinfo)
{
	// insert addrinfo into dns cache
	size_t hostlen = host ? strlen(host) + 1 : 0;
	struct _dns_entry *entryp = xmalloc(sizeof(struct _dns_entry) + hostlen);

	if (host) {
		entryp->port = port;
		entryp->host = ((char *)entryp) + sizeof(struct _dns_entry);
		memcpy((char *)entryp->host, host, hostlen); // ugly cast, but semantically ok
	} else {
		entryp->host = NULL;
	}

	entryp->addrinfo = addrinfo;

	wget_thread_mutex_lock(dns_mutex);
	if (!dns_cache) {
		dns_cache = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_dns, (wget_hashmap_compare_t)_compare_dns);
		wget_hashmap_set_key_destructor(dns_cache, (wget_hashmap_key_destructor_t)_free_dns);
		wget_hashmap_set_value_destructor(dns_cache, (wget_hashmap_value_destructor_t)_free_dns);
	}

	if (wget_hashmap_get(dns_cache, entryp)) {
		_free_dns(entryp);
	} else {
		// key and value are the same to make wget_hashmap_get() return old entry
		wget_hashmap_put_noalloc(dns_cache, entryp, entryp);
	}

	wget_thread_mutex_unlock(dns_mutex);

	return addrinfo;
}

/**
 * Free the DNS cache.
 *
 * The DNS cache is kept internally in memory. This function releases all its entries
 * and then removes the cache itself, thus freeing memory.
 *
 * The cache will be re-generated again when calling wget_tcp_resolve(), if the `tcp->caching` flag
 * was set.
 *
 */
void wget_dns_cache_free(void)
{
	wget_thread_mutex_lock(dns_mutex);
	wget_hashmap_free(&dns_cache);
	wget_thread_mutex_unlock(dns_mutex);
}

/** @} */
