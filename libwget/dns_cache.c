/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
struct cache_entry {
	const char *
		host;
	struct addrinfo *
		addrinfo;
	uint16_t
		port;
};

struct wget_dns_cache_st {
	wget_hashmap
		*cache;
	wget_thread_mutex
		mutex;
};

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int WGET_GCC_PURE hash_dns(const struct cache_entry *entry)
{
	unsigned int hash = entry->port;
	const unsigned char *p = (unsigned char *) entry->host;

	while (*p)
		hash = hash * 101 + *p++;

	return hash;
}

static int WGET_GCC_PURE compare_dns(const struct cache_entry *a1, const struct cache_entry *a2)
{
	if (a1->port < a2->port)
		return -1;
	if (a1->port > a2->port)
		return 1;

	return wget_strcasecmp(a1->host, a2->host);
}

static void free_dns(struct cache_entry *entry)
{
	freeaddrinfo(entry->addrinfo);
	xfree(entry);
}

/**
 * \param[out] cache Pointer to return newly allocated and initialized wget_dns_cache instance
 * \return WGET_E_SUCCESS if OK, WGET_E_MEMORY if out-of-memory or WGET_E_INVALID
 *   if the mutex initialization failed.
 *
 * Allocates and initializes a wget_dns_cache instance.
 */
int wget_dns_cache_init(wget_dns_cache **cache)
{
	wget_dns_cache *_cache = wget_calloc(1, sizeof(wget_dns_cache));

	if (!_cache)
		return WGET_E_MEMORY;

	if (wget_thread_mutex_init(&_cache->mutex)) {
		xfree(_cache);
		return WGET_E_INVALID;
	}

	if (!(_cache->cache = wget_hashmap_create(16, (wget_hashmap_hash_fn *) hash_dns, (wget_hashmap_compare_fn *) compare_dns))) {
		wget_dns_cache_free(&_cache);
		return WGET_E_MEMORY;
	}

	wget_hashmap_set_key_destructor(_cache->cache, (wget_hashmap_key_destructor *) free_dns);
	wget_hashmap_set_value_destructor(_cache->cache, (wget_hashmap_value_destructor *) free_dns);

	*cache = _cache;

	return WGET_E_SUCCESS;
}

/**
 * \param[in/out] cache Pointer to wget_dns_cache instance that will be freed and NULLified.
 *
 * Free the resources allocated by wget_dns_cache_init().
 */
void wget_dns_cache_free(wget_dns_cache **cache)
{
	if (cache && *cache) {
		wget_thread_mutex_lock((*cache)->mutex);
		wget_hashmap_free(&(*cache)->cache);
		wget_thread_mutex_unlock((*cache)->mutex);

		wget_thread_mutex_destroy(&(*cache)->mutex);
		xfree(*cache);
	}
}

/**
 * \param[in] cache A `wget_dns_cache` instance, created by wget_dns_cache_init().
 * \param[in] host Hostname to look up
 * \param[in] port Port to look up
 * \return The cached addrinfo structure or NULL if not found
 */
struct addrinfo *wget_dns_cache_get(wget_dns_cache *cache, const char *host, uint16_t port)
{
	if (cache) {
		struct cache_entry *entryp, entry = { .host = host, .port = port };

		wget_thread_mutex_lock(cache->mutex);
		if (!wget_hashmap_get(cache->cache, &entry, &entryp))
			entryp = NULL;
		wget_thread_mutex_unlock(cache->mutex);

		if (entryp) {
			// DNS cache entry found
			if (wget_ip_is_family(entryp->host, WGET_NET_FAMILY_IPV6))
				debug_printf("Found dns cache entry [%s]:%d\n", entryp->host, entryp->port);
			else
				debug_printf("Found dns cache entry %s:%d\n", entryp->host, entryp->port);
			return entryp->addrinfo;
		}
	}

	return NULL;
}

/**
 * \param[in] cache A `wget_dns_cache` instance, created by wget_dns_cache_init().
 * \param[in] host Hostname part of the key
 * \param[in] port Port part of the key
 * \param[in/out] addrinfo Addrinfo structure to cache, returns cached addrinfo
 * \return WGET_E_SUCCESS on success, else a WGET_E_* error value
 *
 * This functions adds \p addrinfo to the given DNS cache \p cache.
 *
 * If an entry for [host,port] already exists, \p addrinfo is free'd and replaced by the cached entry.
 * Do not free \p addrinfo yourself - this will be done when the whole cache is freed.
 */
int wget_dns_cache_add(wget_dns_cache *cache, const char *host, uint16_t port, struct addrinfo **addrinfo)
{
	if (!cache || !host || !addrinfo)
		return WGET_E_INVALID;

	struct cache_entry entry = { .host = host, .port = port };
	struct cache_entry *entryp;

	wget_thread_mutex_lock(cache->mutex);

	if (wget_hashmap_get(cache->cache, &entry, &entryp)) {
		// host+port is already in cache
		wget_thread_mutex_unlock(cache->mutex);
		if (*addrinfo != entryp->addrinfo)
			freeaddrinfo(*addrinfo);
		*addrinfo = entryp->addrinfo;
		return WGET_E_SUCCESS;
	}

	// insert addrinfo into dns cache
	size_t hostlen = strlen(host) + 1;
	entryp = wget_malloc(sizeof(struct cache_entry) + hostlen);

	if (!entryp) {
		wget_thread_mutex_unlock(cache->mutex);
		return WGET_E_MEMORY;
	}

	entryp->port = port;
	entryp->host = (char *)(entryp + 1);
	memcpy((char *)entryp->host, host, hostlen); // ugly cast, but semantically ok
	entryp->addrinfo = *addrinfo;

	// key and value are the same to make wget_hashmap_get() return old entry
	wget_hashmap_put(cache->cache, entryp, entryp);

	wget_thread_mutex_unlock(cache->mutex);

	return WGET_E_SUCCESS;
}

/** @} */
