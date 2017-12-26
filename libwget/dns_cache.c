/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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
static wget_vector_t
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

struct addrinfo *wget_dns_cache_get(const char *host, uint16_t port)
{
	if (dns_cache) {
		struct _dns_entry *entryp, entry = { .host = host, .port = port };
		int index;

		wget_thread_mutex_lock(dns_mutex);
		entryp = wget_vector_get(dns_cache, (index = wget_vector_find(dns_cache, &entry)));
		wget_thread_mutex_unlock(dns_mutex);

		if (entryp) {
			// DNS cache entry found
			debug_printf("Found dns cache entry #%d\n", index);
			return entryp->addrinfo;
		}
	}

	return NULL;
}

static int G_GNUC_WGET_PURE _compare_addr(struct _dns_entry *a1, struct _dns_entry *a2)
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
}

struct addrinfo * wget_dns_cache_add(const char *host, uint16_t port, struct addrinfo *addrinfo)
{
	// insert addrinfo into dns cache
	size_t hostlen = host ? strlen(host) + 1 : 0;
	struct _dns_entry *entryp = xmalloc(sizeof(struct _dns_entry) + hostlen);
	int index;

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
		dns_cache = wget_vector_create(4, -2, (wget_vector_compare_t)_compare_addr);
		wget_vector_set_destructor(dns_cache, (wget_vector_destructor_t)_free_dns);
	}

	if ((index = wget_vector_find(dns_cache, entryp)) == -1) {
		debug_printf("Add dns cache entry %s\n", host ? host : "");
		wget_vector_insert_sorted_noalloc(dns_cache, entryp);
	} else {
		// race condition:
		xfree(entryp);
		freeaddrinfo(addrinfo);
		entryp = wget_vector_get(dns_cache, index);
		addrinfo = entryp ? entryp->addrinfo : NULL;
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
	wget_vector_free(&dns_cache);
	wget_thread_mutex_unlock(dns_mutex);
}

/** @} */
