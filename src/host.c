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
 * host routines
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created, moved from mget.c
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <libmget.h>

#include "host.h"

static MGET_HASHMAP
	*hosts;
static mget_thread_mutex_t
	hosts_mutex = MGET_THREAD_MUTEX_INITIALIZER;

static int _host_compare(const HOST *host1, const HOST *host2)
{
	int n;

	if (host1->scheme != host2->scheme)
		return host1->scheme < host2->scheme ? -1 : 1;

	// host is already lowercase, no need to call strcasecmp()
	if ((n = strcmp(host1->host, host2->host)))
		return n;

	return 0;
}

static unsigned int _host_hash(const HOST *host)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)host->scheme; p && *p; p++)
		hash = hash * 101 + *p;

	for (p = (unsigned char *)host->host; p && *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static void _free_host_entry(HOST *host, G_GNUC_MGET_UNUSED void *dummy)
{
	mget_robots_free(&host->robots);
}

HOST *hosts_add(MGET_IRI *iri)
{
	mget_thread_mutex_lock(&hosts_mutex);

	if (!hosts) {
		hosts = mget_hashmap_create(16, -2, (unsigned int (*)(const void *))_host_hash, (int (*)(const void *, const void *))_host_compare);
		mget_hashmap_set_destructor(hosts, (void(*)(void *, void *))_free_host_entry);
	}

	HOST *hostp = NULL, host = { .scheme = iri->scheme, .host = iri->host };

	if (!mget_hashmap_contains(hosts, &host)) {
		// info_printf("Add to hosts: %s\n", hostname);
		mget_hashmap_put_noalloc(hosts, hostp = mget_memdup(&host, sizeof(host)), NULL);
	}

	mget_thread_mutex_unlock(&hosts_mutex);

	return hostp;
}

HOST *hosts_get(MGET_IRI *iri)
{
	HOST *hostp, host = { .scheme = iri->scheme, .host = iri->host };

	mget_thread_mutex_lock(&hosts_mutex);

	if (hosts) {
		hostp = mget_hashmap_get(hosts, &host);
	} else {
		hostp = NULL;
	}

	mget_thread_mutex_unlock(&hosts_mutex);

	return hostp;
}

void hosts_free(void)
{
	mget_thread_mutex_lock(&hosts_mutex);
	mget_hashmap_free(&hosts);
	mget_thread_mutex_unlock(&hosts_mutex);
}
