/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * host routines
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created, moved from wget.c
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <libwget.h>

#include "host.h"
#include "options.h"

static wget_hashmap_t
	*hosts;
static wget_thread_mutex_t
	hosts_mutex = WGET_THREAD_MUTEX_INITIALIZER;

static int _host_compare(const HOST *host1, const HOST *host2)
{
	int n;

	// If we use SCHEME here, we would eventually download robots.txt twice,
	//   e.g. for http://example.com and second for https://example.com.
	// This only makes sense when having the scheme and/or port within the directory name.

	if (config.protocol_directories)
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

	// If we use SCHEME here, we would eventually download robots.txt twice.
	// e.g. for http://example.com and second for https://example.com
	// This only makes sense when having the scheme and/or port within the directory name.

	if (config.protocol_directories)
		for (p = (unsigned char *)host->scheme; p && *p; p++)
			hash = hash * 101 + *p;

	for (p = (unsigned char *)host->host; p && *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static void _free_host_entry(HOST *host)
{
	if (host) {
		wget_robots_free(&host->robots);
		wget_xfree(host);
	}
}

HOST *hosts_add(wget_iri_t *iri)
{
	wget_thread_mutex_lock(&hosts_mutex);

	if (!hosts) {
		hosts = wget_hashmap_create(16, -2, (unsigned int (*)(const void *))_host_hash, (int (*)(const void *, const void *))_host_compare);
		wget_hashmap_set_key_destructor(hosts, (void(*)(void *))_free_host_entry);
	}

	HOST *hostp = NULL, host = { .scheme = iri->scheme, .host = iri->host };

	if (!wget_hashmap_contains(hosts, &host)) {
		// info_printf("Add to hosts: %s\n", hostname);
		wget_hashmap_put_noalloc(hosts, hostp = wget_memdup(&host, sizeof(host)), NULL);
	}

	wget_thread_mutex_unlock(&hosts_mutex);

	return hostp;
}

HOST *hosts_get(wget_iri_t *iri)
{
	HOST *hostp, host = { .scheme = iri->scheme, .host = iri->host };

	wget_thread_mutex_lock(&hosts_mutex);

	if (hosts) {
		hostp = wget_hashmap_get(hosts, &host);
	} else {
		hostp = NULL;
	}

	wget_thread_mutex_unlock(&hosts_mutex);

	return hostp;
}

void hosts_free(void)
{
	wget_thread_mutex_lock(&hosts_mutex);
	wget_hashmap_free(&hosts);
	wget_thread_mutex_unlock(&hosts_mutex);
}
