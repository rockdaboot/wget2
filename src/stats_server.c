/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Server statistics functions
 */
#include <config.h>

#include <stdio.h>
#include <stdint.h>

#include <wget.h>
#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"
#include "../libwget/http.h"
#include "../libwget/net.h"

typedef struct
{
	const char
		*hostname,
		*ip;
	wget_hpkp_stats_result
		hpkp;
	wget_iri_scheme
		scheme;
	char
		hsts,
		csp,
		hpkp_new;
} server_stats_data;

typedef struct {
	const char
		*hostname,
		*ip;
	wget_iri_scheme
		scheme;
} server_stats_host;

static wget_hashmap
	*hosts;

static wget_thread_mutex
	mutex;

static FILE
	*fp;

static int host_compare(const server_stats_host *host1, const server_stats_host *host2)
{
	int n;

	if ((n = wget_strcmp(host1->hostname, host2->hostname)))
		return n;

	if ((n = wget_strcmp(host1->ip, host2->ip)))
		return n;

	return host1->scheme - host2->scheme;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int host_hash(const server_stats_host *host)
{
	unsigned int hash = host->scheme; // use 0 as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)host->hostname; p && *p; p++)
			hash = hash * 101 + *p;

	for (p = (unsigned char *)host->ip; p && *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static void free_host_entry(server_stats_host *host)
{
	if (host) {
		wget_xfree(host->hostname);
		wget_xfree(host->ip);
		wget_xfree(host);
	}
}

WGET_GCC_CONST
static const char *hpkp_string(wget_hpkp_stats_result hpkp)
{
	switch (hpkp) {
	case WGET_STATS_HPKP_NO: return "HPKP_NO";
	case WGET_STATS_HPKP_MATCH: return "HPKP_MATCH";
	case WGET_STATS_HPKP_NOMATCH: return "HPKP_NOMATCH";
	case WGET_STATS_HPKP_ERROR: return "HPKP_ERROR";
	default: return "?";
	}
}

static void server_stats_print(server_stats_data *stats)
{
	if (config.stats_server_args->format == WGET_STATS_FORMAT_HUMAN) {
		wget_fprintf(fp, "  %s:\n", NULL_TO_DASH(stats->hostname));
		wget_fprintf(fp, "    IP             : %s\n", NULL_TO_DASH(stats->ip));
		wget_fprintf(fp, "    Scheme         : %s\n", wget_iri_scheme_get_name(stats->scheme));
		wget_fprintf(fp, "    HPKP           : %s\n", hpkp_string(stats->hpkp));
		wget_fprintf(fp, "    HPKP New Entry : %s\n", ON_OFF_DASH(stats->hpkp_new));
		wget_fprintf(fp, "    HSTS           : %s\n", ON_OFF_DASH(stats->hsts));
		wget_fprintf(fp, "    CSP            : %s\n\n", ON_OFF_DASH(stats->csp));
	} else {
		wget_fprintf(fp, "%s,%s,%s,%d,%d,%d,%d\n",
			stats->hostname ? stats->hostname : "",
			stats->ip ? stats->ip : "",
			wget_iri_scheme_get_name(stats->scheme),
			(int) stats->hpkp,
			stats->hpkp_new,
			stats->hsts,
			stats->csp);
	}
}

static void server_stats_add(wget_http_connection *conn, wget_http_response *resp)
{
	server_stats_host *hostp = wget_malloc(sizeof(server_stats_host));

	hostp->hostname = wget_strdup(wget_http_get_host(conn));
	hostp->ip = wget_strdup(wget_tcp_get_ip(conn->tcp));
	hostp->scheme = conn->scheme;

	wget_thread_mutex_lock(mutex);

	if (!wget_hashmap_contains(hosts, hostp)) {
		server_stats_data stats;

		stats.hostname = hostp->hostname;
		stats.ip = hostp->ip;
		stats.scheme = hostp->scheme;
		stats.hpkp = conn->tcp->hpkp;
		stats.hpkp_new = resp ? (resp->hpkp ? 1 : 0): -1;
		stats.hsts = resp ? (resp->hsts ? 1 : 0) : -1;
		stats.csp = resp ? (resp->csp ? 1 : 0) : -1;

		server_stats_print(&stats);
		wget_hashmap_put(hosts, hostp, hostp);
	} else
		free_host_entry(hostp);

	wget_thread_mutex_unlock(mutex);
}

void server_stats_init(FILE *fpout)
{
	wget_thread_mutex_init(&mutex);

	hosts = wget_hashmap_create(16, (wget_hashmap_hash_fn *) host_hash, (wget_hashmap_compare_fn *) host_compare);
	wget_hashmap_set_key_destructor(hosts, (wget_hashmap_key_destructor *) free_host_entry);

	fp = fpout;

	wget_server_set_stats_callback(server_stats_add);
}

void server_stats_exit(void)
{
	// We don't need mutex locking here - this function is called on exit when all threads have ceased.
	wget_hashmap_free(&hosts);
	wget_thread_mutex_destroy(&mutex);
}
