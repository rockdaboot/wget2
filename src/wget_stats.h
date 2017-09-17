/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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
 * Statistics
 *
 */

#ifndef _WGET_STATS_H
#define _WGET_STATS_H

#include "wget_host.h"

typedef struct {
	const char
		*host,
		*ip;
	long long
		millisecs;
	uint16_t
		port;
} dns_stats_t;

typedef struct {
	const char
		*hostname,
		*version,
		*alpn_proto;
	long long
		millisecs;
	int
		cert_chain_size;
	char
		tcp_protocol,
		false_start,
		tfo;
	bool
		tls_con : 1,
		resumed : 1;
} tls_stats_t;

typedef struct {
	const char
		*hostname,
		*ip,
		*scheme;
	char
		hsts,
		csp,
		hpkp_new;
	wget_hpkp_stats_t
		hpkp;
} server_stats_t;

typedef struct {
	const char
		*hostname;
	int
		nvalid,
		nrevoked,
		nignored;
} ocsp_stats_t;

void stats_init(void);
void stats_exit(void);
void stats_print(void);
void stats_set_option(int type, bool status, int format, const char *filename);
void stats_set_hosts(wget_hashmap_t *_hosts, wget_thread_mutex_t *_hosts_mutex);
bool stats_is_enabled(int type);
DOC *stats_docs_add(wget_iri_t *iri, wget_http_response_t *resp);
TREE_DOCS *stats_tree_docs_add(wget_iri_t *parent_iri, wget_iri_t *iri, wget_http_response_t *resp, bool robot_iri, bool redirect, DOC *doc);

#endif
