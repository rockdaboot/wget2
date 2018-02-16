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

#define NULL_TO_DASH(s) ((s) ? (s) : wget_strdup("-"))
#define ONE_ZERO_DASH(s) ((s) ? ((s) == 1 ? "1" : "-") : "0")
#define ON_OFF_DASH(s) ((s) ? ((s) == 1 ? "On" : "-") : "Off")
#define YES_NO(s) ((s) ? "Yes" : "No")
#define HTTP_1_2(s) ((s) == WGET_PROTOCOL_HTTP_1_1 ? "HTTP/1.1" : ((s) == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"))
#define HTTP_S_DASH(s) (strcmp(s, "http") ? (strcmp(s, "https") ? s : "1") : "0")

typedef struct stats_opts stats_opts_t;
typedef void (*stats_print_func_t)(stats_opts_t *, FILE *);
typedef void (*stats_callback_setter_t)(wget_stats_callback_t);

struct stats_opts {
	const char
		**options,
		*tag,
		*file;
	wget_stats_format_t
		format;
	wget_vector_t
		*data;
	wget_thread_mutex_t
		mutex;
	stats_callback_setter_t
		set_callback;
	wget_stats_callback_t
		callback;
	wget_vector_destructor_t
		destructor;
	stats_print_func_t
		*print;
};

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

typedef struct {
} site_stats_t;

//void stats_print_dns_human(stats_opts_t *opts, FILE *fp);
//void stats_print_dns_csv(stats_opts_t *opts, FILE *fp);
//void stats_print_dns_json(stats_opts_t *opts, FILE *fp);
// void stats_callback_dns(const void *stats);
// void free_dns_stats(dns_stats_t *stats);

void stats_callback_tls(const void *stats);
void stats_callback_server(const void *stats);
void stats_callback_ocsp(const void *stats);
void stats_callback_site(const void *stats);

void free_tls_stats(tls_stats_t *stats);
void free_server_stats(server_stats_t *stats);
void free_ocsp_stats(ocsp_stats_t *stats);
void free_site_stats(site_stats_t *stats);

void stats_print_data(const wget_vector_t *v, wget_vector_browse_t browse, FILE *fp, int ntabs);

int stats_init(void);
void stats_exit(void);
void stats_print(void);
void stats_set_hosts(wget_hashmap_t *_hosts, wget_thread_mutex_t _hosts_mutex);
DOC *stats_docs_add(wget_iri_t *iri, wget_http_response_t *resp);
TREE_DOCS *stats_tree_docs_add(wget_iri_t *parent_iri, wget_iri_t *iri, wget_http_response_t *resp, bool robot_iri, bool redirect, DOC *doc);

#endif
