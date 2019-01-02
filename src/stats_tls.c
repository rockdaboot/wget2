/*
 * Copyright(c) 2018-2019 Free Software Foundation, Inc.
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
 * TLS statistics functions
 */
#include <config.h>

#include <wget.h>
#include <stdio.h>
#include <stdint.h>

#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

typedef struct {
	const char
		*hostname,
		*alpn_proto;
	long long
		millisecs;
	int
		version,
		cert_chain_size;
	char
		http_protocol,
		false_start,
		tfo;
	bool
		tls_con : 1,
		resumed : 1;
} tls_stats_t;

// Forward declarations for static functions
static void print_human(stats_opts_t *opts, FILE *fp);
static void print_csv(stats_opts_t *opts, FILE *fp);
static void stats_callback(const void *stats);
static void free_stats(tls_stats_t *stats);

static stats_print_func_t
	print_tls[] = {
		[WGET_STATS_FORMAT_HUMAN] = print_human,
		[WGET_STATS_FORMAT_CSV] = print_csv,
	};

stats_opts_t stats_tls_opts = {
	.tag = "TLS",
	.options = &config.stats_tls,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_tls,
	.callback = stats_callback,
	.destructor = (wget_vector_destructor_t) free_stats,
	.print = print_tls,
};

static void stats_callback(const void *stats)
{
	tls_stats_t tls_stats = { .false_start = -1, .tfo = -1, .tls_con = -1, .resumed = -1, .http_protocol = -1, .cert_chain_size = -1, .millisecs = -1 };

	tls_stats.hostname = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats));
	tls_stats.alpn_proto = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats))
		tls_stats.version = *((int *)wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats))
		tls_stats.false_start = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats))
		tls_stats.tfo = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats))
		tls_stats.tls_con = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats))
		tls_stats.resumed = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_HTTP_PROTO, stats))
		tls_stats.http_protocol = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_HTTP_PROTO, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats))
		tls_stats.cert_chain_size = *((int *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats))
		tls_stats.millisecs = *((long long *)wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats));

	wget_thread_mutex_lock(stats_tls_opts.mutex);
	wget_vector_add(stats_tls_opts.data, &tls_stats, sizeof(tls_stats_t));
	wget_thread_mutex_unlock(stats_tls_opts.mutex);
}

static void free_stats(tls_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->alpn_proto);
	}
}

static const char *_tlsversion_string(int v)
{
	switch (v) {
	case 1: return "SSL3";
	case 2: return "TLS1.0";
	case 3: return "TLS1.1";
	case 4: return "TLS1.2";
	case 5: return "TLS1.3";
	default: return "?";
	}
}

static int print_human_entry(FILE *fp, const tls_stats_t *tls_stats)
{
	fprintf(fp, "  %s:\n", tls_stats->hostname);
	fprintf(fp, "    Version         : %s\n", _tlsversion_string(tls_stats->version));
	fprintf(fp, "    False Start     : %s\n", ON_OFF_DASH(tls_stats->false_start));
	fprintf(fp, "    TFO             : %s\n", ON_OFF_DASH(tls_stats->tfo));
	fprintf(fp, "    ALPN Protocol   : %s\n", NULL_TO_DASH(tls_stats->alpn_proto));
	fprintf(fp, "    Resumed         : %s\n", YES_NO(tls_stats->resumed));
	fprintf(fp, "    TCP Protocol    : %s\n", HTTP_1_2(tls_stats->http_protocol));
	fprintf(fp, "    Cert Chain Size : %d\n", tls_stats->cert_chain_size);
	fprintf(fp, "    TLS negotiation\n");
	fprintf(fp, "    duration (ms)   : %lld\n\n", tls_stats->millisecs);

	return 0;
}

static int print_csv_entry(FILE *fp, const tls_stats_t *tls_stats)
{
	fprintf(fp, "%s,%d,%d,%d,%d,%s,%d,%d,%lld\n",
		tls_stats->hostname,
		tls_stats->version,
		tls_stats->false_start,
		tls_stats->tfo,
		tls_stats->resumed,
		tls_stats->alpn_proto ? tls_stats->alpn_proto : "",
		tls_stats->http_protocol,
		tls_stats->cert_chain_size,
		tls_stats->millisecs);

	return 0;
}

static void print_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nTLS Statistics:\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_human_entry, fp);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,TLSVersion,FalseStart,TFO,Resumed,ALPN,HTTPVersion,Certificates,Duration\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_csv_entry, fp);
}
