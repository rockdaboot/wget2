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
#include <config.h>
#include <wget.h>
#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

static wget_vector_t *dns_stats_v;
static wget_vector_t *tls_stats_v;
static wget_thread_mutex_t dns_mutex = WGET_THREAD_MUTEX_INITIALIZER;
static wget_thread_mutex_t tls_mutex = WGET_THREAD_MUTEX_INITIALIZER;

static void stats_callback(wget_stats_type_t type, const void *stats)
{
	switch(type) {
	case WGET_STATS_TYPE_DNS: {
		dns_stats_t dns_stats;

		dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
		dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));
		dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));

		wget_thread_mutex_lock(&dns_mutex);
		wget_vector_add(dns_stats_v, &dns_stats, sizeof(dns_stats_t));
		wget_thread_mutex_unlock(&dns_mutex);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		tls_stats_t tls_stats;

		tls_stats.hostname = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats));
		tls_stats.version = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats));
		tls_stats.false_start = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats));
		tls_stats.tfo = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats));
		tls_stats.alpn_proto = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats));
		tls_stats.tls_con = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats));
		tls_stats.resumed = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats));
		tls_stats.tcp_protocol = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats));
		tls_stats.millisecs = *((long long *)wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats));
		tls_stats.cert_chain_size = *((unsigned int *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats));

		wget_thread_mutex_lock(&tls_mutex);
		wget_vector_add(tls_stats_v, &tls_stats, sizeof(tls_stats_t));
		wget_thread_mutex_unlock(&tls_mutex);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
	}
}

static void free_dns_stats(dns_stats_t *stats)
{
	if (stats) {
		xfree(stats->host);
		xfree(stats->ip);
	}
}

static void free_tls_stats(tls_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->version);
		xfree(stats->false_start);
		xfree(stats->tfo);
		xfree(stats->alpn_proto);
	}
}

void stats_init(void)
{

	if (config.stats_dns) {
		dns_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(dns_stats_v, (wget_vector_destructor_t) free_dns_stats);
		wget_tcp_set_stats_dns(stats_callback);
	}

	if (config.stats_tls) {
		tls_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(tls_stats_v, (wget_vector_destructor_t) free_tls_stats);
		wget_tcp_set_stats_tls(stats_callback);
	}
}

void stats_print(void)
{
	if (config.stats_dns) {
		info_printf("\nDNS timings:\n");
		info_printf("  %4s %s\n", "ms", "Host");
		for (int it = 0; it < wget_vector_size(dns_stats_v); it++) {
			const dns_stats_t *dns_stats = wget_vector_get(dns_stats_v, it);
			info_printf("  %4lld %s (%s)\n", dns_stats->millisecs, dns_stats->host, dns_stats->ip);
		}
	}

	if (config.stats_tls) {
		info_printf("\nTLS Statistics:\n");
		for (int it = 0; it < wget_vector_size(tls_stats_v); it++) {
			const tls_stats_t *tls_stats = wget_vector_get(tls_stats_v, it);
			info_printf("  %s:\n", tls_stats->hostname);
			info_printf("    Version         : %s\n", tls_stats->version);
			info_printf("    False Start     : %s\n", tls_stats->false_start);
			info_printf("    TFO             : %s\n", tls_stats->tfo);
			info_printf("    ALPN Protocol   : %s\n", tls_stats->alpn_proto);
			info_printf("    Resumed         : %s\n", tls_stats->resumed ? "Yes" : "No");
			info_printf("    TCP Protocol    : %s\n", tls_stats->tcp_protocol? "HTTP/2": "HTTP/1.1");
			info_printf("    Cert Chain Size : %u\n", tls_stats->cert_chain_size);
			info_printf("    TLS negotiation\n");
			info_printf("    duration (ms)   : %lld\n\n", tls_stats->millisecs);
		}
	}

	wget_vector_free(&dns_stats_v);
	wget_vector_free(&tls_stats_v);
}
