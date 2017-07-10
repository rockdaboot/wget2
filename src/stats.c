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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

static wget_vector_t
	*dns_stats_v,
	*tls_stats_v,
	*server_stats_v,
	*ocsp_stats_v;

static wget_thread_mutex_t dns_mutex = WGET_THREAD_MUTEX_INITIALIZER;
static wget_thread_mutex_t tls_mutex = WGET_THREAD_MUTEX_INITIALIZER;
static wget_thread_mutex_t server_mutex = WGET_THREAD_MUTEX_INITIALIZER;
static wget_thread_mutex_t ocsp_mutex = WGET_THREAD_MUTEX_INITIALIZER;

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
		tls_stats.cert_chain_size = *((size_t *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats));

		wget_thread_mutex_lock(&tls_mutex);
		wget_vector_add(tls_stats_v, &tls_stats, sizeof(tls_stats_t));
		wget_thread_mutex_unlock(&tls_mutex);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		server_stats_t server_stats;

		server_stats.hostname = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats));
		server_stats.hpkp = *((wget_hpkp_stats_t *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats));
		server_stats.hpkp_new = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats));
		server_stats.hsts = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats));
		server_stats.csp = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats));

		wget_thread_mutex_lock(&server_mutex);
		wget_vector_add(server_stats_v, &server_stats, sizeof(server_stats_t));
		wget_thread_mutex_unlock(&server_mutex);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		ocsp_stats_t ocsp_stats;

		ocsp_stats.hostname = wget_strdup(wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats));
		ocsp_stats.nvalid = *((size_t *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats));
		ocsp_stats.nrevoked = *((size_t *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats));
		ocsp_stats.nignored = *((size_t *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats));

		wget_thread_mutex_lock(&ocsp_mutex);
		wget_vector_add(ocsp_stats_v, &ocsp_stats, sizeof(ocsp_stats_t));
		wget_thread_mutex_unlock(&ocsp_mutex);

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

static void free_server_stats(server_stats_t *stats)
{
	if (stats)
		xfree(stats->hostname);
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

	if (config.stats_server) {
		server_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(server_stats_v, (wget_vector_destructor_t) free_server_stats);
		wget_tcp_set_stats_server(stats_callback);
	}

	if (config.stats_ocsp) {
		ocsp_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(ocsp_stats_v, (wget_vector_destructor_t) free_server_stats);
		wget_tcp_set_stats_ocsp(stats_callback);
	}

}

void stats_printjson(wget_stats_type_t type)
{
	switch (type) {
	case WGET_STATS_TYPE_TLS: {
		wget_buffer_t *buf = wget_buffer_alloc(0);
		int fd = open("stats.json", O_WRONLY | O_APPEND | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

		info_printf("\nTLS Statistics (JSON):\n");

		wget_buffer_printf(buf, "[\n");

		for (int it = 0; it < wget_vector_size(tls_stats_v); it++) {
			const tls_stats_t *tls_stats = wget_vector_get(tls_stats_v, it);
		wget_buffer_printf_append(buf, "\t{\n");
		wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", tls_stats->hostname);
		wget_buffer_printf_append(buf, "\t\t\"Version\" : \"%s\",\n", tls_stats->version);
		wget_buffer_printf_append(buf, "\t\t\"False Start\" : \"%s\",\n", tls_stats->false_start);
		wget_buffer_printf_append(buf, "\t\t\"TFO\" : \"%s\",\n", tls_stats->tfo);
		wget_buffer_printf_append(buf, "\t\t\"ALPN Protocol\" : \"%s\",\n", tls_stats->alpn_proto);
		wget_buffer_printf_append(buf, "\t\t\"Resumed\" : \"%s\",\n", tls_stats->resumed ? "Yes" : "No");
		wget_buffer_printf_append(buf, "\t\t\"TCP Protocol\" : \"%s\",\n", tls_stats->tcp_protocol? "HTTP/2": "HTTP/1.1");
		wget_buffer_printf_append(buf, "\t\t\"Cert-chain Size\" : %zu,\n", tls_stats->cert_chain_size);
		wget_buffer_printf_append(buf, "\t\t\"TLS negotiation duration\" : %lld\n", tls_stats->millisecs);
		wget_buffer_printf_append(buf, it < wget_vector_size(tls_stats_v) - 1 ? "\t},\n" : "\t}\n]\n");

		info_printf("%s", buf->data);
		if (fd != -1)
			write(fd, buf->data, strlen(buf->data));
		wget_buffer_reset(buf);
		}

		wget_buffer_free(&buf);
		if (fd != -1)
			close(fd);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
	}
}

void stats_printcsv(wget_stats_type_t type, const char **header, const int header_len)
{
	wget_buffer_t *buf = wget_buffer_alloc(0);
	int fd = open("stats.csv", O_WRONLY | O_APPEND | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	info_printf("\nTLS Statistics (CSV):\n");
	for (int it = 0; it < header_len; it++) {
		wget_buffer_printf_append(buf, "%s", header[it]);
		wget_buffer_printf_append(buf, "%s", it < header_len - 1 ? "," : "\n");
	}
	info_printf("%s", buf->data);
	if (fd != -1)
		write(fd, buf->data, strlen(buf->data));

	switch (type) {
	case WGET_STATS_TYPE_TLS: {
		for (int it = 0; it < wget_vector_size(tls_stats_v); it++) {
			const tls_stats_t *tls_stats = wget_vector_get(tls_stats_v, it);

			wget_buffer_printf(buf, "%s,%s,%s,%s,%s,%s,%s,%zu,%lld\n",
					tls_stats->hostname,
					tls_stats->version,
					tls_stats->false_start,
					tls_stats->tfo,
					tls_stats->alpn_proto,
					tls_stats->resumed ? "Yes" : "No",
					tls_stats->tcp_protocol? "HTTP/2": "HTTP/1.1",
					tls_stats->cert_chain_size,
					tls_stats->millisecs);
			info_printf("%s", buf->data);
			if (fd != -1)
				write(fd, buf->data, strlen(buf->data));
		}
		info_printf("\n");
		wget_buffer_free(&buf);
		if (fd != -1)
			close(fd);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
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

		wget_vector_free(&dns_stats_v);
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
			info_printf("    Cert Chain Size : %zu\n", tls_stats->cert_chain_size);
			info_printf("    TLS negotiation\n");
			info_printf("    duration (ms)   : %lld\n\n", tls_stats->millisecs);
		}

		const char *header[] = {
				"Hostname",
				"Version",
				"False Start",
				"TFO",
				"ALPN",
				"Resumed",
				"TCP",
				"Cert-chain Length",
				"TLS negotiation duration"
		};
		stats_printcsv(WGET_STATS_TYPE_TLS, header, sizeof(header)/sizeof(header[0]));
		stats_printjson(WGET_STATS_TYPE_TLS);

		wget_vector_free(&tls_stats_v);
	}

	if (config.stats_server) {
		info_printf("\nServer Statistics:\n");
		for (int it = 0; it < wget_vector_size(server_stats_v); it++) {
			const server_stats_t *server_stats = wget_vector_get(server_stats_v, it);

			info_printf("  %s:\n", server_stats->hostname);
			switch (server_stats->hpkp) {
					case WGET_STATS_HPKP_NO:
						info_printf("    HPKP           : %s\n", "No existing entry in hpkp db");
						break;
					case WGET_STATS_HPKP_MATCH:
						info_printf("    HPKP           : %s\n", "Pubkey pinning matched");
						break;
					case WGET_STATS_HPKP_NOMATCH:
						info_printf("    HPKP           : %s\n", "Pubkey pinning mismatch");
						break;
					default:
						error_printf("Unknown HPKP stats type\n");
						break;
					}
			info_printf("    HPKP New Entry : %s\n", server_stats->hpkp_new);
			info_printf("    HSTS           : %s\n", server_stats->hsts);
			info_printf("    CSP            : %s\n\n", server_stats->csp);
		}

			wget_vector_free(&server_stats_v);
	}

	if (config.stats_ocsp) {
		info_printf("\nOCSP Statistics:\n");
		for (int it = 0; it < wget_vector_size(ocsp_stats_v); it++) {
			const ocsp_stats_t *ocsp_stats = wget_vector_get(ocsp_stats_v, it);

			info_printf("  %s:\n", ocsp_stats->hostname);
			info_printf("    VALID          : %zu\n", ocsp_stats->nvalid);
			info_printf("    REVOKED        : %zu\n", ocsp_stats->nrevoked);
			info_printf("    IGNORED        : %zu\n\n", ocsp_stats->nignored);
		}

			wget_vector_free(&ocsp_stats_v);
	}
}
