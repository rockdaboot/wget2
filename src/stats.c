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
#include "wget_host.h"

#define NULL_TO_DASH(s) ((s) ? (s) : "-")

static wget_vector_t
	*dns_stats_v,
	*tls_stats_v,
	*server_stats_v,
	*ocsp_stats_v;

static wget_thread_mutex_t
	dns_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	tls_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	server_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	ocsp_mutex = WGET_THREAD_MUTEX_INITIALIZER;

static void stats_callback(wget_stats_type_t type, const void *stats)
{
	switch(type) {
	case WGET_STATS_TYPE_DNS: {
		dns_stats_t dns_stats = { .millisecs = -1, .port = -1 };

		dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
		dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats))
			dns_stats.port = *((uint16_t *)wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats));

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats))
			dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));

		wget_thread_mutex_lock(&dns_mutex);
		wget_vector_add(dns_stats_v, &dns_stats, sizeof(dns_stats_t));
		wget_thread_mutex_unlock(&dns_mutex);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		tls_stats_t tls_stats = { .resumed = -1, .tcp_protocol = -1, .millisecs = -1, .cert_chain_size = -1, .tls_con = -1 };

		tls_stats.hostname = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats));
		tls_stats.version = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats));
		tls_stats.false_start = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats));
		tls_stats.tfo = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats));
		tls_stats.alpn_proto = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats));

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats))
			tls_stats.tls_con = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats));

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats))
			tls_stats.resumed = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats));

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats))
			tls_stats.tcp_protocol = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats));

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats))
			tls_stats.cert_chain_size = *((int *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats));

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats))
			tls_stats.millisecs = *((long long *)wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats));

		wget_thread_mutex_lock(&tls_mutex);
		wget_vector_add(tls_stats_v, &tls_stats, sizeof(tls_stats_t));
		wget_thread_mutex_unlock(&tls_mutex);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		server_stats_t server_stats = { .hpkp = WGET_STATS_HPKP_NO };

		server_stats.hostname = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats));
		server_stats.ip = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_IP, stats));
		server_stats.scheme = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_SCHEME, stats));
		server_stats.hpkp_new = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats));
		server_stats.hsts = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats));
		server_stats.csp = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats));

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats))
			server_stats.hpkp = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats));

		wget_thread_mutex_lock(&server_mutex);
		wget_vector_add(server_stats_v, &server_stats, sizeof(server_stats_t));
		wget_thread_mutex_unlock(&server_mutex);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		ocsp_stats_t ocsp_stats = { .nvalid = -1, .nrevoked = -1, .nignored = -1 };

		ocsp_stats.hostname = wget_strdup(wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats));

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats))
			ocsp_stats.nvalid = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats));

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats))
			ocsp_stats.nrevoked = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats));

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats))
			ocsp_stats.nignored = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats));

		wget_thread_mutex_lock(&ocsp_mutex);
		wget_vector_add(ocsp_stats_v, &ocsp_stats, sizeof(ocsp_stats_t));
		wget_thread_mutex_unlock(&ocsp_mutex);

		break;
	}

	case WGET_STATS_TYPE_SITE: {
		break;
	}

	default:
		error_printf("Unknown stats type %d\n", (int) type);
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
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->ip);
		xfree(stats->scheme);
		xfree(stats->hsts);
		xfree(stats->csp);
		xfree(stats->hpkp_new);
	}
}

static void free_ocsp_stats(server_stats_t *stats)
{
	if (stats)
		xfree(stats->hostname);
}

void stats_init(void)
{
	if (stats_opts[WGET_STATS_TYPE_DNS].status) {
		dns_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(dns_stats_v, (wget_vector_destructor_t) free_dns_stats);
		wget_tcp_set_stats_dns(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_TLS].status) {
		tls_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(tls_stats_v, (wget_vector_destructor_t) free_tls_stats);
		wget_tcp_set_stats_tls(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_SERVER].status) {
		server_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(server_stats_v, (wget_vector_destructor_t) free_server_stats);
		wget_tcp_set_stats_server(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_OCSP].status) {
		ocsp_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(ocsp_stats_v, (wget_vector_destructor_t) free_ocsp_stats);
		wget_tcp_set_stats_ocsp(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_SITE].status)
		wget_tcp_set_stats_site(true);
}

G_GNUC_WGET_PURE static const char *stats_server_hpkp(wget_hpkp_stats_t hpkp)
{
	switch (hpkp) {
	case WGET_STATS_HPKP_NO:
		return "No existing entry in hpkp db";
	case WGET_STATS_HPKP_MATCH:
		return "Pubkey pinning matched";
	case WGET_STATS_HPKP_NOMATCH:
		return "Pubkey pinning mismatch";
	case WGET_STATS_HPKP_ERROR:
		return "Pubkey pinning error";
	default:
		error_printf("Unknown HPKP stats type %d\n", (int) hpkp);
		return "-";
	}
}

static void stats_print_human_dns_entry(wget_buffer_t *buf, const dns_stats_t *dns_stats)
{
	wget_buffer_printf_append(buf, "  %4lld %s:%hu (%s)\n",
		dns_stats->millisecs,
		NULL_TO_DASH(dns_stats->host),
		dns_stats->port,
		NULL_TO_DASH(dns_stats->ip));
}

static void stats_print_json_dns_entry(wget_buffer_t *buf, const dns_stats_t *dns_stats)
{
	wget_buffer_printf_append(buf, "\t{\n");
	wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(dns_stats->host));
	wget_buffer_printf_append(buf, "\t\t\"IP\" : \"%s\",\n", NULL_TO_DASH(dns_stats->ip));
	wget_buffer_printf_append(buf, "\t\t\"Port\" : %hu\n", dns_stats->port);
	wget_buffer_printf_append(buf, "\t\t\"DNS resolution duration (ms)\" : %lld\n", dns_stats->millisecs);
	wget_buffer_printf_append(buf, "\t},\n");
}

static void stats_print_csv_dns_entry(wget_buffer_t *buf, const dns_stats_t *dns_stats)
{
	wget_buffer_printf_append(buf, "%s,%s,%hu,%lld\n",
		NULL_TO_DASH(dns_stats->host),
		NULL_TO_DASH(dns_stats->ip),
		dns_stats->port,
		dns_stats->millisecs);
}

static void stats_print_human_tls_entry(wget_buffer_t *buf, const tls_stats_t *tls_stats)
{
	wget_buffer_printf_append(buf, "  %s:\n", NULL_TO_DASH(tls_stats->hostname));
	wget_buffer_printf_append(buf, "    Version         : %s\n", NULL_TO_DASH(tls_stats->version));
	wget_buffer_printf_append(buf, "    False Start     : %s\n", NULL_TO_DASH(tls_stats->false_start));
	wget_buffer_printf_append(buf, "    TFO             : %s\n", NULL_TO_DASH(tls_stats->tfo));
	wget_buffer_printf_append(buf, "    ALPN Protocol   : %s\n", NULL_TO_DASH(tls_stats->alpn_proto));
	wget_buffer_printf_append(buf, "    Resumed         : %s\n",
		tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No");
	wget_buffer_printf_append(buf, "    TCP Protocol    : %s\n",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"HTTP/1.1" :
			(tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"));
	wget_buffer_printf_append(buf, "    Cert Chain Size : %d\n", tls_stats->cert_chain_size);
	wget_buffer_printf_append(buf, "    TLS negotiation\n");
	wget_buffer_printf_append(buf, "    duration (ms)   : %lld\n\n", tls_stats->millisecs);
}

static void stats_print_json_tls_entry(wget_buffer_t *buf, const tls_stats_t *tls_stats)
{
	wget_buffer_printf_append(buf, "\t{\n");
	wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(tls_stats->hostname));
	wget_buffer_printf_append(buf, "\t\t\"Version\" : \"%s\",\n", NULL_TO_DASH(tls_stats->version));
	wget_buffer_printf_append(buf, "\t\t\"False Start\" : \"%s\",\n", NULL_TO_DASH(tls_stats->false_start));
	wget_buffer_printf_append(buf, "\t\t\"TFO\" : \"%s\",\n", NULL_TO_DASH(tls_stats->tfo));
	wget_buffer_printf_append(buf, "\t\t\"ALPN Protocol\" : \"%s\",\n", NULL_TO_DASH(tls_stats->alpn_proto));
	wget_buffer_printf_append(buf, "\t\t\"Resumed\" : \"%s\",\n",
		tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No");
	wget_buffer_printf_append(buf, "\t\t\"TCP Protocol\" : \"%s\",\n",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"HTTP/1.1" :
			(tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"));
	wget_buffer_printf_append(buf, "\t\t\"Cert-chain Size\" : %d,\n", tls_stats->cert_chain_size);
	wget_buffer_printf_append(buf, "\t\t\"TLS negotiation duration (ms)\" : %lld\n", tls_stats->millisecs);
	wget_buffer_printf_append(buf, "\t},\n");
}

static void stats_print_csv_tls_entry(wget_buffer_t *buf, const tls_stats_t *tls_stats)
{
	wget_buffer_printf_append(buf, "%s,%s,%s,%s,%s,%s,%s,%d,%lld\n",
		NULL_TO_DASH(tls_stats->hostname),
		NULL_TO_DASH(tls_stats->version),
		NULL_TO_DASH(tls_stats->false_start),
		NULL_TO_DASH(tls_stats->tfo),
		NULL_TO_DASH(tls_stats->alpn_proto),
		tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"HTTP/1.1" :
			(tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"),
		tls_stats->cert_chain_size,
		tls_stats->millisecs);
}

static void stats_print_human_server_entry(wget_buffer_t *buf, const server_stats_t *server_stats)
{
	wget_buffer_printf_append(buf, "  %s:\n", NULL_TO_DASH(server_stats->hostname));
	wget_buffer_printf_append(buf, "    IP             : %s\n", NULL_TO_DASH(server_stats->ip));
	wget_buffer_printf_append(buf, "    SCHEME         : %s\n", NULL_TO_DASH(server_stats->scheme));
	wget_buffer_printf_append(buf, "    HPKP           : %s\n", stats_server_hpkp(server_stats->hpkp));
	wget_buffer_printf_append(buf, "    HPKP New Entry : %s\n", NULL_TO_DASH(server_stats->hpkp_new));
	wget_buffer_printf_append(buf, "    HSTS           : %s\n", NULL_TO_DASH(server_stats->hsts));
	wget_buffer_printf_append(buf, "    CSP            : %s\n\n", NULL_TO_DASH(server_stats->csp));
}

static void stats_print_json_server_entry(wget_buffer_t *buf, const server_stats_t *server_stats)
{
	wget_buffer_printf_append(buf, "\t{\n");
	wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(server_stats->hostname));
	wget_buffer_printf_append(buf, "\t\t\"IP\" : \"%s\",\n", NULL_TO_DASH(server_stats->ip));
	wget_buffer_printf_append(buf, "\t\t\"SCHEME\" : \"%s\",\n", NULL_TO_DASH(server_stats->scheme));
	wget_buffer_printf_append(buf, "\t\t\"HPKP\" : \"%s\",\n", stats_server_hpkp(server_stats->hpkp));
	wget_buffer_printf_append(buf, "\t\t\"HPKP New Entry\" : \"%s\",\n", NULL_TO_DASH(server_stats->hpkp_new));
	wget_buffer_printf_append(buf, "\t\t\"HSTS\" : \"%s\",\n", NULL_TO_DASH(server_stats->hsts));
	wget_buffer_printf_append(buf, "\t\t\"CSP\" : \"%s\"\n", NULL_TO_DASH(server_stats->csp));
	wget_buffer_printf_append(buf, "\t},\n");
}

static void stats_print_csv_server_entry(wget_buffer_t *buf, const server_stats_t *server_stats)
{
	wget_buffer_printf_append(buf, "%s,%s,%s,%s,%s,%s,%s\n",
		NULL_TO_DASH(server_stats->hostname),
		NULL_TO_DASH(server_stats->ip),
		NULL_TO_DASH(server_stats->scheme),
		stats_server_hpkp(server_stats->hpkp),
		NULL_TO_DASH(server_stats->hpkp_new),
		NULL_TO_DASH(server_stats->hsts),
		NULL_TO_DASH(server_stats->csp));
}

static void stats_print_human_ocsp_entry(wget_buffer_t *buf, const ocsp_stats_t *ocsp_stats)
{
	wget_buffer_printf_append(buf, "  %s:\n", ocsp_stats->hostname);
	wget_buffer_printf_append(buf, "    VALID          : %d\n", ocsp_stats->nvalid);
	wget_buffer_printf_append(buf, "    REVOKED        : %d\n", ocsp_stats->nrevoked);
	wget_buffer_printf_append(buf, "    IGNORED        : %d\n\n", ocsp_stats->nignored);
}

static void stats_print_json_ocsp_entry(wget_buffer_t *buf, const ocsp_stats_t *ocsp_stats)
{
	wget_buffer_printf_append(buf, "\t{\n");
	wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(ocsp_stats->hostname));
	wget_buffer_printf_append(buf, "\t\t\"VALID\" : %d,\n", ocsp_stats->nvalid);
	wget_buffer_printf_append(buf, "\t\t\"REVOKED\" : %d,\n", ocsp_stats->nrevoked);
	wget_buffer_printf_append(buf, "\t\t\"IGNORED\" : %d\n", ocsp_stats->nignored);
	wget_buffer_printf_append(buf, "\t},\n");
}

static void stats_print_csv_ocsp_entry(wget_buffer_t *buf, const ocsp_stats_t *ocsp_stats)
{
	wget_buffer_printf_append(buf, "%s,%d,%d,%d\n",
		NULL_TO_DASH(ocsp_stats->hostname), ocsp_stats->nvalid, ocsp_stats->nrevoked, ocsp_stats->nignored);
}

static void _stats_print(const wget_vector_t *v, wget_vector_browse_t browse, FILE *fp, wget_buffer_t *buf)
{
	for (int it = 0; it < wget_vector_size(v); it++) {
		browse(buf, wget_vector_get(v, it));

		if ((buf->length > 64*1024)) {
			fprintf(fp, "%s", buf->data);
			wget_buffer_reset(buf);
		}
	}

	if (buf->length)
		fprintf(fp, "%s", buf->data);
}

static void stats_print_human(wget_stats_type_t type)
{
	FILE *fp;
	const char *filename;
	wget_buffer_t buf;
	char sbuf[4096];

	if ((int) type < 0 || type >= countof(stats_opts)) {
		error_printf("Unknown stats type %d\n", (int) type);
		return;
	}

	filename = stats_opts[type].file;

	if (filename && *filename && wget_strcmp(filename, "-"))
		fp = fopen(filename, "w");
	else
		fp = stdout;

	if (!fp) {
		error_printf("File could not be opened %s\n", filename);
		return;
	}

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	switch (type) {
	case WGET_STATS_TYPE_DNS:
		wget_buffer_printf(&buf, "\nDNS timings:\n");
		wget_buffer_printf_append(&buf, "  %4s %s\n", "ms", "Host");

		_stats_print(dns_stats_v, (wget_vector_browse_t) stats_print_human_dns_entry, fp, &buf);

		if (fp != stdout)
			info_printf("DNS stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_TLS:
		wget_buffer_printf(&buf, "\nTLS Statistics:\n");

		_stats_print(tls_stats_v, (wget_vector_browse_t) stats_print_human_tls_entry, fp, &buf);

		if (fp != stdout)
			info_printf("TLS stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_SERVER:
		wget_buffer_printf(&buf, "\nServer Statistics:\n");

		_stats_print(server_stats_v, (wget_vector_browse_t) stats_print_human_server_entry, fp, &buf);

		if (fp != stdout)
			info_printf("Server stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_OCSP:
		wget_buffer_printf(&buf, "\nOCSP Statistics:\n");

		_stats_print(ocsp_stats_v, (wget_vector_browse_t) stats_print_human_ocsp_entry, fp, &buf);

		if (fp != stdout)
			info_printf("OCSP stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_SITE:
		wget_buffer_printf(&buf, "\nSite Statistics:\n");

		print_site_stats(&buf, fp);

		if (fp != stdout)
			info_printf("Site stats saved in %s\n", filename);

		break;

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}

	if (fp != stdout)
		fclose(fp);

	wget_buffer_deinit(&buf);
}

static void stats_print_json(wget_stats_type_t type)
{
	FILE *fp;
	const char *filename;
	wget_buffer_t buf;
	char sbuf[4096];

	if ((int) type < 0 || type >= countof(stats_opts)) {
		error_printf("Unknown stats type %d\n", (int) type);
		return;
	}

	filename = stats_opts[type].file;

	if (filename && *filename && wget_strcmp(filename, "-"))
		fp = fopen(filename, "w");
	else
		fp = stdout;

	if (!fp) {
		error_printf("File could not be opened %s\n", filename);
		return;
	}

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	switch (type) {
	case WGET_STATS_TYPE_DNS:
		wget_buffer_printf(&buf, "[\n");

		_stats_print(dns_stats_v, (wget_vector_browse_t) stats_print_json_dns_entry, fp, &buf);

		if (fp != stdout)
			info_printf("DNS stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_TLS:
		wget_buffer_printf(&buf, "[\n");

		_stats_print(tls_stats_v, (wget_vector_browse_t) stats_print_json_tls_entry, fp, &buf);

		if (fp != stdout)
			info_printf("TLS stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_SERVER:
		wget_buffer_printf(&buf, "[\n");

		_stats_print(server_stats_v, (wget_vector_browse_t) stats_print_json_server_entry, fp, &buf);

		if (fp != stdout)
			info_printf("Server stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_OCSP:
		wget_buffer_printf(&buf, "[\n");

		_stats_print(ocsp_stats_v, (wget_vector_browse_t) stats_print_json_ocsp_entry, fp, &buf);

		if (fp != stdout)
			info_printf("OCSP stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_SITE:
		break;

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}

	fprintf(fp, "]\n");

	if (fp != stdout)
		fclose(fp);

	wget_buffer_deinit(&buf);
}

static void stats_print_csv(wget_stats_type_t type)
{
	FILE *fp;
	const char *filename;
	wget_buffer_t buf;
	char sbuf[4096];

	if ((int) type < 0 || type >= countof(stats_opts)) {
		error_printf("Unknown stats type %d\n", (int) type);
		return;
	}

	filename = stats_opts[type].file;

	if (filename && *filename && wget_strcmp(filename, "-"))
		fp = fopen(filename, "w");
	else
		fp = stdout;

	if (!fp) {
		error_printf("File could not be opened %s\n", filename);
		return;
	}

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	switch (type) {
	case WGET_STATS_TYPE_DNS:
		wget_buffer_printf(&buf, "%s\n", "Hostname,IP,Port,DNS resolution duration (ms)");

		_stats_print(dns_stats_v, (wget_vector_browse_t) stats_print_csv_dns_entry, fp, &buf);

		if (fp != stdout)
			info_printf("DNS stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_TLS:
		wget_buffer_printf(&buf, "%s\n", "Hostname,Version,False Start,TFO,ALPN,Resumed,TCP,Cert-chain Length,TLS negotiation duration (ms)");

		_stats_print(tls_stats_v, (wget_vector_browse_t) stats_print_csv_tls_entry, fp, &buf);

		if (fp != stdout)
			info_printf("TLS stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_SERVER:
		wget_buffer_printf(&buf, "%s\n", "Hostname,HPKP,HPKP New Entry,HSTS,CSP");

		_stats_print(server_stats_v, (wget_vector_browse_t) stats_print_csv_server_entry, fp, &buf);

		if (fp != stdout)
			info_printf("Server stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_OCSP:
		wget_buffer_printf(&buf, "%s\n", "Hostname,VALID,REVOKED,IGNORED");

		_stats_print(ocsp_stats_v, (wget_vector_browse_t) stats_print_csv_ocsp_entry, fp, &buf);

		if (fp != stdout)
			info_printf("OCSP stats saved in %s\n", filename);

		break;

	case WGET_STATS_TYPE_SITE:
		wget_buffer_printf(&buf, "\nSite Statistics:\n");

		print_site_stats_cvs(&buf, fp);

		if (fp != stdout)
			info_printf("Site stats saved in %s\n", filename);

		break;

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}

	if (fp != stdout)
		fclose(fp);

	wget_buffer_deinit(&buf);
}

void stats_print(void)
{
	for (wget_stats_type_t type = 0; (int) type < (int) countof(stats_opts); type++) {
		if (!stats_opts[type].status)
			continue;

		switch (stats_opts[type].format) {
		case STATS_FORMAT_HUMAN:
			stats_print_human(type);
			break;

		case STATS_FORMAT_CSV:
			stats_print_csv(type);
			break;

		case STATS_FORMAT_JSON:
			stats_print_json(type);
			break;

		default: error_printf("Unknown stats format %d\n", (int) stats_opts[type].format);
			break;
		}
	}
}
