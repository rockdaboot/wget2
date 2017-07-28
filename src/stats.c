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

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats))
			dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
		else
			dns_stats.host = wget_strdup("-");

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats))
			dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));
		else
			dns_stats.ip = wget_strdup("-");

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats))
			dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));
		else
			dns_stats.millisecs = -1;

		wget_thread_mutex_lock(&dns_mutex);
		wget_vector_add(dns_stats_v, &dns_stats, sizeof(dns_stats_t));
		wget_thread_mutex_unlock(&dns_mutex);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		tls_stats_t tls_stats;

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats))
			tls_stats.hostname = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats));
		else
			tls_stats.hostname = wget_strdup("-");

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats))
			tls_stats.version = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats));
		else
			tls_stats.version = wget_strdup("-");

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats))
			tls_stats.false_start = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats));
		else
			tls_stats.false_start = wget_strdup("-");

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats))
			tls_stats.tfo = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats));
		else
			tls_stats.tfo = wget_strdup("-");

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats))
			tls_stats.alpn_proto = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats));
		else
			tls_stats.alpn_proto = wget_strdup("-");

		tls_stats.tls_con = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats));

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats))
			tls_stats.resumed = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats));
		else
			tls_stats.resumed = -1;

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats))
			tls_stats.tcp_protocol = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats));
		else
			tls_stats.tcp_protocol = -1;

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats))
			tls_stats.millisecs = *((long long *)wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats));
		else
			tls_stats.millisecs = -1;

		if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats))
			tls_stats.cert_chain_size = *((int *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats));
		else
			tls_stats.cert_chain_size = -1;

		wget_thread_mutex_lock(&tls_mutex);
		wget_vector_add(tls_stats_v, &tls_stats, sizeof(tls_stats_t));
		wget_thread_mutex_unlock(&tls_mutex);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		server_stats_t server_stats;

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats))
			server_stats.hostname = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats));
		else
			server_stats.hostname = wget_strdup("-");

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_IP, stats))
			server_stats.ip = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_IP, stats));
		else
			server_stats.ip = wget_strdup("-");

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_SCHEME, stats))
			server_stats.scheme = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_SCHEME, stats));
		else
			server_stats.scheme = wget_strdup("-");

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats))
			server_stats.hpkp = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats));
		else
			server_stats.hpkp = -1;

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats))
			server_stats.hpkp_new = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats));
		else
			server_stats.hpkp_new = wget_strdup("-");

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats))
			server_stats.hsts = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats));
		else
			server_stats.hsts = wget_strdup("-");

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats))
			server_stats.csp = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats));
		else
			server_stats.csp = wget_strdup("-");

		wget_thread_mutex_lock(&server_mutex);
		wget_vector_add(server_stats_v, &server_stats, sizeof(server_stats_t));
		wget_thread_mutex_unlock(&server_mutex);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		ocsp_stats_t ocsp_stats;

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats))
			ocsp_stats.hostname = wget_strdup(wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats));
		else
			ocsp_stats.hostname = wget_strdup("-");

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats))
			ocsp_stats.nvalid = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats));
		else
			ocsp_stats.nvalid = -1;

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats))
			ocsp_stats.nrevoked = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats));
		else
			ocsp_stats.nrevoked = -1;

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats))
			ocsp_stats.nignored = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats));
		else
			ocsp_stats.nignored = -1;

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

}

static const char *stats_server_hpkp(const char hpkp)
{
	const char *msg;

	switch (hpkp) {
	case WGET_STATS_HPKP_NO:
		msg = "No existing entry in hpkp db";
		break;
	case WGET_STATS_HPKP_MATCH:
		msg = "Pubkey pinning matched";
		break;
	case WGET_STATS_HPKP_NOMATCH:
		msg = "Pubkey pinning mismatch";
		break;
	case -1:
		msg = "-";
		break;
	default:
		error_printf("Unknown HPKP stats type\n");
		msg = "-";
		break;
	}

	return msg;
}

static void stats_print_human(wget_stats_type_t type)
{
	wget_buffer_t *buf = wget_buffer_alloc(0);
	FILE *fp;

	switch (type) {
	case WGET_STATS_TYPE_DNS: {
		const char *filename = stats_opts[WGET_STATS_TYPE_DNS].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "\nDNS timings:\n");
			wget_buffer_printf_append(buf, "  %4s %s\n", "ms", "Host");
			for (int it = 0; it < wget_vector_size(dns_stats_v); it++) {
				const dns_stats_t *dns_stats = wget_vector_get(dns_stats_v, it);

				wget_buffer_printf_append(buf, "  %4lld %s (%s)\n", dns_stats->millisecs, dns_stats->host, dns_stats->ip);

				if ((buf->length > 64*1024) || (it == wget_vector_size(dns_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("DNS stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		const char *filename = stats_opts[WGET_STATS_TYPE_TLS].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "\nTLS Statistics:\n");
			for (int it = 0; it < wget_vector_size(tls_stats_v); it++) {
				const tls_stats_t *tls_stats = wget_vector_get(tls_stats_v, it);

				wget_buffer_printf_append(buf, "  %s:\n", tls_stats->hostname);
				wget_buffer_printf_append(buf, "    Version         : %s\n", tls_stats->version);
				wget_buffer_printf_append(buf, "    False Start     : %s\n", tls_stats->false_start);
				wget_buffer_printf_append(buf, "    TFO             : %s\n", tls_stats->tfo);
				wget_buffer_printf_append(buf, "    ALPN Protocol   : %s\n", tls_stats->alpn_proto);
				wget_buffer_printf_append(buf, "    Resumed         : %s\n",
						tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No");
				wget_buffer_printf_append(buf, "    TCP Protocol    : %s\n",
						tls_stats->tcp_protocol ? (tls_stats->tcp_protocol == 1 ? "HTTP/2" : "-") : "HTTP/1.1");
				wget_buffer_printf_append(buf, "    Cert Chain Size : %d\n", tls_stats->cert_chain_size);
				wget_buffer_printf_append(buf, "    TLS negotiation\n");
				wget_buffer_printf_append(buf, "    duration (ms)   : %lld\n\n", tls_stats->millisecs);

				if ((buf->length > 64*1024) || (it == wget_vector_size(tls_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("TLS stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		const char *filename = stats_opts[WGET_STATS_TYPE_SERVER].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "\nServer Statistics:\n");
			for (int it = 0; it < wget_vector_size(server_stats_v); it++) {
				const server_stats_t *server_stats = wget_vector_get(server_stats_v, it);

				wget_buffer_printf_append(buf, "  %s:\n", server_stats->hostname);
				wget_buffer_printf_append(buf, "    IP             : %s\n", server_stats->ip);
				wget_buffer_printf_append(buf, "    SCHEME         : %s\n", server_stats->scheme);
				wget_buffer_printf_append(buf, "    HPKP           : %s\n", stats_server_hpkp(server_stats->hpkp));
				wget_buffer_printf_append(buf, "    HPKP New Entry : %s\n", server_stats->hpkp_new);
				wget_buffer_printf_append(buf, "    HSTS           : %s\n", server_stats->hsts);
				wget_buffer_printf_append(buf, "    CSP            : %s\n\n", server_stats->csp);

				if ((buf->length > 64*1024) || (it == wget_vector_size(server_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("Server stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		const char *filename = stats_opts[WGET_STATS_TYPE_OCSP].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "\nOCSP Statistics:\n");
			for (int it = 0; it < wget_vector_size(ocsp_stats_v); it++) {
				const ocsp_stats_t *ocsp_stats = wget_vector_get(ocsp_stats_v, it);

				wget_buffer_printf_append(buf, "  %s:\n", ocsp_stats->hostname);
				wget_buffer_printf_append(buf, "    VALID          : %d\n", ocsp_stats->nvalid);
				wget_buffer_printf_append(buf, "    REVOKED        : %d\n", ocsp_stats->nrevoked);
				wget_buffer_printf_append(buf, "    IGNORED        : %d\n\n", ocsp_stats->nignored);

				if ((buf->length > 64*1024) || (it == wget_vector_size(ocsp_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("OCSP stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
	}
}

static void stats_print_json(wget_stats_type_t type)
{
	wget_buffer_t *buf = wget_buffer_alloc(0);
	FILE *fp;

	switch (type) {
	case WGET_STATS_TYPE_DNS: {
		const char *filename = stats_opts[WGET_STATS_TYPE_DNS].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "[\n");
			for (int it = 0; it < wget_vector_size(dns_stats_v); it++) {
				const dns_stats_t *dns_stats = wget_vector_get(dns_stats_v, it);
				wget_buffer_printf_append(buf, "\t{\n");
				wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", dns_stats->host);
				wget_buffer_printf_append(buf, "\t\t\"IP\" : \"%s\",\n", dns_stats->ip);
				wget_buffer_printf_append(buf, "\t\t\"DNS resolution duration (ms)\" : %lld\n", dns_stats->millisecs);
				wget_buffer_printf_append(buf, it < wget_vector_size(dns_stats_v) - 1 ? "\t},\n" : "\t}\n]\n");

				if ((buf->length > 64*1024) || (it == wget_vector_size(dns_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("DNS stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		const char *filename = stats_opts[WGET_STATS_TYPE_TLS].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "[\n");
			for (int it = 0; it < wget_vector_size(tls_stats_v); it++) {
				const tls_stats_t *tls_stats = wget_vector_get(tls_stats_v, it);
				wget_buffer_printf_append(buf, "\t{\n");
				wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", tls_stats->hostname);
				wget_buffer_printf_append(buf, "\t\t\"Version\" : \"%s\",\n", tls_stats->version);
				wget_buffer_printf_append(buf, "\t\t\"False Start\" : \"%s\",\n", tls_stats->false_start);
				wget_buffer_printf_append(buf, "\t\t\"TFO\" : \"%s\",\n", tls_stats->tfo);
				wget_buffer_printf_append(buf, "\t\t\"ALPN Protocol\" : \"%s\",\n", tls_stats->alpn_proto);
				wget_buffer_printf_append(buf, "\t\t\"Resumed\" : \"%s\",\n",
						tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No");
				wget_buffer_printf_append(buf, "\t\t\"TCP Protocol\" : \"%s\",\n",
						tls_stats->tcp_protocol ? (tls_stats->tcp_protocol == 1 ? "HTTP/2" : "-") : "HTTP/1.1");
				wget_buffer_printf_append(buf, "\t\t\"Cert-chain Size\" : %d,\n", tls_stats->cert_chain_size);
				wget_buffer_printf_append(buf, "\t\t\"TLS negotiation duration (ms)\" : %lld\n", tls_stats->millisecs);
				wget_buffer_printf_append(buf, it < wget_vector_size(tls_stats_v) - 1 ? "\t},\n" : "\t}\n]\n");

				if ((buf->length > 64*1024) || (it == wget_vector_size(tls_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("TLS stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		const char *filename = stats_opts[WGET_STATS_TYPE_SERVER].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "[\n");
			for (int it = 0; it < wget_vector_size(server_stats_v); it++) {
				const server_stats_t *server_stats = wget_vector_get(server_stats_v, it);
				wget_buffer_printf_append(buf, "\t{\n");
				wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", server_stats->hostname);
				wget_buffer_printf_append(buf, "\t\t\"IP\" : \"%s\",\n", server_stats->ip);
				wget_buffer_printf_append(buf, "\t\t\"SCHEME\" : \"%s\",\n", server_stats->scheme);
				wget_buffer_printf_append(buf, "\t\t\"HPKP\" : \"%s\",\n", stats_server_hpkp(server_stats->hpkp));
				wget_buffer_printf_append(buf, "\t\t\"HPKP New Entry\" : \"%s\",\n", server_stats->hpkp_new);
				wget_buffer_printf_append(buf, "\t\t\"HSTS\" : \"%s\",\n", server_stats->hsts);
				wget_buffer_printf_append(buf, "\t\t\"CSP\" : \"%s\"\n", server_stats->csp);
				wget_buffer_printf_append(buf, it < wget_vector_size(server_stats_v) - 1 ? "\t},\n" : "\t}\n]\n");

				if ((buf->length > 64*1024) || (it == wget_vector_size(server_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("Server stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		const char *filename = stats_opts[WGET_STATS_TYPE_OCSP].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			wget_buffer_printf(buf, "[\n");
			for (int it = 0; it < wget_vector_size(ocsp_stats_v); it++) {
				const ocsp_stats_t *ocsp_stats = wget_vector_get(ocsp_stats_v, it);
				wget_buffer_printf_append(buf, "\t{\n");
				wget_buffer_printf_append(buf, "\t\t\"Hostname\" : \"%s\",\n", ocsp_stats->hostname);
				wget_buffer_printf_append(buf, "\t\t\"VALID\" : %d,\n", ocsp_stats->nvalid);
				wget_buffer_printf_append(buf, "\t\t\"REVOKED\" : %d,\n", ocsp_stats->nrevoked);
				wget_buffer_printf_append(buf, "\t\t\"IGNORED\" : %d\n", ocsp_stats->nignored);
				wget_buffer_printf_append(buf, it < wget_vector_size(ocsp_stats_v) - 1 ? "\t},\n" : "\t}\n]\n");

				if ((buf->length > 64*1024) || (it == wget_vector_size(ocsp_stats_v) - 1)) {
					fprintf(fp, "%s", buf->data);
					wget_buffer_reset(buf);
				}
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("OCSP stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
	}
}

static void stats_print_csv(wget_stats_type_t type)
{
	wget_buffer_t *buf = wget_buffer_alloc(0);
	FILE *fp;

	switch (type) {
	case WGET_STATS_TYPE_DNS: {
		const char *filename = stats_opts[WGET_STATS_TYPE_DNS].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			const char *header = "Hostname,IP,DNS resolution duration (ms)";
			fprintf(fp, "%s\n", header);

			for (int it = 0; it < wget_vector_size(dns_stats_v); it++) {
				const dns_stats_t *dns_stats = wget_vector_get(dns_stats_v, it);

				wget_buffer_printf(buf, "%s,%s,%lld\n", dns_stats->host, dns_stats->ip, dns_stats->millisecs);
				fprintf(fp, "%s", buf->data);
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("DNS stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		const char *filename = stats_opts[WGET_STATS_TYPE_TLS].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			const char *header = "Hostname,Version,False Start,TFO,ALPN,Resumed,TCP,Cert-chain Length,TLS negotiation duration (ms)";
			fprintf(fp, "%s\n", header);

			for (int it = 0; it < wget_vector_size(tls_stats_v); it++) {
				const tls_stats_t *tls_stats = wget_vector_get(tls_stats_v, it);

				wget_buffer_printf(buf, "%s,%s,%s,%s,%s,%s,%s,%d,%lld\n",
						tls_stats->hostname,
						tls_stats->version,
						tls_stats->false_start,
						tls_stats->tfo,
						tls_stats->alpn_proto,
						tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No",
						tls_stats->tcp_protocol ? (tls_stats->tcp_protocol == 1 ? "HTTP/2" : "-") : "HTTP/1.1",
						tls_stats->cert_chain_size,
						tls_stats->millisecs);

				fprintf(fp, "%s", buf->data);
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("TLS stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		const char *filename = stats_opts[WGET_STATS_TYPE_SERVER].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			const char *header = "Hostname,HPKP,HPKP New Entry,HSTS,CSP";
			fprintf(fp, "%s\n", header);

			for (int it = 0; it < wget_vector_size(server_stats_v); it++) {
				const server_stats_t *server_stats = wget_vector_get(server_stats_v, it);

				wget_buffer_printf(buf, "%s,%s,%s,%s,%s,%s,%s\n",
						server_stats->hostname,
						server_stats->ip,
						server_stats->scheme,
						stats_server_hpkp(server_stats->hpkp),
						server_stats->hpkp_new,
						server_stats->hsts,
						server_stats->csp);

				fprintf(fp, "%s", buf->data);
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("Server stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		const char *filename = stats_opts[WGET_STATS_TYPE_OCSP].file;
		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (fp) {
			const char *header = "Hostname,VALID,REVOKED,IGNORED";
			fprintf(fp, "%s\n", header);

			for (int it = 0; it < wget_vector_size(ocsp_stats_v); it++) {
				const ocsp_stats_t *ocsp_stats = wget_vector_get(ocsp_stats_v, it);

				wget_buffer_printf(buf, "%s,%d,%d,%d\n",
						ocsp_stats->hostname, ocsp_stats->nvalid, ocsp_stats->nrevoked, ocsp_stats->nignored);

				fprintf(fp, "%s", buf->data);
			}

			if (fp != stdout) {
				fclose(fp);
				info_printf("OCSP stats saved in %s\n", filename);
			}

		} else
			error_printf("File could not be opened.\n");

		wget_buffer_free(&buf);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
	}
}

void stats_print(void)
{
	if (stats_opts[WGET_STATS_TYPE_DNS].status) {
		switch (stats_opts[WGET_STATS_TYPE_DNS].format) {
		case STATS_FORMAT_HUMAN:
			stats_print_human(WGET_STATS_TYPE_DNS);
			break;

		case STATS_FORMAT_CSV:
			stats_print_csv(WGET_STATS_TYPE_DNS);
			break;

		case STATS_FORMAT_JSON:
			stats_print_json(WGET_STATS_TYPE_DNS);
			break;

		default: error_printf("Unknown stats format.\n");
			break;
		}

		wget_vector_free(&dns_stats_v);
	}

	if (stats_opts[WGET_STATS_TYPE_TLS].status) {
		switch (stats_opts[WGET_STATS_TYPE_TLS].format) {
		case STATS_FORMAT_HUMAN:
			stats_print_human(WGET_STATS_TYPE_TLS);
			break;

		case STATS_FORMAT_CSV:
			stats_print_csv(WGET_STATS_TYPE_TLS);
			break;

		case STATS_FORMAT_JSON:
			stats_print_json(WGET_STATS_TYPE_TLS);
			break;

		default: error_printf("Unknown stats format.\n");
			break;
		}

		wget_vector_free(&tls_stats_v);
	}

	if (stats_opts[WGET_STATS_TYPE_SERVER].status) {
		switch (stats_opts[WGET_STATS_TYPE_SERVER].format) {
		case STATS_FORMAT_HUMAN:
			stats_print_human(WGET_STATS_TYPE_SERVER);
			break;

		case STATS_FORMAT_CSV:
			stats_print_csv(WGET_STATS_TYPE_SERVER);
			break;

		case STATS_FORMAT_JSON:
			stats_print_json(WGET_STATS_TYPE_SERVER);
			break;

		default: error_printf("Unknown stats format.\n");
			break;
		}

		wget_vector_free(&server_stats_v);
	}

	if (stats_opts[WGET_STATS_TYPE_OCSP].status) {
		switch (stats_opts[WGET_STATS_TYPE_OCSP].format) {
		case STATS_FORMAT_HUMAN:
			stats_print_human(WGET_STATS_TYPE_OCSP);
			break;

		case STATS_FORMAT_CSV:
			stats_print_csv(WGET_STATS_TYPE_OCSP);
			break;

		case STATS_FORMAT_JSON:
			stats_print_json(WGET_STATS_TYPE_OCSP);
			break;

		default: error_printf("Unknown stats format.\n");
			break;
		}

		wget_vector_free(&ocsp_stats_v);
	}
}
