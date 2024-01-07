/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Read URLs from stdin and download into results/domain/.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#	include <signal.h>
#endif
#include <wget.h>

typedef struct {
	int
		http_links, https_links,
		status,
		redirs,
		redir_insecure,
		landed_on_https;
	char
		host[256],
		content_type[128];
} stats_t;

#define MAXTHREADS 500

static void *downloader_thread(void *p);

static void write_stats(const stats_t *stats)
{
	FILE *fp;

	if ((fp = fopen("out.csv", "a"))) {
		fprintf(fp, "%s,%d,%d,%d,%d,%s\n",
			stats->host, stats->status, stats->redir_insecure, stats->redirs, stats->landed_on_https,
			stats->content_type);
		fclose(fp);
	}
}

/*
 * helper function: percent-unescape, convert to utf-8, create URL string using base
 */
static int _normalize_uri(wget_iri *base, wget_string *url, const char *encoding, wget_buffer *buf)
{
	char *urlpart_encoded;
	size_t urlpart_encoded_length;
	int rc;

	if (url->len == 0 || (url->len >= 1 && *url->p == '#')) // ignore e.g. href='#'
		return -1;

	char *urlpart = wget_strmemdup(url->p, url->len);
	if (!urlpart)
		return -2;

	wget_iri_unescape_url_inline(urlpart);
	rc = wget_memiconv(encoding, urlpart, strlen(urlpart), "utf-8", &urlpart_encoded, &urlpart_encoded_length);
	wget_xfree(urlpart);

	if (rc)
		return -3;

	rc = !wget_iri_relative_to_abs(base, urlpart_encoded, urlpart_encoded_length, buf);
	wget_xfree(urlpart_encoded);

	if (rc)
		return -4;

	return 0;
}

static char *_normalize_location(const char *base, const char *url)
{
	wget_buffer buf;
	wget_string url_s = { .p = url, .len = strlen(url) };
	wget_iri *base_iri = wget_iri_parse(base, "utf-8");
	char sbuf[1024], *norm_url = NULL;

	if (!base_iri)
		return NULL;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	if (_normalize_uri(base_iri, &url_s, "utf-8", &buf) == 0) {
		norm_url = wget_strmemdup(buf.data, buf.length);
	}
	wget_buffer_deinit(&buf);

	wget_iri_free(&base_iri);

	return norm_url;
}

int main(int argc WGET_GCC_UNUSED, const char *const *argv WGET_GCC_UNUSED)
{
	static wget_thread downloaders[MAXTHREADS];

	// set up libwget global configuration
	wget_global_init(
//		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stdout,
		WGET_INFO_STREAM, stdout,
		WGET_DNS_CACHING, 0,
		0);

#ifndef _WIN32
	struct sigaction sig_action = { .sa_handler = SIG_IGN };
	sigaction(SIGPIPE, &sig_action, NULL); // this forces socket error return
#endif

	// set global timeouts to 5s
	wget_tcp_set_timeout(NULL, 3000);
	wget_tcp_set_connect_timeout(NULL, 3000);

	// OCSP off
	wget_ssl_set_config_int(WGET_SSL_OCSP, 0);
	wget_ssl_set_config_int(WGET_SSL_OCSP_STAPLING, 0);

	// don't check cert and SNI
	wget_ssl_set_config_int(WGET_SSL_CHECK_CERTIFICATE, 0);
	wget_ssl_set_config_int(WGET_SSL_CHECK_HOSTNAME, 0);

	// start threads
	for (int rc, it = 0; it < MAXTHREADS; it++) {
		if ((rc = wget_thread_start(&downloaders[it], downloader_thread, NULL, 0)) != 0) {
			wget_error_printf("Failed to start thread, error %d\n", rc);
		}
	}

	// wait until threads are done
	for (int rc, it = 0; it < MAXTHREADS; it++) {
		if ((rc = wget_thread_join(&downloaders[it])) != 0)
			wget_error_printf("Failed to wait for downloader #%d (%d %d)\n", it, rc, errno);
	}

	// free resources - needed for valgrind testing
	wget_global_deinit();

	return 0;
}

static void *downloader_thread(WGET_GCC_UNUSED void *p)
{
	stats_t stats;
	wget_http_response *resp = NULL;
	char *url = NULL;

	while (fscanf(stdin, "%255s", stats.host) == 1) {
		wget_xfree(url);

		if (!wget_strncasecmp_ascii(stats.host, "http://", 7))
			url = wget_strdup(stats.host);
		else if (!wget_strncasecmp_ascii(stats.host, "https://", 8))
			url = wget_strdup(stats.host);
		else
			url = wget_aprintf("http://%s", stats.host);

		stats.http_links = stats. https_links = 0;
		stats.status = -1;
		stats.redirs = stats.redir_insecure = stats.landed_on_https = 0;
		*stats.content_type = 0;

		// follow up to max 5 redirections, stop if one is plain text
		for (int redirs = 0, max = 5; redirs < max; redirs++) {

			wget_http_free_response(&resp);
//			wget_http_close(&conn);

			wget_info_printf("%s%s\n", redirs ? "  -> " : "", url);

			// execute an HTTP GET request and return the response
			resp = wget_http_get(
				WGET_HTTP_URL, url,
				WGET_HTTP_HEADER_ADD, "User-Agent", "Mozilla/5.0",
				WGET_HTTP_HEADER_ADD, "Accept-Encoding", "gzip, br",
				WGET_HTTP_HEADER_ADD, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", /* some sites need this */
				WGET_HTTP_HEADER_ADD, "Accept-Encoding", "gzip, br",
//				WGET_HTTP_HEADER_ADD, "Upgrade-Insecure-Requests", "1",
				WGET_HTTP_MAX_REDIRECTIONS, 0,
//				WGET_HTTP_CONNECTION_PTR, &conn,
				0);

			if (!resp) {
				wget_info_printf("  No connection / response\n");
				break;
			}

			snprintf(stats.content_type, sizeof(stats.content_type), "%s", resp->content_type);

			stats.status = resp->code;
			if (resp->code != 200) {
				if (resp->location) {
					stats.redirs++;

					wget_info_printf("  Response code %hd, %s\n", resp->code, resp->location);

					char *newurl = _normalize_location(url, resp->location);
					if (!newurl) {
						wget_info_printf("  Failed to normalize '%s', '%s'\n", url, resp->location);
						break;
					}
					wget_xfree(url);
					url = newurl;

					if (wget_strncasecmp(url, "https://", 8))
						stats.redir_insecure++;

					continue;
				}

				wget_info_printf("  Response code %hd\n", resp->code);
				break;
			}

			if (wget_strncasecmp(url, "https://", 8))
				break; // no need to parse, we landed on HTTP

			stats.landed_on_https = 1;

			break;
		}

		// free the response
		wget_http_free_response(&resp);

		// close connection if still open
//		wget_http_close(&conn);

		write_stats(&stats);
	}

	wget_xfree(url);

	return NULL;
}
