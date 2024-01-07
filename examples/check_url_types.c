/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * Read URLs from stdin and print numbers of HTTP / HTTPS links found in HTML.
 * Input format is Alexa top-x, e.g. <id>,<domain>
 *
 */

#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#	include <signal.h>
#endif
#include <wget.h>

typedef struct {
	int
		id,
		http_links, https_links,
		http_links_same_host, https_links_same_host,
		status,
		redirs,
		redir_insecure,
		landed_on_https;
	char
		host[256];
} stats_t;

static stats_t stats;

static void write_stats(void)
{
	FILE *fp;

	if ((fp = fopen("out.csv", "a"))) {
		fprintf(fp, "%d,%s,%d,%d,%d,%d,%d,%d,%d,%d\n",
			stats.id, stats.host, stats.status, stats.redir_insecure, stats.redirs, stats.landed_on_https,
			stats.http_links_same_host, stats.http_links,
			stats.https_links_same_host, stats.https_links);
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

static void html_parse(const char *html, size_t html_len, const char *encoding, const char *hosturl)
{
	wget_iri *base = wget_iri_parse(hosturl, "utf-8");
	wget_iri *allocated_base = NULL;
	const char *reason;
	char *utf8 = NULL;
	wget_buffer buf;
	char sbuf[1024];

	// https://html.spec.whatwg.org/#determining-the-character-encoding
	if ((unsigned char)html[0] == 0xFE && (unsigned char)html[1] == 0xFF) {
		// Big-endian UTF-16
		encoding = "UTF-16BE";
		reason = "set by BOM";

		// adjust behind BOM, ignore trailing single byte
		html += 2;
		html_len -= 2;
	} else if ((unsigned char)html[0] == 0xFF && (unsigned char)html[1] == 0xFE) {
		// Little-endian UTF-16
		encoding = "UTF-16LE";
		reason = "set by BOM";

		// adjust behind BOM
		html += 2;
		html_len -= 2;
	} else if ((unsigned char)html[0] == 0xEF && (unsigned char)html[1] == 0xBB && (unsigned char)html[2] == 0xBF) {
		// UTF-8
		encoding = "UTF-8";
		reason = "set by BOM";

		// adjust behind BOM
		html += 3;
		html_len -= 3;
	} else {
		reason = "set by server response";
	}

//	size_t n;
//	html_len -= html_len & 3; // ignore single trailing byte, else charset conversion fails

	if (wget_memiconv(encoding, html, html_len, "UTF-8", &utf8, NULL) == 0) {
		wget_info_printf("  Convert encoding '%s' (%s) to UTF-8\n", encoding ? encoding : "iso-8859-1", reason);
		html = utf8;
	} else {
		wget_info_printf("Failed to convert non-ASCII encoding '%s' (%s) to UTF-8, skip parsing\n", encoding, reason);
		return;
	}

	wget_html_parsed_result *parsed  = wget_html_get_urls_inline(html, NULL, NULL);

	if (!encoding) {
		if (parsed->encoding) {
			encoding = parsed->encoding;
			reason = "set by document";
		} else {
			encoding = "CP1252"; // default encoding for HTML5 (pre-HTML5 is iso-8859-1)
			reason = "default, encoding not specified";
		}
	}

	wget_info_printf("  URI content encoding = '%s' (%s)\n", encoding, reason);

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	if (parsed->base.p) {
		wget_info_printf("  base='%.*s'\n", (int) parsed->base.len, parsed->base.p);
		if (_normalize_uri(base, &parsed->base, encoding, &buf) == 0) {
			if (buf.length) {
				wget_iri *newbase = wget_iri_parse(buf.data, "utf-8");
				if (newbase) {
					wget_iri_free(&base);
					base = newbase;
				}
			}
		}
	}

	for (int it = 0; it < wget_vector_size(parsed->uris); it++) {
		wget_html_parsed_url *html_url = wget_vector_get(parsed->uris, it);
		wget_string *url = &html_url->url;

		if (_normalize_uri(base, url, encoding, &buf) || buf.length == 0)
			continue;

		wget_iri *canon_url = wget_iri_parse(buf.data, "utf-8");
		if (!canon_url)
			continue;

		int same_host = !wget_strcasecmp(canon_url->host, base->host);

		if (canon_url->scheme == WGET_IRI_SCHEME_HTTPS) {
			stats.https_links++;
			stats.https_links_same_host += same_host;
		}
		else if (canon_url->scheme == WGET_IRI_SCHEME_HTTP) {
			stats.http_links++;
			stats.http_links_same_host += same_host;
//			if (same_host)
//				wget_info_printf("  '%s'\n", canon_url->uri);
		}

		wget_iri_free(&canon_url);
	}

	wget_buffer_deinit(&buf);
	wget_iri_free(&allocated_base);
	wget_html_free_urls_inline(&parsed);
	wget_iri_free(&base);
	wget_xfree(utf8);

	wget_info_printf("  same host: http=%d https=%d\n", stats.http_links_same_host, stats.https_links_same_host);
	wget_info_printf("      total: http=%d https=%d\n", stats.http_links, stats.https_links);
}

int main(int argc WGET_GCC_UNUSED, const char *const *argv WGET_GCC_UNUSED)
{
//	wget_http_connection *conn = NULL;
	wget_http_response *resp = NULL;
	char *url = NULL;

	// set up libwget global configuration
	wget_global_init(
//		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stdout,
		WGET_INFO_STREAM, stdout,
		WGET_DNS_CACHING, 1,
		0);

#ifndef _WIN32
	struct sigaction sig_action = { .sa_handler = SIG_IGN };
	sigaction(SIGPIPE, &sig_action, NULL); // this forces socket error return
#endif

	// set global timeouts to 5s
	wget_tcp_set_timeout(NULL, 5000);
	wget_tcp_set_connect_timeout(NULL, 5000);
	wget_dns_set_timeout(NULL, 5000);

	// OCSP off
	wget_ssl_set_config_int(WGET_SSL_OCSP, 0);
	wget_ssl_set_config_int(WGET_SSL_OCSP_STAPLING, 0);

	while (fscanf(stdin, "%d,%255s", &stats.id, stats.host) == 2) {

		wget_xfree(url);
		if (!wget_strncasecmp_ascii(stats.host, "http://", 7))
			url = wget_aprintf("https://%s", stats.host + 7);
		else if (wget_strncasecmp_ascii(stats.host, "https://", 8))
			url = wget_aprintf("https://%s", stats.host);
		else
			url = wget_strdup(stats.host);

		stats.http_links = stats. https_links = 0;
		stats.http_links_same_host = stats.https_links_same_host = 0;
		stats.status = -1;
		stats.redirs = stats.redir_insecure = stats.landed_on_https = 0;

		// follow up to max 10 redirections, stop if one is plain text
		for (int redirs = 0, max = 10; redirs < max; redirs++) {

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

//			wget_info_printf("conn %p\n", conn);
//			stats.landed_on_https = 1 + (conn->protocol == WGET_PROTOCOL_HTTP_2_0);
			stats.landed_on_https = 1;

			if (wget_strcasecmp_ascii(resp->content_type, "text/html")) {
				wget_info_printf("  No HTML: %s\n", resp->content_type);
				break;
			}

			if (resp->body)
				html_parse(resp->body->data, resp->body->length, resp->content_type_encoding, url);

			break;
		}

		// free the response
		wget_http_free_response(&resp);

		// close connection if still open
//		wget_http_close(&conn);

		write_stats();
	}

	wget_xfree(url);

	// free resources - needed for valgrind testing
	wget_global_deinit();

	return 0;
}
