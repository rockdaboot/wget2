/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * HTTP routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 26.10.2012               added Cookie support (RFC 6265)
 *
 * Resources:
 * RFC 2616
 * RFC 6265
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef WITH_LIBNGHTTP2
	#include <nghttp2/nghttp2.h>
#endif
#ifdef HAVE_LIBPROXY
#include "proxy.h"
#endif

#include <wget.h>
#include "private.h"
#include "http.h"
#include "net.h"

static char
	abort_indicator;

static wget_vector
	*http_proxies,
	*https_proxies,
	*no_proxies;

// protect access to the above vectors
static wget_thread_mutex
	proxy_mutex,
	hosts_mutex;
static bool
	initialized;

static void http_exit(void)
{
	if (initialized) {
		wget_thread_mutex_destroy(&proxy_mutex);
		wget_thread_mutex_destroy(&hosts_mutex);
		initialized = false;
	}
}

INITIALIZER(http_init)
{
	if (!initialized) {
		wget_thread_mutex_init(&proxy_mutex);
		wget_thread_mutex_init(&hosts_mutex);
		initialized = true;
		atexit(http_exit);
	}
}


/**
 * HTTP API initialization, allocating/preparing the internal resources.
 *
 * On systems with automatic library constructors, this function
 * doesn't have to be called explicitly.
 *
 * This function is not thread-safe.
 */
void wget_http_init(void)
{
	http_init();
}

/**
 * HTTP API deinitialization, free'ing all internal resources.
 *
 * On systems with automatic library destructors, this function
 * doesn't have to be called explicitly.
 *
 * This function is not thread-safe.
 */
void wget_http_exit(void)
{
	http_exit();
}

static wget_server_stats_callback
	*server_stats_callback;

// This is the default function for collecting body data
static wget_http_body_callback body_callback;
static int body_callback(wget_http_response *resp, void *user_data WGET_GCC_UNUSED, const char *data, size_t length)
{
	if (!resp->body)
		resp->body = wget_buffer_alloc(102400);

	wget_buffer_memcat(resp->body, data, length);

	return 0;
}

/*
 * https://tools.ietf.org/html/rfc7230#section-3: Message Format
 * https://tools.ietf.org/html/rfc7230#section-3.1: Start Line
 * https://tools.ietf.org/html/rfc7230#section-3.1.1: Request Line
 * https://tools.ietf.org/html/rfc7230#section-5.3: Request Target
 * https://tools.ietf.org/html/rfc7230#section-5.3.1: Origin Form
 * https://tools.ietf.org/html/rfc7230#section-2.7.3: http and https URI Normalization and Comparison
 *   Characters other than those in the "reserved" set are equivalent to their
 *   percent-encoded octets: the normal form is to not encode them (see Sections 2.1 and 2.2 of [RFC3986]).
 */
wget_http_request *wget_http_create_request(const wget_iri *iri, const char *method)
{
	wget_http_request *req = wget_calloc(1, sizeof(wget_http_request));
	if (!req)
		return NULL;

	wget_buffer_init(&req->esc_resource, req->esc_resource_buf, sizeof(req->esc_resource_buf));
	wget_buffer_init(&req->esc_host, req->esc_host_buf, sizeof(req->esc_host_buf));

	req->scheme = iri->scheme;
	wget_strscpy(req->method, method, sizeof(req->method));
	wget_iri_get_escaped_resource(iri, &req->esc_resource);
	if (wget_ip_is_family(iri->host, WGET_NET_FAMILY_IPV6))
		wget_buffer_printf(&req->esc_host, "[%s]", iri->host);
	else
		wget_iri_get_escaped_host(iri, &req->esc_host);
	req->headers = wget_vector_create(8, NULL);
	wget_vector_set_destructor(req->headers, (wget_vector_destructor *) wget_http_free_param);

	wget_http_add_header(req, "Host", req->esc_host.data);
	wget_http_request_set_body_cb(req, body_callback, NULL);

	return req;
}

void wget_http_request_set_header_cb(wget_http_request *req, wget_http_header_callback *callback, void *user_data)
{
	req->header_callback = callback;
	req->header_user_data = user_data;
}

void wget_http_request_set_body_cb(wget_http_request *req, wget_http_body_callback *callback, void *user_data)
{
	req->body_callback = callback;
	req->body_user_data = user_data;
}

void wget_http_request_set_int(wget_http_request *req, int key, int value)
{
	switch (key) {
	case WGET_HTTP_RESPONSE_KEEPHEADER: req->response_keepheader = value != 0; break;
	case WGET_HTTP_RESPONSE_IGNORELENGTH: req->response_ignorelength = value != 0; break;
	default: error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
	}
}

int wget_http_request_get_int(wget_http_request *req, int key)
{
	switch (key) {
	case WGET_HTTP_RESPONSE_KEEPHEADER: return req->response_keepheader;
	case WGET_HTTP_RESPONSE_IGNORELENGTH: return req->response_ignorelength;
	default:
		error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
		return -1;
	}
}

void wget_http_request_set_ptr(wget_http_request *req, int key, void *value)
{
	switch (key) {
	case WGET_HTTP_USER_DATA: req->user_data = value; break;
	default: error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
	}
}

void *wget_http_request_get_ptr(wget_http_request *req, int key)
{
	switch (key) {
	case WGET_HTTP_USER_DATA: return req->user_data;
	default:
		error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
		return NULL;
	}
}

void wget_http_request_set_body(wget_http_request *req, const char *mimetype, char *body, size_t length)
{
	if (mimetype)
		wget_http_add_header(req, "Content-Type", mimetype);

	req->body = body;
	req->body_length = length;
}

static int http_add_header(wget_http_request *req, const char *name, const char *value)
{
	wget_http_header_param *param = wget_malloc(sizeof(wget_http_header_param));

	if (!param || !name || !value)
		goto err;

	param->name = name;
	param->value = value;

	if (wget_vector_add(req->headers, param) >= 0)
		return WGET_E_SUCCESS;

	xfree(param);

err:
	xfree(value);
	xfree(name);
	return WGET_E_MEMORY;
}

int wget_http_add_header_vprintf(wget_http_request *req, const char *name, const char *fmt, va_list args)
{
	return http_add_header(req, wget_strdup(name), wget_vaprintf(fmt, args));
}

int wget_http_add_header_printf(wget_http_request *req, const char *name, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int rc = wget_http_add_header_vprintf(req, name, fmt, args);
	va_end(args);

	return rc;
}

int wget_http_add_header(wget_http_request *req, const char *name, const char *value)
{
	return http_add_header(req, wget_strdup(name), wget_strdup(value));
}

int wget_http_add_header_param(wget_http_request *req, wget_http_header_param *param)
{
	return http_add_header(req, wget_strdup(param->name), wget_strdup(param->value));
}

void wget_http_add_credentials(wget_http_request *req, wget_http_challenge *challenge, const char *username, const char *password, int proxied)
{
	if (!challenge)
		return;

	if (!username)
		username = "";

	if (!password)
		password = "";

	if (!wget_strcasecmp_ascii(challenge->auth_scheme, "basic")) {
		const char *encoded = wget_base64_encode_printf_alloc("%s:%s", username, password);
		if (proxied)
			wget_http_add_header_printf(req, "Proxy-Authorization", "Basic %s", encoded);
		else
			wget_http_add_header_printf(req, "Authorization", "Basic %s", encoded);
		xfree(encoded);
	}
	else if (!wget_strcasecmp_ascii(challenge->auth_scheme, "digest")) {
		const char *realm, *opaque, *nonce, *qop, *algorithm;
		wget_buffer buf;
		int hashtype, hashlen;

		if (!wget_stringmap_get(challenge->params, "realm", &realm))
			realm = NULL;
		if (!wget_stringmap_get(challenge->params, "opaque", &opaque))
			opaque = NULL;
		if (!wget_stringmap_get(challenge->params, "nonce", &nonce))
			nonce = NULL;
		if (!wget_stringmap_get(challenge->params, "qop", &qop))
			qop = NULL;
		if (!wget_stringmap_get(challenge->params, "algorithm", &algorithm))
			algorithm = NULL;

		if (qop && (wget_strcasecmp_ascii(qop, "auth") && wget_strcasecmp_ascii(qop, "auth-int"))) {
			error_printf(_("Unsupported quality of protection '%s'.\n"), qop);
			return;
		}

		if (!wget_strcasecmp_ascii(algorithm, "MD5") || !wget_strcasecmp_ascii(algorithm, "MD5-sess") || algorithm == NULL) {
			// RFC 2617
			hashtype = WGET_DIGTYPE_MD5;
		} else if (!wget_strcasecmp_ascii(algorithm, "SHA-256") || !wget_strcasecmp_ascii(algorithm, "SHA-256-sess")) {
			// RFC 7616
			hashtype = WGET_DIGTYPE_SHA256;
		} else {
			error_printf(_("Unsupported algorithm '%s'.\n"), algorithm);
			return;
		}

		if (!realm || !nonce)
			return;

		char a1buf[32 * 2 + 1], a2buf[32 * 2 + 1];
		char response_digest[32 * 2 + 1], cnonce[16] = "";

		hashlen = wget_hash_get_len(hashtype);
		size_t buflen = hashlen * 2 + 1;
		if (buflen > sizeof(a1buf))
			return;

		// A1BUF = H(user ":" realm ":" password)
		wget_hash_printf_hex(hashtype, a1buf, buflen, "%s:%s:%s", username, realm, password);

		if (!wget_strcasecmp_ascii(algorithm, "MD5-sess") || !wget_strcasecmp_ascii(algorithm, "SHA-256-sess")) {
			// A1BUF = H( H(user ":" realm ":" password) ":" nonce ":" cnonce )
			wget_snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned) wget_random()); // create random hex string
			wget_hash_printf_hex(hashtype, a1buf, buflen, "%s:%s:%s", a1buf, nonce, cnonce);
		}

		// A2BUF = H(method ":" path)
		wget_hash_printf_hex(hashtype, a2buf, buflen, "%s:/%s", req->method, req->esc_resource.data);

		if (!qop) {
			// RFC 2069 Digest Access Authentication

			// RESPONSE_DIGEST = H(A1BUF ":" nonce ":" A2BUF)
			wget_hash_printf_hex(hashtype, response_digest, buflen, "%s:%s:%s", a1buf, nonce, a2buf);
		} else { // if (!wget_strcasecmp_ascii(qop, "auth") || !wget_strcasecmp_ascii(qop, "auth-int")) {
			// RFC 2617 Digest Access Authentication
			if (!*cnonce)
				wget_snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned) wget_random()); // create random hex string

			// RESPONSE_DIGEST = H(A1BUF ":" nonce ":" nc ":" cnonce ":" qop ": " A2BUF)
			wget_hash_printf_hex(hashtype, response_digest, buflen,
				"%s:%s:00000001:%s:%s:%s", a1buf, nonce, /* nc, */ cnonce, qop, a2buf);
		}

		wget_buffer_init(&buf, NULL, 256);

		wget_buffer_printf(&buf,
			"Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"/%s\", response=\"%s\"",
			username, realm, nonce, req->esc_resource.data, response_digest);

		if (!wget_strcasecmp_ascii(qop,"auth"))
			wget_buffer_printf_append(&buf, ", qop=auth, nc=00000001, cnonce=\"%s\"", cnonce);

		if (opaque)
			wget_buffer_printf_append(&buf, ", opaque=\"%s\"", opaque);

		if (algorithm)
			wget_buffer_printf_append(&buf, ", algorithm=%s", algorithm);

		if (proxied)
			wget_http_add_header(req, "Proxy-Authorization", buf.data);
		else
			wget_http_add_header(req, "Authorization", buf.data);

		wget_buffer_deinit(&buf);
	}
}

/*
static struct config {
	int
		read_timeout;
	unsigned int
		dns_caching : 1;
} config = {
	.read_timeout = -1,
	.dns_caching = 1
};

void http_set_config_int(int key, int value)
{
	switch (key) {
	case HTTP_READ_TIMEOUT: config.read_timeout = value;
	case HTTP_DNS: config.read_timeout = value;
	default: error_printf(_("Unknown config key %d (or value must not be an integer)\n"), key);
	}
}
*/

int http_decompress_error_handler_cb(wget_decompressor *dc, int err WGET_GCC_UNUSED)
{
	wget_http_response *resp = (wget_http_response *) wget_decompress_get_context(dc);

	if (resp && resp->req)
		error_printf(_("Decompress failed [host: %s - resource: %s]\n"),
			resp->req->esc_host.data, resp->req->esc_resource.data);

	return 0;
}

int http_get_body_cb(void *userdata, const char *data, size_t length)
{
	wget_http_response *resp = (wget_http_response *) userdata;

	return resp->req->body_callback(resp, resp->req->body_user_data, data, length);
}

void http_fix_broken_server_encoding(wget_http_response *resp)
{
	// a workaround for broken server configurations
	// see https://mail-archives.apache.org/mod_mbox/httpd-dev/200207.mbox/<3D2D4E76.4010502@talex.com.pl>
	if (resp->content_encoding == wget_content_encoding_gzip) {
		const char *ext;
		if (!wget_strcasecmp_ascii(resp->content_type, "application/x-gzip")
			|| !wget_strcasecmp_ascii(resp->content_type, "application/gzip")
			|| !wget_strcasecmp_ascii(resp->content_type, "application/gunzip")
			|| ((ext = strrchr(resp->req->esc_resource.data, '.'))
			&& (!wget_strcasecmp_ascii(ext, ".gz") || !wget_strcasecmp_ascii(ext, ".tgz"))))
		{
			debug_printf("Broken server configuration gzip workaround triggered\n");
			resp->content_encoding =  wget_content_encoding_identity;
		}
	}
}

#ifdef WITH_LIBNGHTTP2
#endif

static int establish_proxy_connect(wget_tcp *tcp, const char *host, uint16_t port)
{
	char sbuf[1024];
	wget_buffer buf;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	// The use of Proxy-Connection has been discouraged in RFC 7230 A.1.2.
	// wget_buffer_sprintf(buf, "CONNECT %s:%hu HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",

	if (wget_ip_is_family(host, WGET_NET_FAMILY_IPV6))
		wget_buffer_printf(&buf, "CONNECT [%s]:%hu HTTP/1.1\r\nHost: [%s]:%hu\r\n\r\n",
			host, port, host, port);
	else
		wget_buffer_printf(&buf, "CONNECT %s:%hu HTTP/1.1\r\nHost: %s:%hu\r\n\r\n",
			host, port, host, port);

	if (wget_tcp_write(tcp, buf.data, buf.length) != (ssize_t) buf.length) {
		wget_buffer_deinit(&buf);
		return WGET_E_CONNECT;
	}

	wget_buffer_deinit(&buf);

	ssize_t nbytes;
	if ((nbytes = wget_tcp_read(tcp, sbuf, sizeof(sbuf) - 1)) < 0) {
		return WGET_E_CONNECT;
	}
	sbuf[nbytes] = 0;

	// strip trailing whitespace
	while (nbytes > 0 && c_isspace(sbuf[--nbytes]))
		sbuf[nbytes] = 0;

	// Additionally accepting HTTP/1.0 solves at least some compatibility issues.
	// See https://gitlab.com/gnuwget/wget2/-/issues/666#note_2002037243
	if (wget_strncasecmp_ascii(sbuf, "HTTP/1.1 200", 12) && wget_strncasecmp_ascii(sbuf, "HTTP/1.0 200", 12)) {
		error_printf(_("Proxy connection failed with: %s\n"), sbuf);
		return WGET_E_CONNECT;
	}

	debug_printf("Proxy connection established: %s\n", sbuf);

	return WGET_E_SUCCESS;
}

int wget_http_open(wget_http_connection **_conn, const wget_iri *iri)
{
	static int next_http_proxy = -1;
	static int next_https_proxy = -1;

	wget_http_connection
		*conn;
	const char
		*host;
	uint16_t
		port;
	int
		rc,
		ssl = iri->scheme == WGET_IRI_SCHEME_HTTPS;
	bool
		need_connect = false;

	if (!_conn)
		return WGET_E_INVALID;

	conn = wget_calloc(1, sizeof(wget_http_connection)); // convenience assignment
	if (!conn)
		return WGET_E_MEMORY;

	*_conn = conn;
	host = iri->host;
	port = iri->port;
	conn->tcp = wget_tcp_init();

#ifdef HAVE_LIBPROXY
{
	pxProxyFactory *pf = px_proxy_factory_new();
	if (pf) {
		char **proxies = px_proxy_factory_get_proxies(pf, iri->uri);

		if (proxies) {
			if (proxies[0]) {
				if (strcmp (proxies[0], "direct://") != 0) {
					wget_iri *proxy_iri = wget_iri_parse(proxies[0], "utf-8");
					host = strdup(proxy_iri->host);
					port = proxy_iri->port;

					if (proxy_iri->scheme == WGET_IRI_SCHEME_HTTP) {
						ssl = false;
						conn->proxied = 1;
					} else {
						ssl = true;
						need_connect = true;
					}
					wget_iri_free(&proxy_iri);
				}
			}

			px_proxy_factory_free_proxies(proxies);
		}

		px_proxy_factory_free (pf);
	}
}
#else
	if (!wget_http_match_no_proxy(no_proxies, iri->host)) {
		if (!ssl && http_proxies) {
			wget_thread_mutex_lock(proxy_mutex);
			wget_iri *proxy = wget_vector_get(http_proxies, (++next_http_proxy) % wget_vector_size(http_proxies));
			wget_thread_mutex_unlock(proxy_mutex);

			if (!proxy) {
				// this practically can't happen
				xfree(conn);
				*_conn = NULL;
				return WGET_E_UNKNOWN;
			}

			host = proxy->host;
			port = proxy->port;
			ssl = proxy->scheme == WGET_IRI_SCHEME_HTTPS;
			conn->proxied = 1;
		} else if (ssl && https_proxies) {
			wget_thread_mutex_lock(proxy_mutex);
			wget_iri *proxy = wget_vector_get(https_proxies, (++next_https_proxy) % wget_vector_size(https_proxies));
			wget_thread_mutex_unlock(proxy_mutex);

			if (!proxy) {
				// this practically can't happen
				xfree(conn);
				*_conn = NULL;
				return WGET_E_UNKNOWN;
			}

			host = proxy->host;
			port = proxy->port;
			ssl = proxy->scheme == WGET_IRI_SCHEME_HTTPS;
			// conn->proxied = 1;

			need_connect = true;
		}
	}
#endif

	if (ssl) {
		wget_tcp_set_ssl(conn->tcp, 1); // switch SSL on
		wget_tcp_set_ssl_hostname(conn->tcp, host); // enable host name checking
	}

	if ((rc = wget_tcp_connect(conn->tcp, host, port)) != WGET_E_SUCCESS) {
		if (server_stats_callback && (rc == WGET_E_CERTIFICATE))
			server_stats_callback(conn, NULL);

		wget_http_close(_conn);
		return rc;
	}

	if (need_connect) {
		if ((rc = establish_proxy_connect(conn->tcp, iri->host, iri->port)) != WGET_E_SUCCESS) {
			wget_http_close(_conn);
			return rc;
		}

		if (iri->scheme == WGET_IRI_SCHEME_HTTPS) {
			wget_tcp_set_ssl(conn->tcp, 1); // switch SSL on
			wget_tcp_set_ssl_hostname(conn->tcp, iri->host); // enable host name checking
			wget_tcp_tls_start(conn->tcp);
		}
	}

	conn->esc_host = iri->host ? wget_strdup(iri->host) : NULL;
	conn->port = iri->port;
	conn->scheme = iri->scheme;
	conn->buf = wget_buffer_alloc(102400); // reusable buffer, large enough for most requests and responses
#ifdef WITH_LIBNGHTTP2
	if ((conn->protocol = (char) wget_tcp_get_protocol(conn->tcp)) == WGET_PROTOCOL_HTTP_2_0) {
		if ((rc = wget_http2_open(conn)) < 0) {
			wget_http_close(_conn);
			return rc;
		}
	} else {
		conn->pending_requests = wget_vector_create(16, NULL);
	}

#else
	conn->pending_requests = wget_vector_create(16, NULL);
#endif

	return rc;
}

void wget_http_close(wget_http_connection **conn)
{
	if (*conn) {
		debug_printf("closing connection\n");
#ifdef WITH_LIBNGHTTP2
		wget_http2_close(conn);
#endif
		wget_tcp_deinit(&(*conn)->tcp);
//		if (!wget_tcp_get_dns_caching())
//			freeaddrinfo((*conn)->addrinfo);
		xfree((*conn)->esc_host);
		// xfree((*conn)->scheme);
		wget_buffer_free(&(*conn)->buf);
		wget_vector_clear_nofree((*conn)->pending_requests);
		wget_vector_free(&(*conn)->pending_requests);
		xfree(*conn);
	}
}

int wget_http_send_request(wget_http_connection *conn, wget_http_request *req)
{
	ssize_t nbytes;

#ifdef WITH_LIBNGHTTP2
	if (wget_tcp_get_protocol(conn->tcp) == WGET_PROTOCOL_HTTP_2_0) {
		return wget_http2_send_request(conn, req);
	}
#endif

	if ((nbytes = wget_http_request_to_buffer(req, conn->buf, conn->proxied, conn->port)) < 0) {
		error_printf(_("Failed to create request buffer\n"));
		return -1;
	}

	req->request_start = wget_get_timemillis();

	if (wget_tcp_write(conn->tcp, conn->buf->data, nbytes) != nbytes) {
		// An error will be written by the wget_tcp_write function.
		// error_printf(_("Failed to send %zd bytes (%d)\n"), nbytes, errno);
		return -1;
	}

	wget_vector_add(conn->pending_requests, req);

	if (req->debug_skip_body)
		debug_printf("# sent %zd bytes:\n%.*s<body skipped>", nbytes, (int)(conn->buf->length - req->body_length), conn->buf->data);
	else
		debug_printf("# sent %zd bytes:\n%.*s", nbytes, (int)conn->buf->length, conn->buf->data);

	return 0;
}

ssize_t wget_http_request_to_buffer(wget_http_request *req, wget_buffer *buf, int proxied, int port)
{
	char have_content_length = 0;
	char check_content_length = req->body && req->body_length;

//	wget_buffer_sprintf(buf, "%s /%s HTTP/1.1\r\nHost: %s", req->method, req->esc_resource.data ? req->esc_resource.data : "",);

	wget_buffer_strcpy(buf, req->method);
	wget_buffer_memcat(buf, " ", 1);
	if (proxied) {
		wget_buffer_strcat(buf, wget_iri_scheme_get_name(req->scheme));
		wget_buffer_memcat(buf, "://", 3);
		wget_buffer_bufcat(buf, &req->esc_host);
		wget_buffer_printf_append(buf, ":%d", port);
	}
	wget_buffer_memcat(buf, "/", 1);
	wget_buffer_bufcat(buf, &req->esc_resource);
	wget_buffer_memcat(buf, " HTTP/1.1\r\n", 11);

	for (int it = 0; it < wget_vector_size(req->headers); it++) {
		wget_http_header_param *param = wget_vector_get(req->headers, it);
		if (!param)
			continue;

		wget_buffer_strcat(buf, param->name);
		wget_buffer_memcat(buf, ": ", 2);
		wget_buffer_strcat(buf, param->value);

		if (buf->data[buf->length - 1] != '\n') {
			wget_buffer_memcat(buf, "\r\n", 2);
		}

		if (check_content_length && !wget_strcasecmp_ascii(param->name, "Content-Length"))
			have_content_length = 1; // User supplied Content-Length header, keep it unchecked
	}

/* The use of Proxy-Connection has been discouraged in RFC 7230 A.1.2.
	if (proxied)
		wget_buffer_strcat(buf, "Proxy-Connection: keep-alive\r\n");
*/

	if (check_content_length && !have_content_length)
		wget_buffer_printf_append(buf, "Content-Length: %zu\r\n", req->body_length);

	wget_buffer_memcat(buf, "\r\n", 2); // end-of-header

	if (req->body && req->body_length)
		wget_buffer_memcat(buf, req->body, req->body_length);

	return buf->length;
}

static char *get_page(wget_http_request *req)
{
	return wget_aprintf("%s://%s/%s",
		wget_iri_scheme_get_name(req->scheme), req->esc_host.data, req->esc_resource.data);
}

wget_http_response *wget_http_get_response_cb(wget_http_connection *conn)
{
	size_t bufsize, body_len = 0, body_size = 0;
	ssize_t nbytes, nread = 0;
	char *buf, *p = NULL;
	wget_http_response *resp = NULL;

#ifdef WITH_LIBNGHTTP2
	if (conn->protocol == WGET_PROTOCOL_HTTP_2_0) {
		return wget_http2_get_response_cb(conn, server_stats_callback);
	}
#endif

	wget_decompressor *dc = NULL;
	wget_http_request *req = wget_vector_get(conn->pending_requests, 0); // TODO: should use double linked lists here

	debug_printf("### req %p pending requests = %d\n", (void *) req, wget_vector_size(conn->pending_requests));
	if (!req)
		goto cleanup;

	wget_vector_remove_nofree(conn->pending_requests, 0);

	// reuse generic connection buffer
	buf = conn->buf->data;
	bufsize = conn->buf->size;

	while ((nbytes = wget_tcp_read(conn->tcp, buf + nread, bufsize - nread)) > 0) {
		req->first_response_start = wget_get_timemillis();
		// debug_printf("nbytes %zd nread %zd %zu\n", nbytes, nread, bufsize);
		nread += nbytes;
		buf[nread] = 0; // 0-terminate to allow string functions
skip_1xx:
		if (nread < 4) continue;

		if (nread - nbytes <= 4)
			p = buf;
		else
			p = buf + nread - nbytes - 3;

		if ((p = strstr(p, "\r\n\r\n"))) {
			// found end-of-header
			*p = 0;

			debug_printf("# got header %zd bytes:\n%s\n\n", p - buf, buf);

			if (!(resp = wget_http_parse_response_header(buf)))
				goto cleanup; // something is wrong with the header

			if (H_10X(resp->code)) {
				wget_http_free_response(&resp);
				p += 4;
				// calculate number of bytes so far read
				nbytes = nread -= (p - buf);
				// move remaining data to begin of buf
				memmove(buf, p, nread + 1);
				goto skip_1xx; // ignore intermediate response, no body expected
			}

			if (req->response_keepheader) {
				wget_buffer *header = wget_buffer_alloc(p - buf + 4);
				wget_buffer_memcpy(header, buf, p - buf);
				wget_buffer_memcat(header, "\r\n", 2);

				resp->header = header;

			}

			resp->req = req;

			if (server_stats_callback)
				server_stats_callback(conn, resp);

			if (req->header_callback) {
				req->header_callback(resp, req->header_user_data);
			}

			if (!wget_strcasecmp_ascii(req->method, "HEAD"))
				goto cleanup; // a HEAD response won't have a body

			http_fix_broken_server_encoding(resp);

			p += 4; // skip \r\n\r\n to point to body
			break;
		}

		if ((size_t)nread + 1024 > bufsize) {
			if (wget_buffer_ensure_capacity(conn->buf, bufsize + 1024) != WGET_E_SUCCESS) {
				error_printf(_("Failed to allocate %zu bytes\n"), bufsize + 1024);
				goto cleanup;
			}
			buf = conn->buf->data;
			bufsize = conn->buf->size;
		}
	}
	if (!nread) goto cleanup;
	if (!p) goto cleanup;

	if (resp && resp->code == HTTP_STATUS_RANGE_NOT_SATISFIABLE) {
		/*
		    RFC7233:
		    4.4.  416 Range Not Satisfiable

		       The 416 (Range Not Satisfiable) status code indicates that none of
		       the ranges in the request's Range header field (Section 3.1) overlap
		       the current extent of the selected resource or that the set of ranges
		       requested has been rejected due to invalid ranges or an excessive
		       request of small or overlapping ranges.
		*/
		goto cleanup;
	}
	if (!resp
	 || resp->code == HTTP_STATUS_NO_CONTENT
	 || resp->code == HTTP_STATUS_NOT_MODIFIED
	 || (resp->transfer_encoding == wget_transfer_encoding_identity && resp->content_length == 0 && resp->content_length_valid)) {
		// - body not included, see RFC 2616 4.3
		// - body empty, see RFC 2616 4.4
		goto cleanup;
	}

	dc = wget_decompress_open(resp->content_encoding, http_get_body_cb, resp);
	wget_decompress_set_error_handler(dc, http_decompress_error_handler_cb);

	// calculate number of body bytes so far read
	body_len = nread - (p - buf);
	// move already read body data to buf
	memmove(buf, p, body_len);
	buf[body_len] = 0;
	resp->cur_downloaded = body_len;

	if (resp->transfer_encoding == wget_transfer_encoding_chunked) {
		size_t chunk_size = 0;
		char *end;

		debug_printf("method 1 %zu %zu:\n", body_len, body_size);
		// RFC 2616 3.6.1
		// Chunked-Body   = *chunk last-chunk trailer CRLF
		// chunk          = chunk-size [ chunk-extension ] CRLF chunk-data CRLF
		// chunk-size     = 1*HEX
		// last-chunk     = 1*("0") [ chunk-extension ] CRLF
		// chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
		// chunk-ext-name = token
		// chunk-ext-val  = token | quoted-string
		// chunk-data     = chunk-size(OCTET)
		// trailer        = *(entity-header CRLF)
		// entity-header  = extension-header = message-header
		// message-header = field-name ":" [ field-value ]
		// field-name     = token
		// field-value    = *( field-content | LWS )
		// field-content  = <the OCTETs making up the field-value
		//                  and consisting of either *TEXT or combinations
		//                  of token, separators, and quoted-string>

/*
			length := 0
			read chunk-size, chunk-extension (if any) and CRLF
			while (chunk-size > 0) {
				read chunk-data and CRLF
				append chunk-data to entity-body
				length := length + chunk-size
				read chunk-size and CRLF
			}
			read entity-header
			while (entity-header not empty) {
				append entity-header to existing header fields
				read entity-header
			}
			Content-Length := length
			Remove "chunked" from Transfer-Encoding
*/

		// read each chunk, stripping the chunk info
		p = buf;
		for (;;) {
			// read: chunk-size [ chunk-extension ] CRLF
			while ((!(end = strchr(p, '\r')) || end[1] != '\n')) {
				if (http_connection_is_aborted(conn))
					goto cleanup;

				if (body_len + 1024 > bufsize) {
					if (wget_buffer_ensure_capacity(conn->buf, bufsize + 1024) != WGET_E_SUCCESS) {
						char *page = get_page(req);
						error_printf(_("Failed to allocate %zu bytes (%s)\n"), bufsize + 1024, page);
						xfree(page);
						goto cleanup;
					}
					p = conn->buf->data + (p - buf);
					buf = conn->buf->data;
					bufsize = conn->buf->size;
				}

				if ((nbytes = wget_tcp_read(conn->tcp, buf + body_len, bufsize - body_len)) <= 0)
					goto cleanup;

				body_len += nbytes;
				buf[body_len] = 0;
				// debug_printf("a nbytes %zd body_len %zu\n", nbytes, body_len);
			}
			end += 2;

			// now p points to chunk-size (hex)
			errno = 0;
			chunk_size = (size_t) strtoll(p, NULL, 16);
			if (errno) {
				char *page = get_page(req);
				error_printf(_("Failed to convert chunk size '%.31s' (%s)\n"), p, page);
				xfree(page);
				goto cleanup;
			}

			// debug_printf("chunk size is %zu\n", chunk_size);
			if (chunk_size == 0) {
				// now read 'trailer CRLF' which is '*(entity-header CRLF) CRLF'
				if (*end == '\r' && end[1] == '\n') // shortcut for the most likely case (empty trailer)
					goto cleanup;

				debug_printf("reading trailer\n");
				while (!strstr(end, "\r\n\r\n")) {
					if (body_len > 3) {
						// just need to keep the last 3 bytes to avoid buffer resizing
						memmove(buf, buf + body_len - 3, 4); // plus 0 terminator, just in case
						body_len = 3;
					}

					if (http_connection_is_aborted(conn))
						goto cleanup;

					if ((nbytes = wget_tcp_read(conn->tcp, buf + body_len, bufsize - body_len)) <= 0)
						goto cleanup;

					body_len += nbytes;
					buf[body_len] = 0;
					end = buf;
					// debug_printf("a nbytes %zd\n", nbytes);
				}
				debug_printf("end of trailer\n");
				goto cleanup;
			}

			// check for pointer overflow
			if (chunk_size > SIZE_MAX/2 - 2 || end >= end + chunk_size + 2) {
//			if (end > end + chunk_size || end >= end + chunk_size + 2) {
				char *page = get_page(req);
				error_printf(_("Chunk size overflow: %zX (%s)\n"), chunk_size, page);
				xfree(page);
				goto cleanup;
			}

			p = end + chunk_size + 2;
			if (p <= buf + body_len) {
				// debug_printf("write full chunk, %zu bytes\n", chunk_size);
				resp->cur_downloaded += chunk_size;
				wget_decompress(dc, end, chunk_size);
				continue;
			}

//			resp->cur_downloaded += (buf + body_len) - end;
//			wget_decompress(dc, end, (buf + body_len) - end);

			if ((uintptr_t)((buf + body_len) - end) > chunk_size) {
				resp->cur_downloaded += chunk_size;
				wget_decompress(dc, end, chunk_size);
			} else {
				resp->cur_downloaded += (buf + body_len) - end;
				wget_decompress(dc, end, (buf + body_len) - end);
			}

			chunk_size = (((uintptr_t) p) - ((uintptr_t) (buf + body_len))); // in fact needed bytes to have chunk_size+2 in buf

			debug_printf("need at least %zu more bytes\n", chunk_size);

			while (chunk_size > 0) {
				if (http_connection_is_aborted(conn))
					goto cleanup;

				if ((nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) <= 0)
					goto cleanup;
				// debug_printf("a nbytes=%zd chunk_size=%zu\n", nread, chunk_size);

				if (chunk_size <= (size_t)nbytes) {
					if (chunk_size == 1 || !strncmp(buf + chunk_size - 2, "\r\n", 2)) {
						debug_printf("chunk completed\n");
						// p=end+chunk_size+2;
					} else {
						char *page = get_page(req);
						error_printf(_("Expected end-of-chunk not found (%s)\n"), page);
						xfree(page);
						goto cleanup;
					}
					if (chunk_size > 2) {
						resp->cur_downloaded += chunk_size - 2;
						wget_decompress(dc, buf, chunk_size - 2);
					}
					body_len = nbytes - chunk_size;
					if (body_len)
						memmove(buf, buf + chunk_size, body_len);
					buf[body_len] = 0;
					p = buf;
					break;
				} else {
					chunk_size -= nbytes;
					if (chunk_size >= 2) {
						resp->cur_downloaded += nbytes;
						wget_decompress(dc, buf, nbytes);
					} else {
						// special case: we got a partial end-of-chunk
						resp->cur_downloaded += nbytes - 1;
						wget_decompress(dc, buf, nbytes - 1);
					}
				}
			}
		}
	} else if (resp->content_length_valid && !resp->req->response_ignorelength) {
		// read content_length bytes
		debug_printf("method 2\n");

		if (body_len)
			wget_decompress(dc, buf, body_len);

		while (body_len < resp->content_length) {
			if (http_connection_is_aborted(conn))
				break;

			if (((nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) <= 0))
				break;

			body_len += nbytes;
			// debug_printf("nbytes %zd total %zu/%zu\n", nbytes, body_len, resp->content_length);
			resp->cur_downloaded += nbytes;
			wget_decompress(dc, buf, nbytes);
		}
		if (nbytes < 0) {
			char *page = get_page(req);
			error_printf(_("Failed to read %zd bytes (%d) (%s)\n"), nbytes, errno, page);
			xfree(page);
		}
		if (body_len < resp->content_length) {
			resp->length_inconsistent = true;
			char *page = get_page(req);
			error_printf(_("Just got %zu of %zu bytes (%s)\n"), body_len, resp->content_length, page);
			xfree(page);
		} else if (body_len > resp->content_length) {
			resp->length_inconsistent = true;
			char *page = get_page(req);
			error_printf(_("Body too large: %zu instead of %zu bytes (%s)\n"), body_len, resp->content_length, page);
			xfree(page);
		}
		resp->content_length = body_len;
	} else {
		// read as long as we can
		debug_printf("method 3\n");

		if (body_len)
			wget_decompress(dc, buf, body_len);

		while (!http_connection_is_aborted(conn) && (nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) > 0) {
			body_len += nbytes;
			// debug_printf("nbytes %zd total %zu\n", nbytes, body_len);
			resp->cur_downloaded += nbytes;
			wget_decompress(dc, buf, nbytes);
		}
		resp->content_length = body_len;
	}

cleanup:

	if (resp)
		resp->response_end = wget_get_timemillis();

	wget_decompress_close(dc);

	return resp;
}

// get response, resp->body points to body in memory

wget_http_response *wget_http_get_response(wget_http_connection *conn)
{
	wget_http_response *resp;

	resp = wget_http_get_response_cb(conn);

	if (resp) {
		if (!wget_strcasecmp_ascii(resp->req->method, "GET"))
			if (resp->body)
				resp->content_length = resp->body->length;
	}

	return resp;
}

static void iri_free(void *iri)
{
	if (iri)
		wget_iri_free((wget_iri **) &iri);
}

static wget_vector *parse_proxies(const char *proxy, const char *encoding)
{
	if (!proxy)
		return NULL;

	wget_vector *proxies = NULL;
	const char *s, *p;

	for (s = p = proxy; *p; s = p + 1) {
		if ((p = strchrnul(s, ',')) != s && p - s < 256) {
			wget_iri *iri;
			char host[256];

			wget_strmemcpy(host, sizeof(host), s, p - s);

			iri = wget_iri_parse (host, encoding);
			if (iri) {
				if (!proxies) {
					proxies = wget_vector_create(8, NULL);
					wget_vector_set_destructor(proxies, iri_free);
				}
				wget_vector_add(proxies, iri);
			}
		}
	}

	return proxies;
}

static wget_vector *parse_no_proxies(const char *no_proxy, const char *encoding)
{
	if (!no_proxy)
		return NULL;

	wget_vector *proxies;
	const char *s, *p;

	proxies = wget_vector_create(8, NULL);

	for (s = p = no_proxy; *p; s = p + 1) {
		while (c_isspace(*s) && s < p) s++;

		if ((p = strchrnul(s, ',')) != s && p - s < 256) {
			char *host, *hostp;

			while (c_isspace(*s) && s < p) s++;

			if (s >= p || !(host = wget_strmemdup(s, p - s)))
				continue;

			// May be a hostname, domainname (optional with leading dot or wildcard), IP address.
			// We do not support network address (CIDR) for now.

			wget_strtolower(host);
			if (wget_str_needs_encoding(host)) {
				if ((hostp = wget_str_to_utf8(host, encoding))) {
					xfree(host);
					host = hostp;
				}
			}
			if ((hostp = (char *) wget_str_to_ascii(host)) != host) {
				xfree(host);
				host = hostp;
			}

			wget_vector_add(proxies, host);
		}
	}

	return proxies;
}

int wget_http_set_http_proxy(const char *proxy, const char *encoding)
{
	if (http_proxies)
		wget_vector_free(&http_proxies);

	http_proxies = parse_proxies(proxy, encoding);

	return wget_vector_size(http_proxies);
}

int wget_http_set_https_proxy(const char *proxy, const char *encoding)
{
	if (https_proxies)
		wget_vector_free(&https_proxies);

	https_proxies = parse_proxies(proxy, encoding);

	return wget_vector_size(https_proxies);
}

int wget_http_set_no_proxy(const char *no_proxy, const char *encoding)
{
	if (no_proxies)
		wget_vector_free(&no_proxies);

	no_proxies = parse_no_proxies(no_proxy, encoding);
	if (!no_proxies)
		return -1;

	return 0;
}

const wget_vector *wget_http_get_no_proxy(void)
{
	return no_proxies;
}

static bool cidr_v4_match(const char *cidr, struct in_addr *addr)
{
	const char *slash_pos = strchr(cidr, '/');
	if (slash_pos == NULL) {
		return false; // invalid CIDR range
	}
	int prefix_len = atoi(slash_pos + 1);
	if (prefix_len < 0 || prefix_len > 32) {
		return false; // invalid prefix length
	}
	struct in_addr network_addr;
	const char *prefix = wget_strmemdup(cidr, slash_pos - cidr);
	if (inet_pton(AF_INET, prefix, &network_addr) != 1) {
		xfree(prefix);
		return false; // invalid network address
	}
	xfree(prefix);

	uint32_t mask = (uint32_t) ~(0xFFFFFFFFLLU >> prefix_len);
	uint32_t network = ntohl(network_addr.s_addr) & mask;
	uint32_t test_addr = ntohl(addr->s_addr);
	return (test_addr & mask) == network;
}

#include <netinet/in.h>

static bool cidr_v6_match(const char *cidr, struct in6_addr *addr)
{
	const char *slash_pos = strchr(cidr, '/');
	if (slash_pos == NULL) {
		return false; // invalid CIDR range
	}
	int prefix_len = atoi(slash_pos + 1);
	if (prefix_len < 0 || prefix_len > 128) {
		return false; // invalid prefix length
	}
	struct in6_addr network_addr;
	const char *prefix = wget_strmemdup(cidr, slash_pos - cidr);
	if (inet_pton(AF_INET6, prefix, &network_addr) != 1) {
		xfree(prefix);
		return false; // invalid network address
	}
	xfree(prefix);

	int bytes = prefix_len / 8;
	if (bytes && memcmp(network_addr.s6_addr, addr->s6_addr, bytes))
		return false;

	int bits = prefix_len & 7;
	if (!bits)
		return true;

	uint8_t mask = (uint8_t) ~(0xFF >> bits);
	return ((network_addr.s6_addr[bytes] ^ addr->s6_addr[bytes]) & mask) == 0;
}

int wget_http_match_no_proxy(const wget_vector *no_proxies_vec, const char *host)
{
	if (wget_vector_size(no_proxies_vec) < 1 || !host)
		return 0;

	struct in_addr addr;
	struct in6_addr addr6;
	bool ipv4 = false, ipv6 = false;

	if (inet_pton(AF_INET, host, &addr) == 1) {
		ipv4 = true;
	} else if (inet_pton(AF_INET6, host, &addr6) == 1) {
		ipv6 = true;
	}

	// https://www.gnu.org/software/emacs/manual/html_node/url/Proxies.html
	for (int it = 0; it < wget_vector_size(no_proxies_vec); it++) {
		const char *no_proxy = wget_vector_get(no_proxies_vec, it);

		if (!no_proxy)
			continue;

		if (!strcmp(no_proxy, host))
			return 1; // exact match

		if (ipv4) {
			if (cidr_v4_match(no_proxy, &addr)) {
				return 1;
			}
		} else if (ipv6) {
			if (cidr_v6_match(no_proxy, &addr6)) {
				return 1;
			}
		}

		// check for subdomain match
		if (*no_proxy == '.' && wget_match_tail(host, no_proxy))
			return 1;
	}

	return 0;
}

void wget_http_abort_connection(wget_http_connection *conn)
{
	if (conn)
		conn->abort_indicator = 1; // stop single connection
	else
		abort_indicator = 1; // stop all connections
}

int http_connection_is_aborted(wget_http_connection *conn)
{
	return conn->abort_indicator || abort_indicator;
}

/**
 * \param[in] conn Pointer to a `wget_http_connection` instance.
 * \return Returns true if the remote side no longer accepts requests.
 *
 * With HTTP/2 a server can indicate that no more requests are accepted.
 * If that happens, pending responses are still delivered and should be retrieved.
 * After the last response has been received, the connection should be closed.
 */
bool wget_http_connection_receive_only(wget_http_connection *conn)
{
	return conn->goaway;
}

/**
 * \param[in] fn A `wget_server_stats_callback` callback function to receive server statistics data
 * \param[in] ctx Context data given to \p fn
 *
 * Set callback function to be called when server statistics are available
 */
void wget_server_set_stats_callback(wget_server_stats_callback *fn)
{
	server_stats_callback = fn;
}
