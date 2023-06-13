/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2022 Free Software Foundation, Inc.
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

static void __attribute__ ((constructor)) http_init(void)
{
	if (!initialized) {
		wget_thread_mutex_init(&proxy_mutex);
		wget_thread_mutex_init(&hosts_mutex);
		initialized = 1;
	}
}

static void __attribute__ ((destructor)) http_exit(void)
{
	if (initialized) {
		wget_thread_mutex_destroy(&proxy_mutex);
		wget_thread_mutex_destroy(&hosts_mutex);
		initialized = 0;
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

		hashlen = wget_hash_get_len(hashtype);
		size_t abufSize = hashlen * 2 + 1;
		char * a1buf = malloc(abufSize);
		char * a2buf = malloc(abufSize);
		char * response_digest = malloc(abufSize);
		char cnonce[16] = "";
		// A1BUF = H(user ":" realm ":" password)
		wget_hash_printf_hex(hashtype, a1buf, abufSize, "%s:%s:%s", username, realm, password);

		if (!wget_strcasecmp_ascii(algorithm, "MD5-sess") || !wget_strcasecmp_ascii(algorithm, "SHA-256-sess")) {
			// A1BUF = H( H(user ":" realm ":" password) ":" nonce ":" cnonce )
			wget_snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned) wget_random()); // create random hex string
			wget_hash_printf_hex(hashtype, a1buf, abufSize, "%s:%s:%s", a1buf, nonce, cnonce);
		}

		// A2BUF = H(method ":" path)
		wget_hash_printf_hex(hashtype, a2buf, abufSize, "%s:/%s", req->method, req->esc_resource.data);

		if (!qop) {
			// RFC 2069 Digest Access Authentication

			// RESPONSE_DIGEST = H(A1BUF ":" nonce ":" A2BUF)
			wget_hash_printf_hex(hashtype, response_digest, abufSize, "%s:%s:%s", a1buf, nonce, a2buf);
		} else { // if (!wget_strcasecmp_ascii(qop, "auth") || !wget_strcasecmp_ascii(qop, "auth-int")) {
			// RFC 2617 Digest Access Authentication
			if (!*cnonce)
				wget_snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned) wget_random()); // create random hex string

			// RESPONSE_DIGEST = H(A1BUF ":" nonce ":" nc ":" cnonce ":" qop ": " A2BUF)
			wget_hash_printf_hex(hashtype, response_digest, abufSize,
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
		free(response_digest);
		free(a1buf);
		free(a2buf);

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

struct http2_stream_context {
	wget_http_response
		*resp;
	wget_decompressor
		*decompressor;
};

static int decompress_error_handler(wget_decompressor *dc, int err WGET_GCC_UNUSED)
{
	wget_http_response *resp = (wget_http_response *) wget_decompress_get_context(dc);

	if (resp && resp->req)
		error_printf(_("Decompress failed [host: %s - resource: %s]\n"),
			resp->req->esc_host.data, resp->req->esc_resource.data);

	return 0;
}

static wget_decompressor_sink_fn get_body;
static int get_body(void *userdata, const char *data, size_t length)
{
	wget_http_response *resp = (wget_http_response *) userdata;

	return resp->req->body_callback(resp, resp->req->body_user_data, data, length);
}

static void fix_broken_server_encoding(wget_http_response *resp)
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
static ssize_t send_callback(nghttp2_session *session WGET_GCC_UNUSED,
	const uint8_t *data, size_t length, int flags WGET_GCC_UNUSED, void *user_data)
{
	wget_http_connection *conn = (wget_http_connection *)user_data;
	ssize_t rc;

	// debug_printf("writing... %zd\n", length);
	if ((rc = wget_tcp_write(conn->tcp, (const char *)data, length)) <= 0) {
		// An error will be written by the wget_tcp_write function.
		// debug_printf("write rc %d, errno=%d\n", rc, errno);
		return rc ? NGHTTP2_ERR_CALLBACK_FAILURE : NGHTTP2_ERR_WOULDBLOCK;
	}
	// debug_printf("write rc %d\n",rc);

	return rc;
}

static void print_frame_type(int type, const char tag, int streamid)
{
	static const char *name[] = {
		[NGHTTP2_DATA] = "DATA",
		[NGHTTP2_HEADERS] = "HEADERS",
		[NGHTTP2_PRIORITY] = "PRIORITY",
		[NGHTTP2_RST_STREAM] = "RST_STREAM",
		[NGHTTP2_SETTINGS] = "SETTINGS",
		[NGHTTP2_PUSH_PROMISE] = "PUSH_PROMISE",
		[NGHTTP2_PING] = "PING",
		[NGHTTP2_GOAWAY] = "GOAWAY",
		[NGHTTP2_WINDOW_UPDATE] = "WINDOW_UPDATE",
		[NGHTTP2_CONTINUATION] = "CONTINUATION"
	};

	if ((unsigned) type < countof(name)) {
		// Avoid printing frame info for DATA frames
		if (type != NGHTTP2_DATA)
			debug_printf("[FRAME %d] %c %s\n", streamid, tag, name[type]);
	} else
		debug_printf("[FRAME %d] %c Unknown type %d\n", streamid, tag, type);
}

static int on_frame_send_callback(nghttp2_session *session WGET_GCC_UNUSED,
	const nghttp2_frame *frame, void *user_data WGET_GCC_UNUSED)
{
	print_frame_type(frame->hd.type, '>', frame->hd.stream_id);

	if (frame->hd.type == NGHTTP2_HEADERS) {
		const nghttp2_nv *nva = frame->headers.nva;

		for (unsigned i = 0; i < frame->headers.nvlen; i++)
			debug_printf("[FRAME %d] > %.*s: %.*s\n", frame->hd.stream_id,
				(int)nva[i].namelen, nva[i].name, (int)nva[i].valuelen, nva[i].value);
	}

	return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
	const nghttp2_frame *frame, void *user_data WGET_GCC_UNUSED)
{
	print_frame_type(frame->hd.type, '<', frame->hd.stream_id);

	// header callback after receiving all header tags
	if (frame->hd.type == NGHTTP2_HEADERS) {
		struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
		wget_http_response *resp = ctx ? ctx->resp : NULL;

		if (resp) {
			if (resp->header && resp->req->header_callback) {
				resp->req->header_callback(resp, resp->req->header_user_data);
			}

			fix_broken_server_encoding(resp);

			if (!ctx->decompressor) {
				ctx->decompressor = wget_decompress_open(resp->content_encoding, get_body, resp);
				wget_decompress_set_error_handler(ctx->decompressor, decompress_error_handler);
			}
		}
	}

	return 0;
}

static int on_header_callback(nghttp2_session *session,
	const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
	const uint8_t *value, size_t valuelen,
	uint8_t flags WGET_GCC_UNUSED, void *user_data WGET_GCC_UNUSED)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
	wget_http_response *resp = ctx ? ctx->resp : NULL;

	if (!resp)
		return 0;

	if (resp->req->response_keepheader || resp->req->header_callback) {
		if (!resp->header)
			resp->header = wget_buffer_alloc(1024);
	}

	if (frame->hd.type == NGHTTP2_HEADERS) {
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
			debug_printf("%.*s: %.*s\n", (int) namelen, name, (int) valuelen, value);

			if (resp->header)
				wget_buffer_printf_append(resp->header, "%.*s: %.*s\n", (int) namelen, name, (int) valuelen, value);

			wget_http_parse_header_line(resp, (char *) name, namelen, (char *) value, valuelen);
		}
	}

	return 0;
}

/*
 * This function is called to indicate that a stream is closed.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
	uint32_t error_code WGET_GCC_UNUSED, void *user_data)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);

	debug_printf("closing stream %d\n", stream_id);
	if (ctx) {
		wget_http_connection *conn = (wget_http_connection *) user_data;

		ctx->resp->response_end = wget_get_timemillis(); // Final transmission time.

		wget_vector_add(conn->received_http2_responses, ctx->resp);
		wget_decompress_close(ctx->decompressor);
		nghttp2_session_set_stream_user_data(session, stream_id, NULL);
		xfree(ctx);
	}

	return 0;
}
/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session,
	uint8_t flags WGET_GCC_UNUSED, int32_t stream_id,
	const uint8_t *data, size_t len,	void *user_data WGET_GCC_UNUSED)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);

	if (ctx) {
		// debug_printf("[INFO] C <---------------------------- S%d (DATA chunk - %zu bytes)\n", stream_id, len);
		// debug_printf("nbytes %zu\n", len);

		ctx->resp->req->first_response_start = wget_get_timemillis();

		ctx->resp->cur_downloaded += len;
		wget_decompress(ctx->decompressor, (char *) data, len);
	}
	return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
}
#endif

static int establish_proxy_connect(wget_tcp *tcp, const char *host, uint16_t port)
{
	char sbuf[1024];
	wget_buffer buf;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	// The use of Proxy-Connection has been discouraged in RFC 7230 A.1.2.
	// wget_buffer_sprintf(buf, "CONNECT %s:%hu HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",

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

	if (wget_strncasecmp_ascii(sbuf, "HTTP/1.1 200", 12)) {
		error_printf("Proxy connection failed with: %s\n", sbuf);
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

	conn = *_conn = wget_calloc(1, sizeof(wget_http_connection)); // convenience assignment

	host = iri->host;
	port = iri->port;
	conn->tcp = wget_tcp_init();

	if (!wget_http_match_no_proxy(no_proxies, iri->host)) {
		if (!ssl && http_proxies) {
			wget_thread_mutex_lock(proxy_mutex);
			wget_iri *proxy = wget_vector_get(http_proxies, (++next_http_proxy) % wget_vector_size(http_proxies));
			wget_thread_mutex_unlock(proxy_mutex);

			host = proxy->host;
			port = proxy->port;
			ssl = proxy->scheme == WGET_IRI_SCHEME_HTTPS;
			conn->proxied = 1;
		} else if (ssl && https_proxies) {
			wget_thread_mutex_lock(proxy_mutex);
			wget_iri *proxy = wget_vector_get(https_proxies, (++next_https_proxy) % wget_vector_size(https_proxies));
			wget_thread_mutex_unlock(proxy_mutex);

			host = proxy->host;
			port = proxy->port;
			ssl = proxy->scheme == WGET_IRI_SCHEME_HTTPS;
//			conn->proxied = 1;

			need_connect = true;
		}
	}

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
		nghttp2_session_callbacks *callbacks;

		if (nghttp2_session_callbacks_new(&callbacks)) {
			error_printf(_("Failed to create HTTP2 callbacks\n"));
			wget_http_close(_conn);
			return WGET_E_INVALID;
		}

		setup_nghttp2_callbacks(callbacks);
		rc = nghttp2_session_client_new(&conn->http2_session, callbacks, conn);
		nghttp2_session_callbacks_del(callbacks);

		if (rc) {
			error_printf(_("Failed to create HTTP2 client session (%d)\n"), rc);
			wget_http_close(_conn);
			return WGET_E_INVALID;
		}

		nghttp2_settings_entry iv[] = {
			// {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
			{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1 << 30}, // prevent window size changes
			{NGHTTP2_SETTINGS_ENABLE_PUSH, 0}, // avoid push messages from server
		};

		if ((rc = nghttp2_submit_settings(conn->http2_session, NGHTTP2_FLAG_NONE, iv, countof(iv)))) {
			error_printf(_("Failed to submit HTTP2 client settings (%d)\n"), rc);
			wget_http_close(_conn);
			return WGET_E_INVALID;
		}

#if NGHTTP2_VERSION_NUM >= 0x010c00
		// without this we experience slow downloads on fast networks
		if ((rc = nghttp2_session_set_local_window_size(conn->http2_session, NGHTTP2_FLAG_NONE, 0, 1 << 30)))
			debug_printf("Failed to set HTTP2 connection level window size (%d)\n", rc);
#endif

		conn->received_http2_responses = wget_vector_create(16, NULL);
	} else
		conn->pending_requests = wget_vector_create(16, NULL);

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
		if ((*conn)->http2_session) {
			int rc = nghttp2_session_terminate_session((*conn)->http2_session, NGHTTP2_NO_ERROR);
			if (rc)
				error_printf(_("Failed to terminate HTTP2 session (%d)\n"), rc);
			nghttp2_session_del((*conn)->http2_session);
		}
		wget_vector_clear_nofree((*conn)->received_http2_responses);
		wget_vector_free(&(*conn)->received_http2_responses);
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

#ifdef WITH_LIBNGHTTP2
static ssize_t data_prd_read_callback(
	nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
	uint32_t *data_flags, nghttp2_data_source *source, void *user_data WGET_GCC_UNUSED)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);
	const char *bodyp = source->ptr;

	if (!ctx)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

//	debug_printf("[INFO] C ----------------------------> S (DATA post body), length:%zu %zu\n", length, ctx->resp->req->body_length);

	size_t len = ctx->resp->req->body_length - (bodyp - ctx->resp->req->body);

	if (len > length)
		len = length;

	memcpy(buf, bodyp, len);
	source->ptr = (char *) (bodyp + len);

	if (!len)
		*data_flags = NGHTTP2_DATA_FLAG_EOF;

	return len;
}

static void init_nv(nghttp2_nv *nv, const char *name, const char *value)
{
	nv->name = (uint8_t *)name;
	nv->namelen = strlen(name);
	nv->value = (uint8_t *)value;
	nv->valuelen = strlen(value);
	nv->flags = NGHTTP2_NV_FLAG_NONE;
}
#endif

int wget_http_send_request(wget_http_connection *conn, wget_http_request *req)
{
	ssize_t nbytes;

#ifdef WITH_LIBNGHTTP2
	if (wget_tcp_get_protocol(conn->tcp) == WGET_PROTOCOL_HTTP_2_0) {
		char length_str[32];
		int n = 4 + wget_vector_size(req->headers);
		nghttp2_nv *nvs = malloc(sizeof(nghttp2_nv) * n);
		nghttp2_nv *nvp;
		size_t resourceSize = req->esc_resource.length + 2;
		char *resource = malloc(resourceSize);

		resource[0] = '/';
		memcpy(resource + 1, req->esc_resource.data, req->esc_resource.length + 1);
		init_nv(&nvs[0], ":method", req->method);
		init_nv(&nvs[1], ":path", resource);
		init_nv(&nvs[2], ":scheme", "https");
		// init_nv(&nvs[3], ":authority", req->esc_host.data);
		nvp = &nvs[4];

		for (int it = 0; it < wget_vector_size(req->headers); it++) {
			wget_http_header_param *param = wget_vector_get(req->headers, it);
			if (!wget_strcasecmp_ascii(param->name, "Connection"))
				continue;
			if (!wget_strcasecmp_ascii(param->name, "Transfer-Encoding"))
				continue;
			if (!wget_strcasecmp_ascii(param->name, "Host")) {
				init_nv(&nvs[3], ":authority", param->value);
				continue;
			}

			init_nv(nvp++, param->name, param->value);
		}

		if (req->body_length) {
			wget_snprintf(length_str, sizeof(length_str), "%zu", req->body_length);
			init_nv(nvp++, "Content-Length", length_str);
		}

		struct http2_stream_context *ctx = wget_calloc(1, sizeof(struct http2_stream_context));
		// HTTP/2.0 has the streamid as link between
		ctx->resp = wget_calloc(1, sizeof(wget_http_response));
		ctx->resp->req = req;
		ctx->resp->major = 2;
		// we do not get a Keep-Alive header in HTTP2 - let's assume the connection stays open
		ctx->resp->keep_alive = 1;
		req->request_start = wget_get_timemillis();

		if (req->body_length) {
			nghttp2_data_provider data_prd;
			data_prd.source.ptr = (void *) req->body;
			debug_printf("body length: %zu %zu\n", req->body_length, ctx->resp->req->body_length);
			data_prd.read_callback = data_prd_read_callback;
			req->stream_id = nghttp2_submit_request(conn->http2_session, NULL, nvs, nvp - nvs, &data_prd, ctx);
		} else {
			// nghttp2 does strdup of name+value and lowercase conversion of 'name'
			req->stream_id = nghttp2_submit_request(conn->http2_session, NULL, nvs, nvp - nvs, NULL, ctx);
		}

		if (req->stream_id < 0) {
			error_printf(_("Failed to submit HTTP2 request\n"));
			wget_http_free_response(&ctx->resp);
			xfree(ctx);
			free(nvs);
			free(resource);
			return -1;
		}

		conn->pending_http2_requests++;

		debug_printf("HTTP2 stream id %d\n", req->stream_id);
		free(nvs);
		free(resource);
		return 0;
	}
#endif

	if ((nbytes = wget_http_request_to_buffer(req, conn->buf, conn->proxied)) < 0) {
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

ssize_t wget_http_request_to_buffer(wget_http_request *req, wget_buffer *buf, int proxied)
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
	}
	wget_buffer_memcat(buf, "/", 1);
	wget_buffer_bufcat(buf, &req->esc_resource);
	wget_buffer_memcat(buf, " HTTP/1.1\r\n", 11);

	for (int it = 0; it < wget_vector_size(req->headers); it++) {
		wget_http_header_param *param = wget_vector_get(req->headers, it);

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
		debug_printf("  ##  pending_requests = %d\n", conn->pending_http2_requests);
		if (conn->pending_http2_requests > 0)
			conn->pending_http2_requests--;
		else
			return NULL;

		// reuse generic connection buffer
		buf = conn->buf->data;
		bufsize = conn->buf->size;

		while (!wget_vector_size(conn->received_http2_responses) && !conn->abort_indicator && !abort_indicator) {
			int rc;

			while (nghttp2_session_want_write(conn->http2_session) && nghttp2_session_send(conn->http2_session) == 0)
				;

			if ((nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) <= 0) {
				debug_printf("failed to receive: %d (nbytes=%ld)\n", errno, (long) nbytes);
				if (nbytes == -1)
					break;

				// nbytes == 0 has been seen on Win11, continue looping
			}

			if ((nbytes = nghttp2_session_mem_recv(conn->http2_session, (uint8_t *) buf, nbytes)) < 0) {
				rc = (int) nbytes;
				debug_printf("mem_recv failed: %d %s\n", rc, nghttp2_strerror(rc));
				break;
			}

			// debug_printf("  ##  loop responses=%d rc=%d nbytes=%zd\n", wget_vector_size(conn->received_http2_responses), rc, nbytes);
		}

		resp = wget_vector_get(conn->received_http2_responses, 0); // should use double linked lists here

		if (server_stats_callback)
			server_stats_callback(conn, resp);

		if (resp) {
			debug_printf("  ##  response status %d\n", resp->code);
			wget_vector_remove_nofree(conn->received_http2_responses, 0);
		}

		return resp;
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

		if (nread < 4) continue;

		if (nread - nbytes <= 4)
			p = buf;
		else
			p = buf + nread - nbytes - 3;

		if ((p = strstr(p, "\r\n\r\n"))) {
			// found end-of-header
			*p = 0;

			debug_printf("# got header %zd bytes:\n%s\n\n", p - buf, buf);

			if (req->response_keepheader) {
				wget_buffer *header = wget_buffer_alloc(p - buf + 4);
				wget_buffer_memcpy(header, buf, p - buf);
				wget_buffer_memcat(header, "\r\n\r\n", 4);

				if (!(resp = wget_http_parse_response_header(buf))) {
					wget_buffer_free(&header);
					goto cleanup; // something is wrong with the header
				}

				resp->header = header;

			} else {
				if (!(resp = wget_http_parse_response_header(buf)))
					goto cleanup; // something is wrong with the header
			}

			resp->req = req;

			if (server_stats_callback)
				server_stats_callback(conn, resp);

			if (req->header_callback) {
				req->header_callback(resp, req->header_user_data);
			}

			if (req && !wget_strcasecmp_ascii(req->method, "HEAD"))
				goto cleanup; // a HEAD response won't have a body

			fix_broken_server_encoding(resp);

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
	 || H_10X(resp->code)
	 || resp->code == HTTP_STATUS_NO_CONTENT
	 || resp->code == HTTP_STATUS_NOT_MODIFIED
	 || (resp->transfer_encoding == wget_transfer_encoding_identity && resp->content_length == 0 && resp->content_length_valid)) {
		// - body not included, see RFC 2616 4.3
		// - body empty, see RFC 2616 4.4
		goto cleanup;
	}

	dc = wget_decompress_open(resp->content_encoding, get_body, resp);
	wget_decompress_set_error_handler(dc, decompress_error_handler);

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
				if (conn->abort_indicator || abort_indicator)
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

					if (conn->abort_indicator || abort_indicator)
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
				if (conn->abort_indicator || abort_indicator)
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
			if (conn->abort_indicator || abort_indicator)
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

		while (!conn->abort_indicator && !abort_indicator && (nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) > 0) {
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

const wget_vector *http_get_no_proxy(void)
{
	return no_proxies;
}

static bool wget_http_cidr_match(const char *cidr, struct in_addr *addr)
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

int wget_http_match_no_proxy(const wget_vector *no_proxies_vec, const char *host)
{
	if (!no_proxies_vec || !host)
		return 0;

	// https://www.gnu.org/software/emacs/manual/html_node/url/Proxies.html
	for (int it = 0; it < wget_vector_size(no_proxies_vec); it++) {
		const char *no_proxy = wget_vector_get(no_proxies_vec, it);

		if (!no_proxy)
			continue;

		if (!strcmp(no_proxy, host))
			return 1; // exact match

		struct in_addr addr;
		if (inet_pton(AF_INET, host, &addr) == 1) {
			if(wget_http_cidr_match(no_proxy, &addr)) {
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
