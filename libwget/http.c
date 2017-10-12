/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#elif defined HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
#endif
#include <netinet/in.h>
#ifdef WITH_ZLIB
//#include <zlib.h>
#endif
#ifdef WITH_LIBNGHTTP2
	#include <nghttp2/nghttp2.h>
#endif

#include <wget.h>
#include "private.h"
#include "http.h"
#include "net.h"

static char
	_abort_indicator;

static wget_vector_t
	*http_proxies,
	*https_proxies,
	*no_proxies;

static wget_hashmap_t
	*hosts;
static wget_thread_mutex_t
	hosts_mutex = WGET_THREAD_MUTEX_INITIALIZER;

typedef struct {
	const char
		*hostname,
		*ip,
		*scheme;
} HOST;

typedef struct
{
	const char
		*hostname,
		*ip,
		*scheme;
	char
		hsts,
		csp,
		hpkp_new;
	wget_hpkp_stats_t hpkp;
} _stats_data_t;

static wget_stats_callback_t stats_callback;

// This is the default function for collecting body data
static int _body_callback(wget_http_response_t *resp, void *user_data G_GNUC_WGET_UNUSED, const char *data, size_t length)
{
	if (!resp->body)
		resp->body = wget_buffer_alloc(102400);

	wget_buffer_memcat(resp->body, data, length);

	return 0;
}

wget_http_request_t *wget_http_create_request(const wget_iri_t *iri, const char *method)
{
	wget_http_request_t *req = xcalloc(1, sizeof(wget_http_request_t));

	wget_buffer_init(&req->esc_resource, req->esc_resource_buf, sizeof(req->esc_resource_buf));
	wget_buffer_init(&req->esc_host, req->esc_host_buf, sizeof(req->esc_host_buf));

	req->scheme = iri->scheme;
	wget_strscpy(req->method, method, sizeof(req->method));
	wget_iri_get_escaped_resource(iri, &req->esc_resource);
	wget_iri_get_escaped_host(iri, &req->esc_host);
	req->headers = wget_vector_create(8, 8, NULL);
	wget_vector_set_destructor(req->headers, (wget_vector_destructor_t)wget_http_free_param);

	wget_http_add_header(req, "Host", req->esc_host.data);
	wget_http_request_set_body_cb(req, _body_callback, NULL);

	return req;
}

void wget_http_request_set_header_cb(wget_http_request_t *req, wget_http_header_callback_t callback, void *user_data)
{
	req->header_callback = callback;
	req->header_user_data = user_data;
}

void wget_http_request_set_body_cb(wget_http_request_t *req, wget_http_body_callback_t callback, void *user_data)
{
	req->body_callback = callback;
	req->body_user_data = user_data;
}

void wget_http_request_set_int(wget_http_request_t *req, int key, int value)
{
	switch (key) {
	case WGET_HTTP_RESPONSE_KEEPHEADER: req->response_keepheader = !!value; break;
	default: error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
	}
}

int wget_http_request_get_int(wget_http_request_t *req, int key)
{
	switch (key) {
	case WGET_HTTP_RESPONSE_KEEPHEADER: return req->response_keepheader;
	default:
		error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
		return -1;
	}
}

void wget_http_request_set_ptr(wget_http_request_t *req, int key, void *value)
{
	switch (key) {
	case WGET_HTTP_USER_DATA: req->user_data = value; break;
	default: error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
	}
}

void *wget_http_request_get_ptr(wget_http_request_t *req, int key)
{
	switch (key) {
	case WGET_HTTP_USER_DATA: return req->user_data;
	default:
		error_printf(_("%s: Unknown key %d (or value must not be an integer)\n"), __func__, key);
		return NULL;
	}
}

void wget_http_request_set_body(wget_http_request_t *req, const char *mimetype, char *body, size_t length)
{
	if (mimetype)
		wget_http_add_header(req, "Content-Type", mimetype);

	req->body = body;
	req->body_length = length;
}

void wget_http_add_header_vprintf(wget_http_request_t *req, const char *name, const char *fmt, va_list args)
{
	wget_http_header_param_t param;

	param.value = wget_vaprintf(fmt, args);
	param.name = wget_strdup(name);
	wget_vector_add(req->headers, &param, sizeof(param));
}

void wget_http_add_header_printf(wget_http_request_t *req, const char *name, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	wget_http_add_header_vprintf(req, name, fmt, args);
	va_end(args);
}

void wget_http_add_header(wget_http_request_t *req, const char *name, const char *value)
{
	wget_http_header_param_t param = {
		.name = wget_strdup(name),
		.value = wget_strdup(value)
	};

	wget_vector_add(req->headers, &param, sizeof(param));
}

void wget_http_add_header_param(wget_http_request_t *req, wget_http_header_param_t *param)
{
	wget_http_header_param_t _param = {
		.name = wget_strdup(param->name),
		.value = wget_strdup(param->value)
	};

	wget_vector_add(req->headers, &_param, sizeof(_param));
}

void wget_http_add_credentials(wget_http_request_t *req, wget_http_challenge_t *challenge, const char *username, const char *password, int proxied)
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
		int md5size = wget_hash_get_len(WGET_DIGTYPE_MD5);
		char a1buf[md5size * 2 + 1], a2buf[md5size * 2 + 1];
		char response_digest[md5size * 2 + 1], cnonce[16] = "";
		wget_buffer_t buf;
		const char
			*realm = wget_stringmap_get(challenge->params, "realm"),
			*opaque = wget_stringmap_get(challenge->params, "opaque"),
			*nonce = wget_stringmap_get(challenge->params, "nonce"),
			*qop = wget_stringmap_get(challenge->params, "qop"),
			*algorithm = wget_stringmap_get(challenge->params, "algorithm");

		if (wget_strcmp(qop, "auth")) {
			error_printf(_("Unsupported quality of protection '%s'.\n"), qop);
			return;
		}

		if (wget_strcmp(algorithm, "MD5") &&
			wget_strcmp(algorithm, "MD5-sess") &&
			wget_strcmp(algorithm, NULL)) {
			error_printf(_("Unsupported algorithm '%s'.\n"), algorithm);
			return;
		}

		if (!realm || !nonce)
			return;

		// A1BUF = H(user ":" realm ":" password)
		wget_md5_printf_hex(a1buf, "%s:%s:%s", username, realm, password);

		if (!wget_strcmp(algorithm, "MD5-sess")) {
			// A1BUF = H( H(user ":" realm ":" password) ":" nonce ":" cnonce )
			snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned) wget_random()); // create random hex string
			wget_md5_printf_hex(a1buf, "%s:%s:%s", a1buf, nonce, cnonce);
		}

		// A2BUF = H(method ":" path)
		wget_md5_printf_hex(a2buf, "%s:/%s", req->method, req->esc_resource.data);

		if (!wget_strcmp(qop, "auth") || !wget_strcmp(qop, "auth-int")) {
			// RFC 2617 Digest Access Authentication
			if (!*cnonce)
				snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned) wget_random()); // create random hex string

			// RESPONSE_DIGEST = H(A1BUF ":" nonce ":" nc ":" cnonce ":" qop ": " A2BUF)
			wget_md5_printf_hex(response_digest, "%s:%s:00000001:%s:%s:%s", a1buf, nonce, /* nc, */ cnonce, qop, a2buf);
		} else {
			// RFC 2069 Digest Access Authentication

			// RESPONSE_DIGEST = H(A1BUF ":" nonce ":" A2BUF)
			wget_md5_printf_hex(response_digest, "%s:%s:%s", a1buf, nonce, a2buf);
		}

		wget_buffer_init(&buf, NULL, 256);

		wget_buffer_printf(&buf,
			"Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"/%s\", response=\"%s\"",
			username, realm, nonce, req->esc_resource.data, response_digest);

		if (!wget_strcmp(qop,"auth"))
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
static struct _config {
	int
		read_timeout;
	unsigned int
		dns_caching : 1;
} _config = {
	.read_timeout = -1,
	.dns_caching = 1
};

void http_set_config_int(int key, int value)
{
	switch (key) {
	case HTTP_READ_TIMEOUT: _config.read_timeout = value;
	case HTTP_DNS: _config.read_timeout = value;
	default: error_printf(_("Unknown config key %d (or value must not be an integer)\n"), key);
	}
}
*/

struct _http2_stream_context {
	wget_http_response_t
		*resp;
	wget_decompressor_t
		*decompressor;
};

static int _decompress_error_handler(wget_decompressor_t *dc, int err G_GNUC_WGET_UNUSED)
{
	wget_http_response_t *resp = (wget_http_response_t *) wget_decompress_get_context(dc);

	if (resp && resp->req)
		error_printf(_("Decompress failed [host: %s - resource: %s]\n"),
			resp->req->esc_host.data, resp->req->esc_resource.data);

	return 0;
}

static int _get_body(void *userdata, const char *data, size_t length)
{
	wget_http_response_t *resp = (wget_http_response_t *) userdata;

	return resp->req->body_callback(resp, resp->req->body_user_data, data, length);
}

#ifdef WITH_LIBNGHTTP2
static ssize_t _send_callback(nghttp2_session *session G_GNUC_WGET_UNUSED,
	const uint8_t *data, size_t length, int flags G_GNUC_WGET_UNUSED, void *user_data)
{
	wget_http_connection_t *conn = (wget_http_connection_t *)user_data;
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

static ssize_t _recv_callback(nghttp2_session *session G_GNUC_WGET_UNUSED,
	uint8_t *buf, size_t length, int flags G_GNUC_WGET_UNUSED, void *user_data)
{
	wget_http_connection_t *conn = (wget_http_connection_t *)user_data;
	ssize_t rc;

	// debug_printf("reading... %zd\n", length);
	if ((rc = wget_tcp_read(conn->tcp, (char *)buf, length)) <= 0) {
		//  0 = timeout resp. blocking
		// -1 = failure
		// debug_printf("read rc %d, errno=%d\n", rc, errno);
		return rc ? NGHTTP2_ERR_CALLBACK_FAILURE : NGHTTP2_ERR_WOULDBLOCK;
	}
	// debug_printf("read rc %d\n",rc);

	return rc;
}

static void _print_frame_type(int type, const char tag, int streamid)
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

	if ((unsigned) type < countof(name))
		debug_printf("[FRAME %d] %c %s\n", streamid, tag, name[type]);
	else
		debug_printf("[FRAME %d] %c Unknown type %d\n", streamid, tag, type);
}

static int _on_frame_send_callback(nghttp2_session *session G_GNUC_WGET_UNUSED,
	const nghttp2_frame *frame, void *user_data G_GNUC_WGET_UNUSED)
{
	_print_frame_type(frame->hd.type, '>', frame->hd.stream_id);

	if (frame->hd.type == NGHTTP2_HEADERS) {
		const nghttp2_nv *nva = frame->headers.nva;

		for (unsigned i = 0; i < frame->headers.nvlen; i++)
			debug_printf("[FRAME %d] > %.*s: %.*s\n", frame->hd.stream_id,
				(int)nva[i].namelen, nva[i].name, (int)nva[i].valuelen, nva[i].value);
	}

	return 0;
}

static int _on_frame_recv_callback(nghttp2_session *session,
	const nghttp2_frame *frame, void *user_data G_GNUC_WGET_UNUSED)
{
	_print_frame_type(frame->hd.type, '<', frame->hd.stream_id);

	// header callback after receiving all header tags
	if (frame->hd.type == NGHTTP2_HEADERS) {
		struct _http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
		wget_http_response_t *resp = ctx ? ctx->resp : NULL;

		if (resp) {
			if (resp->header && resp->req->header_callback) {
				resp->req->header_callback(resp, resp->req->header_user_data);
			}

			if (!ctx->decompressor) {
				ctx->decompressor = wget_decompress_open(resp->content_encoding, _get_body, resp);
				wget_decompress_set_error_handler(ctx->decompressor, _decompress_error_handler);
			}
		}
	}

	return 0;
}

static int _on_header_callback(nghttp2_session *session,
	const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
	const uint8_t *value, size_t valuelen,
	uint8_t flags G_GNUC_WGET_UNUSED, void *user_data G_GNUC_WGET_UNUSED)
{
	struct _http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
	wget_http_response_t *resp = ctx ? ctx->resp : NULL;

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
static int _on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
	uint32_t error_code G_GNUC_WGET_UNUSED, void *user_data)
{
	struct _http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);

	debug_printf("closing stream %d\n", stream_id);
	if (ctx) {
		wget_http_connection_t *conn = (wget_http_connection_t *) user_data;

		wget_vector_add_noalloc(conn->received_http2_responses, ctx->resp);
		wget_decompress_close(ctx->decompressor);
		xfree(ctx);
	}

	return 0;
}
/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int _on_data_chunk_recv_callback(nghttp2_session *session,
	uint8_t flags G_GNUC_WGET_UNUSED, int32_t stream_id,
	const uint8_t *data, size_t len,	void *user_data G_GNUC_WGET_UNUSED)
{
	struct _http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);

	if (ctx) {
		// debug_printf("[INFO] C <---------------------------- S%d (DATA chunk - %zu bytes)\n", stream_id, len);
		// debug_printf("nbytes %zu\n", len);
		ctx->resp->cur_downloaded += len;
		wget_decompress(ctx->decompressor, (char *) data, len);
	}
	return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
	nghttp2_session_callbacks_set_send_callback(callbacks, _send_callback);
	nghttp2_session_callbacks_set_recv_callback(callbacks, _recv_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, _on_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, _on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, _on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, _on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, _on_header_callback);
}
#endif

static int _host_compare(const HOST *host1, const HOST *host2)
{
	int n;

	if ((n = wget_strcmp(host1->hostname, host2->hostname)))
		return n;

	if ((n = wget_strcmp(host1->ip, host2->ip)))
		return n;

	return wget_strcmp(host1->scheme, host2->scheme);
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int _host_hash(const HOST *host)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)host->hostname; p && *p; p++)
			hash = hash * 101 + *p;

	for (p = (unsigned char *)host->ip; p && *p; p++)
		hash = hash * 101 + *p;

	for (p = (unsigned char *)host->scheme; p && *p; p++)
			hash = hash * 101 + *p;

	return hash;
}

static void _free_host_entry(HOST *host)
{
	if (host) {
		wget_xfree(host->hostname);
		wget_xfree(host->ip);
		wget_xfree(host->scheme);
		wget_xfree(host);
	}
}

static const HOST *host_add(const HOST *hostp)
{
	if (!hosts) {
		hosts = wget_hashmap_create(16, (wget_hashmap_hash_t)_host_hash, (wget_hashmap_compare_t)_host_compare);
		wget_hashmap_set_key_destructor(hosts, (wget_hashmap_key_destructor_t)_free_host_entry);
	}

	wget_hashmap_put_noalloc(hosts, hostp, hostp);

	return hostp;
}

void host_ips_free(void)
{
	// We don't need mutex locking here - this function is called on exit when all threads have ceased.
	if (stats_callback)
		wget_hashmap_free(&hosts);
}

static void _server_stats_add(wget_http_connection_t *conn, wget_http_response_t *resp)
{
	wget_thread_mutex_lock(&hosts_mutex);

	HOST *hostp = wget_malloc(sizeof(HOST));
	hostp->hostname = wget_strdup(wget_http_get_host(conn));
	hostp->ip = wget_strdup(conn->tcp->ip);
	hostp->scheme = wget_strdup(conn->scheme);

	if (!hosts || !wget_hashmap_contains(hosts, hostp)) {
		_stats_data_t stats;

		stats.hostname = hostp->hostname;
		stats.ip = hostp->ip;
		stats.scheme = hostp->scheme;
		stats.hpkp = conn->tcp->hpkp;
		stats.hpkp_new = resp ? (resp->hpkp ? 1 : 0): -1;
		stats.hsts = resp ? (resp->hsts ? 1 : 0) : -1;
		stats.csp = resp ? (resp->csp ? 1 : 0) : -1;

		stats_callback(WGET_STATS_TYPE_SERVER, &stats);
		host_add(hostp);
	} else
		_free_host_entry(hostp);

	wget_thread_mutex_unlock(&hosts_mutex);
}

int wget_http_open(wget_http_connection_t **_conn, const wget_iri_t *iri)
{
	static int next_http_proxy = -1;
	static int next_https_proxy = -1;
	static wget_thread_mutex_t
		mutex = WGET_THREAD_MUTEX_INITIALIZER;

	wget_http_connection_t
		*conn;
	const char
		*host;
	uint16_t
		port;
	int
		rc,
		ssl = iri->scheme == WGET_IRI_SCHEME_HTTPS;

	if (!_conn)
		return WGET_E_INVALID;

	conn = *_conn = xcalloc(1, sizeof(wget_http_connection_t)); // convenience assignment

	host = iri->host;
	port = iri->port;

	if (!wget_http_match_no_proxy(no_proxies, iri->host)) {
		wget_iri_t *proxy;

		wget_thread_mutex_lock(&mutex);
		if (iri->scheme == WGET_IRI_SCHEME_HTTP && http_proxies) {
			proxy = wget_vector_get(http_proxies, (++next_http_proxy) % wget_vector_size(http_proxies));
			host = proxy->host;
			port = proxy->port;
			conn->proxied = 1;
		} else if (iri->scheme == WGET_IRI_SCHEME_HTTPS && https_proxies) {
			proxy = wget_vector_get(https_proxies, (++next_https_proxy) % wget_vector_size(https_proxies));
			host = proxy->host;
			port = proxy->port;
			conn->proxied = 1;
		}
		wget_thread_mutex_unlock(&mutex);
	}

	conn->tcp = wget_tcp_init();
	if (ssl) {
		wget_tcp_set_ssl(conn->tcp, 1); // switch SSL on
		wget_tcp_set_ssl_hostname(conn->tcp, host); // enable host name checking
	}

	if ((rc = wget_tcp_connect(conn->tcp, host, port)) == WGET_E_SUCCESS) {
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
				{NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
			};

			if ((rc = nghttp2_submit_settings(conn->http2_session, NGHTTP2_FLAG_NONE, iv, countof(iv)))) {
				error_printf(_("Failed to submit HTTP2 client settings (%d)\n"), rc);
				wget_http_close(_conn);
				return WGET_E_INVALID;
			}

			conn->received_http2_responses = wget_vector_create(16, -2, NULL);
		} else
			conn->pending_requests = wget_vector_create(16, -2, NULL);
#else
		conn->pending_requests = wget_vector_create(16, -2, NULL);
#endif
	} else {
		if (stats_callback && (rc == WGET_E_CERTIFICATE))
			_server_stats_add(conn, NULL);

		wget_http_close(_conn);
	}

	return rc;
}

void wget_http_close(wget_http_connection_t **conn)
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
static void _init_nv(nghttp2_nv *nv, const char *name, const char *value)
{
	nv->name = (uint8_t *)name;
	nv->namelen = strlen(name);
	nv->value = (uint8_t *)value;
	nv->valuelen = strlen(value);
	nv->flags = NGHTTP2_NV_FLAG_NONE;
}
#endif

int wget_http_send_request(wget_http_connection_t *conn, wget_http_request_t *req)
{
	ssize_t nbytes;

#ifdef WITH_LIBNGHTTP2
	if (wget_tcp_get_protocol(conn->tcp) == WGET_PROTOCOL_HTTP_2_0) {
		int n = 4 + wget_vector_size(req->headers);
		nghttp2_nv nvs[n], *nvp;
		char resource[req->esc_resource.length + 2];

		resource[0] = '/';
		memcpy(resource + 1, req->esc_resource.data, req->esc_resource.length + 1);
		_init_nv(&nvs[0], ":method", "GET");
		_init_nv(&nvs[1], ":path", resource);
		_init_nv(&nvs[2], ":scheme", "https");
		// _init_nv(&nvs[3], ":authority", req->esc_host.data);
		nvp = &nvs[4];

		for (int it = 0; it < wget_vector_size(req->headers); it++) {
			wget_http_header_param_t *param = wget_vector_get(req->headers, it);
			if (!wget_strcasecmp_ascii(param->name, "Connection"))
				continue;
			if (!wget_strcasecmp_ascii(param->name, "Transfer-Encoding"))
				continue;
			if (!wget_strcasecmp_ascii(param->name, "Host")) {
				_init_nv(&nvs[3], ":authority", param->value);
				continue;
			}

			_init_nv(nvp++, param->name, param->value);
		}

		struct _http2_stream_context *ctx = xcalloc(1, sizeof(struct _http2_stream_context));
		// HTTP/2.0 has the streamid as link between
		ctx->resp = xcalloc(1, sizeof(wget_http_response_t));
		ctx->resp->req = req;
		ctx->resp->major = 2;
		// we do not get a Keep-Alive header in HTTP2 - let's assume the connection stays open
		ctx->resp->keep_alive = 1;

		// nghttp2 does strdup of name+value and lowercase conversion of 'name'
		req->stream_id = nghttp2_submit_request(conn->http2_session, NULL, nvs, nvp - nvs, NULL, ctx);

		if (req->stream_id < 0) {
			error_printf(_("Failed to submit HTTP2 request\n"));
			wget_http_free_response(&ctx->resp);
			xfree(ctx);
			return -1;
		}

		conn->pending_http2_requests++;

		debug_printf("HTTP2 stream id %d\n", req->stream_id);

		return 0;
	}
#endif

	if ((nbytes = wget_http_request_to_buffer(req, conn->buf, conn->proxied)) < 0) {
		error_printf(_("Failed to create request buffer\n"));
		return -1;
	}

	if (wget_tcp_write(conn->tcp, conn->buf->data, nbytes) != nbytes) {
		// An error will be written by the wget_tcp_write function.
		// error_printf(_("Failed to send %zd bytes (%d)\n"), nbytes, errno);
		return -1;
	}

	wget_vector_add_noalloc(conn->pending_requests, req);

	if (req->debug_skip_body)
		debug_printf("# sent %zd bytes:\n%.*s<body skipped>", nbytes, (int)(conn->buf->length - req->body_length), conn->buf->data);
	else
		debug_printf("# sent %zd bytes:\n%.*s", nbytes, (int)conn->buf->length, conn->buf->data);

	return 0;
}

ssize_t wget_http_request_to_buffer(wget_http_request_t *req, wget_buffer_t *buf, int proxied)
{
	char have_content_length = 0;
	char check_content_length = req->body && req->body_length;

//	buffer_sprintf(buf, "%s /%s HTTP/1.1\r\nHost: %s", req->method, req->esc_resource.data ? req->esc_resource.data : "",);

	wget_buffer_strcpy(buf, req->method);
	wget_buffer_memcat(buf, " ", 1);
	if (proxied) {
		wget_buffer_strcat(buf, req->scheme);
		wget_buffer_memcat(buf, "://", 3);
		wget_buffer_bufcat(buf, &req->esc_host);
	}
	wget_buffer_memcat(buf, "/", 1);
	wget_buffer_bufcat(buf, &req->esc_resource);
	wget_buffer_memcat(buf, " HTTP/1.1\r\n", 11);

	for (int it = 0; it < wget_vector_size(req->headers); it++) {
		wget_http_header_param_t *param = wget_vector_get(req->headers, it);

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

wget_http_response_t *wget_http_get_response_cb(wget_http_connection_t *conn)
{
	size_t bufsize, body_len = 0, body_size = 0;
	ssize_t nbytes, nread = 0;
	char *buf, *p = NULL;
	wget_http_response_t *resp = NULL;

#ifdef WITH_LIBNGHTTP2
	if (conn->protocol == WGET_PROTOCOL_HTTP_2_0) {
		debug_printf("  ##  pending_requests = %d\n", conn->pending_http2_requests);
		if (conn->pending_http2_requests > 0)
			conn->pending_http2_requests--;
		else
			return NULL;

		int timeout = wget_tcp_get_timeout(conn->tcp);
		int ioflags;

		for (int rc = 0; rc == 0 && !wget_vector_size(conn->received_http2_responses) && !conn->abort_indicator && !_abort_indicator;) {
			debug_printf("  ##  loop responses=%d\n", wget_vector_size(conn->received_http2_responses));
			ioflags = 0;
			if (nghttp2_session_want_write(conn->http2_session))
				ioflags |= WGET_IO_WRITABLE;
			if (nghttp2_session_want_read(conn->http2_session))
				ioflags |= WGET_IO_READABLE;

			if (ioflags)
				ioflags = wget_tcp_ready_2_transfer(conn->tcp, ioflags);
			// debug_printf("ioflags=%d timeout=%d\n",ioflags,wget_tcp_get_timeout(conn->tcp));
			if (ioflags <= 0) break; // error or timeout

			wget_tcp_set_timeout(conn->tcp, 0); // 0 = immediate
			rc = 0;
			if (ioflags & WGET_IO_WRITABLE) {
				rc = nghttp2_session_send(conn->http2_session);
			}
			if (!rc && (ioflags & WGET_IO_READABLE))
				rc = nghttp2_session_recv(conn->http2_session);
			wget_tcp_set_timeout(conn->tcp, timeout); // restore old timeout

/*
			while (nghttp2_session_want_write(conn->http2_session)) {
				rc = nghttp2_session_send(conn->http2_session);
			}
			debug_printf("1 response status %d done %d\n", resp->code, ctx.done);
			if (nghttp2_session_want_read(conn->http2_session)) {
				rc = nghttp2_session_recv(conn->http2_session);
			}
*/
		}

		resp = wget_vector_get(conn->received_http2_responses, 0); // should use double linked lists here
		if (resp) {
			debug_printf("  ##  response status %d\n", resp->code);
			wget_vector_remove_nofree(conn->received_http2_responses, 0);

			// a workaround for broken server configurations
			// see https://mail-archives.apache.org/mod_mbox/httpd-dev/200207.mbox/<3D2D4E76.4010502@talex.com.pl>
			if (resp->content_encoding == wget_content_encoding_gzip &&
				!wget_strcasecmp_ascii(resp->content_type, "application/x-gzip"))
			{
				debug_printf("Broken server configuration gzip workaround triggered\n");
				resp->content_encoding =  wget_content_encoding_identity;
			}
		}

		if (stats_callback)
			_server_stats_add(conn, resp);

		return resp;
	}
#endif

	wget_decompressor_t *dc = NULL;
	wget_http_request_t *req = wget_vector_get(conn->pending_requests, 0); // TODO: should use double linked lists here

	debug_printf("### req %p pending requests = %d\n", (void *) req, wget_vector_size(conn->pending_requests));
	if (!req)
		goto cleanup;

	wget_vector_remove_nofree(conn->pending_requests, 0);

	// reuse generic connection buffer
	buf = conn->buf->data;
	bufsize = conn->buf->size;

	while ((nbytes = wget_tcp_read(conn->tcp, buf + nread, bufsize - nread)) > 0) {
		// debug_printf("nbytes %zd nread %zd %zu\n", nbytes, nread, bufsize);
		nread += nbytes;
		buf[nread] = 0; // 0-terminate to allow string functions

		if (nread < 4) continue;

		if (nread == nbytes)
			p = buf;
		else
			p = buf + nread - nbytes - 3;

		if ((p = strstr(p, "\r\n\r\n"))) {
			// found end-of-header
			*p = 0;

			debug_printf("# got header %zd bytes:\n%s\n\n", p - buf, buf);

			if (req->response_keepheader) {
				wget_buffer_t *header = wget_buffer_alloc(p - buf + 4);
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

			if (stats_callback)
				_server_stats_add(conn, resp);

			if (req->header_callback) {
				if (req->header_callback(resp, req->header_user_data))
					goto cleanup; // stop requested by callback function
			}

			if (req && !wget_strcasecmp_ascii(req->method, "HEAD"))
				goto cleanup; // a HEAD response won't have a body

			p += 4; // skip \r\n\r\n to point to body
			break;
		}

		if ((size_t)nread + 1024 > bufsize) {
			wget_buffer_ensure_capacity(conn->buf, bufsize + 1024);
			buf = conn->buf->data;
			bufsize = conn->buf->size;
		}
	}
	if (!nread) goto cleanup;

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
	 || (resp->transfer_encoding == transfer_encoding_identity && resp->content_length == 0 && resp->content_length_valid)) {
		// - body not included, see RFC 2616 4.3
		// - body empty, see RFC 2616 4.4
		goto cleanup;
	}

	dc = wget_decompress_open(resp->content_encoding, _get_body, resp);
	wget_decompress_set_error_handler(dc, _decompress_error_handler);

	// calculate number of body bytes so far read
	body_len = nread - (p - buf);
	// move already read body data to buf
	memmove(buf, p, body_len);
	buf[body_len] = 0;
	resp->cur_downloaded = body_len;

	if (resp->transfer_encoding == transfer_encoding_chunked) {
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
				if (conn->abort_indicator || _abort_indicator)
					goto cleanup;

				if ((nbytes = wget_tcp_read(conn->tcp, buf + body_len, bufsize - body_len)) <= 0)
					goto cleanup;

				body_len += nbytes;
				buf[body_len] = 0;
				// debug_printf("a nbytes %zd body_len %zu\n", nbytes, body_len);
			}
			end += 2;

			// now p points to chunk-size (hex)
			chunk_size = strtoll(p, NULL, 16);
			debug_printf("chunk size is %zu\n", chunk_size);
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

					if (conn->abort_indicator || _abort_indicator)
						goto cleanup;

					if ((nbytes = wget_tcp_read(conn->tcp, buf + body_len, bufsize - body_len)) <= 0)
						goto cleanup;

					body_len += nbytes;
					buf[body_len] = 0;
					end = buf;
					// debug_printf("a nbytes %zd\n", nbytes);
				}
				debug_printf("end of trailer \n");
				goto cleanup;
			}

			// check for pointer overflow
			if (end > end + chunk_size || end >= end + chunk_size + 2) {
				error_printf(_("Chunk size overflow: %lX\n"), chunk_size);
				goto cleanup;
			}

			p = end + chunk_size + 2;
			if (p <= buf + body_len) {
				// debug_printf("write full chunk, %zu bytes\n", chunk_size);
				resp->cur_downloaded += chunk_size;
				wget_decompress(dc, end, chunk_size);
				continue;
			}

			resp->cur_downloaded += (buf + body_len) - end;
			wget_decompress(dc, end, (buf + body_len) - end);

			chunk_size = (((uintptr_t) p) - ((uintptr_t) (buf + body_len))); // in fact needed bytes to have chunk_size+2 in buf

			debug_printf("need at least %zu more bytes\n", chunk_size);

			while (chunk_size > 0) {
				if (conn->abort_indicator || _abort_indicator)
					goto cleanup;

				if ((nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) <= 0)
					goto cleanup;
				// debug_printf("a nbytes=%zd chunk_size=%zu\n", nread, chunk_size);

				if (chunk_size <= (size_t)nbytes) {
					if (chunk_size == 1 || !strncmp(buf + chunk_size - 2, "\r\n", 2)) {
						debug_printf("chunk completed\n");
						// p=end+chunk_size+2;
					} else {
						error_printf(_("Expected end-of-chunk not found\n"));
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
	} else if (resp->content_length_valid) {
		// read content_length bytes
		debug_printf("method 2\n");

		if (body_len)
			wget_decompress(dc, buf, body_len);

		while (body_len < resp->content_length) {
			if (conn->abort_indicator || _abort_indicator)
				break;

			if (((nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) <= 0))
				break;

			body_len += nbytes;
			// debug_printf("nbytes %zd total %zu/%zu\n", nbytes, body_len, resp->content_length);
			resp->cur_downloaded += nbytes;
			wget_decompress(dc, buf, nbytes);
		}
		if (nbytes < 0)
			error_printf(_("Failed to read %zd bytes (%d)\n"), nbytes, errno);
		if (body_len < resp->content_length)
			error_printf(_("Just got %zu of %zu bytes\n"), body_len, resp->content_length);
		else if (body_len > resp->content_length)
			error_printf(_("Body too large: %zu instead of %zu bytes\n"), body_len, resp->content_length);
		resp->content_length = body_len;
	} else {
		// read as long as we can
		debug_printf("method 3\n");

		if (body_len)
			wget_decompress(dc, buf, body_len);

		while (!conn->abort_indicator && !_abort_indicator && (nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) > 0) {
			body_len += nbytes;
			// debug_printf("nbytes %zd total %zu\n", nbytes, body_len);
			resp->cur_downloaded += nbytes;
			wget_decompress(dc, buf, nbytes);
		}
		resp->content_length = body_len;
	}

cleanup:
	wget_decompress_close(dc);

	return resp;
}

// get response, resp->body points to body in memory

wget_http_response_t *wget_http_get_response(wget_http_connection_t *conn)
{
	wget_http_response_t *resp;

	resp = wget_http_get_response_cb(conn);

	if (resp) {
		if (!wget_strcasecmp_ascii(resp->req->method, "GET"))
			if (resp->body)
				resp->content_length = resp->body->length;
	}

	return resp;
}

static wget_vector_t *_parse_proxies(const char *proxy, const char *encoding)
{
	if (!proxy)
		return NULL;

	wget_vector_t *proxies = NULL;
	const char *s, *p;

	for (s = p = proxy; *p; s = p + 1) {
		if ((p = strchrnul(s, ',')) != s && p - s < 256) {
			wget_iri_t *iri;
			char host[p - s + 1];

			memcpy(host, s, p - s);
			host[p - s] = 0;

			iri = wget_iri_parse (host, encoding);
			if (iri) {
				if (!proxies) {
					proxies = wget_vector_create(8, -2, NULL);
					wget_vector_set_destructor(proxies, (wget_vector_destructor_t)wget_iri_free_content);
				}
				wget_vector_add_noalloc(proxies, iri);
			}
		}
	}

	return proxies;
}

static wget_vector_t *_parse_no_proxies(const char *no_proxy, const char *encoding)
{
	if (!no_proxy)
		return NULL;

	wget_vector_t *proxies;
	const char *s, *p;

	proxies = wget_vector_create(8, -2, NULL);
	wget_vector_set_destructor(proxies, (wget_vector_destructor_t)wget_iri_free_content);

	for (s = p = no_proxy; *p; s = p + 1) {
		while (c_isspace(*s) && s < p) s++;

		if ((p = strchrnul(s, ',')) != s && p - s < 256) {
			char *host, *hostp;

			host = wget_strmemdup(s, p - s);

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

			wget_vector_add_noalloc(proxies, host);
		}
	}

	return proxies;
}

int wget_http_set_http_proxy(const char *proxy, const char *encoding)
{
	if (http_proxies)
		wget_vector_free(&http_proxies);

	http_proxies = _parse_proxies(proxy, encoding);

	return wget_vector_size(http_proxies);
}

int wget_http_set_https_proxy(const char *proxy, const char *encoding)
{
	if (https_proxies)
		wget_vector_free(&https_proxies);

	https_proxies = _parse_proxies(proxy, encoding);

	return wget_vector_size(https_proxies);
}

int wget_http_set_no_proxy(const char *no_proxy, const char *encoding)
{
	if (no_proxies)
		wget_vector_free(&no_proxies);

	no_proxies = _parse_no_proxies(no_proxy, encoding);
	if (!no_proxies)
		return -1;

	return 0;
}

int wget_http_match_no_proxy(wget_vector_t *no_proxies_vec, const char *host)
{
	if (!no_proxies_vec || !host)
		return 0;

	// https://www.gnu.org/software/emacs/manual/html_node/url/Proxies.html
	for (int it = 0; it < wget_vector_size(no_proxies_vec); it++) {
		const char *no_proxy = wget_vector_get(no_proxies_vec, it);

		if (!strcmp(no_proxy, host))
			return 1; // exact match

		// check for subdomain match
		if (*no_proxy == '.' && wget_match_tail(host, no_proxy))
			return 1;
	}

	return 0;
}

void wget_http_abort_connection(wget_http_connection_t *conn)
{
	if (conn)
		conn->abort_indicator = 1; // stop single connection
	else
		_abort_indicator = 1; // stop all connections
}

/**
 * \param[in] fn A `wget_stats_callback_t` callback function used to collect Server statistics
 *
 * Set callback function to be called once Server statistics for a host are collected
 */
void wget_tcp_set_stats_server(wget_stats_callback_t fn)
{
	stats_callback = fn;
}

/**
 * \param[in] type A `wget_server_stats_t` constant representing Server statistical info to return
 * \param[in] _stats An internal  pointer sent to callback function
 * \return Server statistical info in question
 *
 * Get the specific Server statistics information
 */
const void *wget_tcp_get_stats_server(wget_server_stats_t type, const void *_stats)
{
	const _stats_data_t *stats = (_stats_data_t *) _stats;

	switch(type) {
	case WGET_STATS_SERVER_HOSTNAME:
		return stats->hostname;
	case WGET_STATS_SERVER_IP:
		return stats->ip;
	case WGET_STATS_SERVER_SCHEME:
		return stats->scheme;
	case WGET_STATS_SERVER_HPKP:
		return &(stats->hpkp);
	case WGET_STATS_SERVER_HPKP_NEW:
		return &(stats->hpkp_new);
	case WGET_STATS_SERVER_HSTS:
		return &(stats->hsts);
	case WGET_STATS_SERVER_CSP:
		return &(stats->csp);
	default:
		return NULL;
	}
}
