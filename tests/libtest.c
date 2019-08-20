/*
 * Copyright(c) 2013-2014 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 * Test suite function library
 *
 * Changelog
 * 16.01.2013  Tim Ruehsen  created
 *
 * To create the X.509 stuff, I followed the instructions at
 *   gnutls.org/manual/html_node/gnutls_002dserv-Invocation.html
 *
 */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <wget.h>
#include "../src/wget_utils.h"
#include "libtest.h"

#include <microhttpd.h>
#ifdef HAVE_MICROHTTPD_HTTP2_H
#  include <microhttpd_http2.h>
#endif
#ifndef HAVE_MHD_FREE
#  define MHD_free wget_free
#endif
#ifndef MHD_HTTP_RANGE_NOT_SATISFIABLE
#  define MHD_HTTP_RANGE_NOT_SATISFIABLE MHD_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE
#endif
#ifndef MHD_USE_TLS
#  define MHD_USE_TLS MHD_USE_SSL
#endif

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HAVE_GNUTLS_OCSP_H
#  include <gnutls/ocsp.h>
#  include <gnutls/x509.h>
#  include <gnutls/abstract.h>
#endif

#ifdef WITH_GNUTLS
#  include <gnutls/gnutls.h>
#  define file_load_err(fname, msg) wget_error_printf_exit("Couldn't load '%s' : %s\n", fname, msg)
#endif

static int
	http_server_port,
	https_server_port,
	ocsp_server_port,
	h2_server_port,
	keep_tmpfiles,
	reject_http_connection,
	reject_https_connection;
static wget_vector
	*request_urls;
static wget_test_url_t
	*urls;
static size_t
	nurls;
static char
	tmpdir[128];
static char
	server_send_content_length = 1;

#if MHD_VERSION >= 0x00096302 && GNUTLS_VERSION_NUMBER >= 0x030603
static enum CHECK_POST_HANDSHAKE_AUTH {
	CHECK_ENABLED,
	CHECK_PASSED,
	CHECK_FAILED
} *post_handshake_auth;
#endif

// MHD_Daemon instance
static struct MHD_Daemon
	*httpdaemon,
	*httpsdaemon,
	*ocspdaemon,
	*h2daemon;

#ifdef HAVE_GNUTLS_OCSP_H
static gnutls_pcert_st *pcrt;
static gnutls_privkey_t *privkey;

static struct ocsp_resp_t {
	char
		*data;
	size_t
		size;
} *ocsp_resp;
#endif

#ifdef HAVE_GNUTLS_OCSP_H
#if MHD_VERSION >= 0x00096502 && GNUTLS_VERSION_NUMBER >= 0x030603
static gnutls_pcert_st *pcrt_stap;
static gnutls_privkey_t *privkey_stap;
static gnutls_ocsp_data_st *ocsp_stap_resp;
#endif
#endif

// for passing URL query string
struct query_string {
	wget_buffer
		*params;
	int
		it;
};

static char
	*key_pem,
	*cert_pem;

enum SERVER_MODE {
	HTTP_MODE,
	HTTPS_MODE,
	OCSP_MODE,
	OCSP_STAP_MODE,
	H2_MODE
};

static enum PASS {
	HTTP_1_1_PASS,
	H2_PASS,
	END_PASS
} proto_pass;

static char *_scan_directory(const char* data)
{
	return strchr(data, '/');
}


static const char *_parse_hostname(const char* data)
{
	if (data) {
		if (!wget_strncasecmp_ascii(data, "http://", 7)) {
			return strchr(data += 7, '/');
		} else if (!wget_strncasecmp_ascii(data, "https://", 8)) {
			return strchr(data += 8, '/');
		}
	}

	return data;
}

static void _replace_space_with_plus(wget_buffer *buf, const char *data)
{
	for (; *data; data++)
		wget_buffer_memcat(buf, *data == ' ' ? "+" : data, 1);
}

static int _print_query_string(
	void *cls,
	enum MHD_ValueKind kind WGET_GCC_UNUSED,
	const char *key,
	const char *value)
{
	struct query_string *query = cls;

	if (key && !query->it) {
		wget_buffer_strcpy(query->params, "?");
		_replace_space_with_plus(query->params, key);
		if (value) {
			wget_buffer_strcat(query->params, "=");
			_replace_space_with_plus(query->params, value);
		}
	}
	if (key && query->it) {
		wget_buffer_strcat(query->params, "&");
		_replace_space_with_plus(query->params, key);
		if (value) {
			wget_buffer_strcat(query->params, "=");
			_replace_space_with_plus(query->params, value);
		}
	}

	query->it++;
	return MHD_YES;
}

static int _print_header_range(
	void *cls,
	enum MHD_ValueKind kind WGET_GCC_UNUSED,
	const char *key,
	const char *value)
{
	wget_buffer *header_range = cls;

	if (!strcasecmp(key, MHD_HTTP_HEADER_RANGE)) {
		wget_buffer_strcpy(header_range, key);
		if (value) {
			wget_buffer_strcat(header_range, value);
		}
	}

	return MHD_YES;
}

struct ResponseContentCallbackParam
{
	const char *response_data;
	size_t response_size;
};

static ssize_t _callback (void *cls, uint64_t pos, char *buf, size_t buf_size)
{
	size_t size_to_copy;
	struct ResponseContentCallbackParam *const param =
		(struct ResponseContentCallbackParam *)cls;

	if (pos >= param->response_size)
		return MHD_CONTENT_READER_END_OF_STREAM;

	// divide data into two chunks
	buf_size = (param->response_size / 2) + 1;
	if (buf_size < (param->response_size - pos))
		size_to_copy = buf_size;
	else
		size_to_copy = param->response_size - pos;

	memcpy (buf, param->response_data + pos, size_to_copy);

	return size_to_copy;
}

static void _free_callback_param(void *cls)
{
	wget_free(cls);
}

#ifdef HAVE_GNUTLS_OCSP_H
static int _ocsp_ahc(
	void *cls WGET_GCC_UNUSED,
	struct MHD_Connection *connection,
	const char *url WGET_GCC_UNUSED,
	const char *method WGET_GCC_UNUSED,
	const char *version WGET_GCC_UNUSED,
	const char *upload_data,
	size_t *upload_data_size,
	void **con_cls WGET_GCC_UNUSED)
{
	static bool first = true;

	if (first && upload_data == NULL) {
		first = false;

		return MHD_YES;
	} else if (!first && upload_data == NULL) {
		int ret = 0;

		if (ocsp_resp->data) {
			struct MHD_Response *response = MHD_create_response_from_buffer (ocsp_resp->size, ocsp_resp->data, MHD_RESPMEM_MUST_COPY);

			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);

			MHD_destroy_response (response);

			wget_xfree(ocsp_resp->data);
		}

		return ret;
	}

	*upload_data_size = 0;

	return MHD_YES;
}

static int _ocsp_cert_callback(
	gnutls_session_t session WGET_GCC_UNUSED,
	const gnutls_datum_t* req_ca_dn WGET_GCC_UNUSED,
	int nreqs WGET_GCC_UNUSED,
	const gnutls_pk_algorithm_t* pk_algos WGET_GCC_UNUSED,
	int pk_algos_length WGET_GCC_UNUSED,
	gnutls_pcert_st** pcert,
	unsigned int *pcert_length,
	gnutls_privkey_t *pkey)
{
	*pcert = pcrt;
	*(pcert+1) = pcrt+1;
	*pkey = *privkey;
	*pcert_length = 2;

	return 0;
}

#if MHD_VERSION >= 0x00096502 && GNUTLS_VERSION_NUMBER >= 0x030603
static gnutls_certificate_retrieve_function3 _ocsp_stap_cert_callback;
static int _ocsp_stap_cert_callback(
	gnutls_session_t session WGET_GCC_UNUSED,
	const struct gnutls_cert_retr_st *info WGET_GCC_UNUSED,
	gnutls_pcert_st **pcert,
	unsigned int *pcert_length,
	gnutls_ocsp_data_st **ocsp,
	unsigned int *ocsp_length,
	gnutls_privkey_t *pkey,
	unsigned int *flags WGET_GCC_UNUSED)
{
	*pcert = pcrt_stap;
	*pkey = *privkey_stap;
	*pcert_length = 1;

	*ocsp = ocsp_stap_resp;
	*ocsp_length = 1;

	return 0;
}
#endif
#endif

static int _answer_to_connection(
	void *cls WGET_GCC_UNUSED,
	struct MHD_Connection *connection,
	const char *url,
	const char *method,
	const char *version WGET_GCC_UNUSED,
	const char *upload_data WGET_GCC_UNUSED,
	size_t *upload_data_size WGET_GCC_UNUSED,
	void **con_cls WGET_GCC_UNUSED)
{
#if MHD_VERSION >= 0x00096302 && GNUTLS_VERSION_NUMBER >= 0x030603
	if (post_handshake_auth != NULL) {
		gnutls_session_t tls_sess;
		const union MHD_ConnectionInfo *conn_info = MHD_get_connection_info (connection, MHD_CONNECTION_INFO_GNUTLS_SESSION);

		if (conn_info) {
			int check_auth;
			tls_sess = conn_info->tls_session;
			gnutls_certificate_server_set_request(tls_sess, GNUTLS_CERT_REQUEST);
			do
				check_auth = gnutls_reauth(tls_sess, 0);
			while (check_auth == GNUTLS_E_AGAIN);

			*post_handshake_auth = (check_auth == GNUTLS_E_SUCCESS) ? CHECK_PASSED : CHECK_FAILED;
		}
	}
#endif

	struct MHD_Response *response = NULL;
	struct query_string query;
	int ret = 0;
	time_t modified;
	const char *modified_val, *to_bytes_string = "";
	ssize_t from_bytes, to_bytes;
	size_t body_len;
	char content_len[100], content_range[100];

	// whether or not this connection is HTTPS
	bool https = !!MHD_get_connection_info(connection, MHD_CONNECTION_INFO_PROTOCOL);

	// get query string
	query.params = wget_buffer_alloc(1024);
	query.it = 0;
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, &_print_query_string, &query);

	// get if-modified-since header
	modified_val = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
												MHD_HTTP_HEADER_IF_MODIFIED_SINCE);
	modified = 0;
	if (modified_val)
		modified = wget_http_parse_full_date(modified_val);

	// get header range
	wget_buffer *header_range = wget_buffer_alloc(1024);
	if (!strcmp(method, "GET"))
		MHD_get_connection_values(connection, MHD_HEADER_KIND, &_print_header_range, header_range);

	from_bytes = to_bytes = body_len = 0;
	if (*header_range->data) {
		const char *from_bytes_string;
		const char *range_string = strchr(header_range->data, '=');

		to_bytes_string = strchr(range_string, '-');
		if (strcmp(to_bytes_string, "-"))
			to_bytes = (ssize_t) atoi(to_bytes_string + 1);
		from_bytes_string = wget_strmemdup(range_string, to_bytes_string - range_string);
		from_bytes = (ssize_t) atoi(from_bytes_string + 1);
		wget_xfree(from_bytes_string);
	}

	// append query string into URL
	wget_buffer *url_full = wget_buffer_alloc(1024);
	wget_buffer_strcpy(url_full, url);
	if (query.params->data)
		wget_buffer_strcat(url_full, query.params->data);
	wget_buffer_free(&query.params);

	// default page to index.html
	if (!strcmp(url_full->data, "/"))
		wget_buffer_strcat(url_full, "index.html");

	// it1 = iteration for urls data
	unsigned int found = 0, chunked = 0;
	for (unsigned it1 = 0; it1 < nurls && !found; it1++) {
		if (urls[it1].http_only && https)
			continue;
		if (urls[it1].https_only && !https)
			continue;

		// create default page for directory without index page
		const char *dir = _scan_directory(url_full->data + 1);
		if (dir && !strcmp(dir, "/"))
			wget_buffer_strcat(url_full, "index.html");

		// create default page for hostname without index page
		const char *host = _parse_hostname(url_full->data);
		if (host && !strcmp(host, "/"))
			wget_buffer_strcat(url_full, "index.html");

		// convert remote url into escaped char for iri encoding
		wget_buffer *url_iri = wget_buffer_alloc(1024);
		wget_buffer_strcpy(url_iri, urls[it1].name);
		MHD_http_unescape(url_iri->data);

		if (!strcmp(_parse_hostname(url_full->data), _parse_hostname(url_iri->data))) {
			size_t body_length =
				urls[it1].body_len ? urls[it1].body_len
				: (urls[it1].body ? strlen(urls[it1].body) : 0);

			// check request headers
			int bad_request = 0;

			for (unsigned it2 = 0; urls[it1].expected_req_headers[it2]; it2++) {
				const char *header = urls[it1].expected_req_headers[it2];
				if (header) {
					const char *header_value = strchr(header, ':');
					const char *header_key = wget_strmemdup(header, header_value - header);
					const char *got_val = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, header_key);
					// 400 Bad Request
					if (!got_val || strcmp(got_val, header_value + 2)) {
						bad_request = 1;
						wget_xfree(header_key);
						break;
					}
					wget_xfree(header_key);
				}
			}

			// check unexpected headers
			for (unsigned it2 = 0; urls[it1].unexpected_req_headers[it2] && !bad_request; it2++) {
				const char *header_key = urls[it1].unexpected_req_headers[it2];
				const char *got_val = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, header_key);
				// 400 Bad Request
				if (got_val) {
					bad_request = 1;
					break;
				}
			}

			// return with "400 Bad Request"
			if (bad_request) {
				response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
				ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
				wget_buffer_free(&url_iri);
				found = 1;
				break;
			}

			// chunked encoding
			if (!wget_strcmp(urls[it1].name + 3, "bad.txt")) {
				response = MHD_create_response_from_buffer(body_length,
					(void *) urls[it1].body, MHD_RESPMEM_MUST_COPY);
				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
				MHD_add_response_header(response, "Transfer-Encoding", "chunked");
				MHD_add_response_header(response, "Connection", "close");
				wget_buffer_free(&url_iri);
				found = 1;
				break;
			}
			for (int it2 = 0; urls[it1].headers[it2]; it2++) {
				const char *header = urls[it1].headers[it2];
				if (header) {
					const char *header_value = strchr(header, ':');
					const char *header_key = wget_strmemdup(header, header_value - header);
					if (!strcmp(header_key, "Transfer-Encoding") && !strcmp(header_value + 2, "chunked"))
						chunked = 1;
					wget_xfree(header_key);
				}
			}
			if (chunked == 1) {
				struct ResponseContentCallbackParam *callback_param = wget_malloc(sizeof(struct ResponseContentCallbackParam));

				callback_param->response_data = urls[it1].body;
				callback_param->response_size = body_length;

				response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
					1024, &_callback, callback_param, &_free_callback_param);
				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
				wget_buffer_free(&url_iri);
				found = 1;
				break;
			}

			// redirection
			if (atoi(urls[it1].code)/100 == 3) {
				response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
				// it2 = iteration for headers
				for (unsigned it2 = 0; urls[it1].headers[it2]; it2++) {
					const char *header = urls[it1].headers[it2];
					if (header) {
						const char *header_value = strchr(header, ':');
						const char *header_key = wget_strmemdup(header, header_value - header);
						MHD_add_response_header(response, header_key, header_value + 2);
						wget_xfree(header_key);
					}
				}
				ret = MHD_queue_response(connection, MHD_HTTP_FOUND, response);
				wget_buffer_free(&url_iri);
				found = 1;
				break;
			}

			// 404 with non-empty "body"
			if (atoi(urls[it1].code) != 200) {
				response = MHD_create_response_from_buffer(body_length,
					(void *) urls[it1].body, MHD_RESPMEM_MUST_COPY);
				ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
				wget_buffer_free(&url_iri);
				found = 1;
				break;
			}

			// basic authentication
			if (!wget_strcmp(urls[it1].auth_method, "Basic")) {
				char *pass = NULL;
				char *user = MHD_basic_auth_get_username_password(connection, &pass);
				if ((user == NULL && pass == NULL) ||
					wget_strcmp(user, urls[it1].auth_username) ||
					wget_strcmp(pass, urls[it1].auth_password))
				{
					response = MHD_create_response_from_buffer(strlen ("DENIED"),
						(void *) "DENIED", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_basic_auth_fail_response(connection, "basic@example.com", response);
					MHD_free(user);
					MHD_free(pass);
					wget_buffer_free(&url_iri);
					found = 1;
					break;
				}
				MHD_free(user);
				MHD_free(pass);
			}

			// digest authentication
			if (!wget_strcmp(urls[it1].auth_method, "Digest")) {
				const char *realm = "digest@example.com";
				char *user = MHD_digest_auth_get_username(connection);
				if (wget_strcmp(user, urls[it1].auth_username)) {
					response = MHD_create_response_from_buffer(strlen ("DENIED"),
						(void *) "DENIED", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_auth_fail_response(connection, realm, TEST_OPAQUE_STR, response, MHD_NO);
					MHD_free(user);
					wget_buffer_free(&url_iri);
					found = 1;
					break;
				}
				ret = MHD_digest_auth_check(connection, realm, user, urls[it1].auth_password, 300);
				MHD_free(user);
				if ((ret == MHD_INVALID_NONCE) || (ret == MHD_NO)) {
					response = MHD_create_response_from_buffer(strlen ("DENIED"),
						(void *) "DENIED", MHD_RESPMEM_PERSISTENT);

					if (response) {
						ret = MHD_queue_auth_fail_response(connection, realm, TEST_OPAQUE_STR, response,
							(ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);
						found = 1;
					} else
						ret = MHD_NO;

					wget_buffer_free(&url_iri);
					break;
				}
			}

			if (modified && urls[it1].modified <= modified) {
				response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
				ret = MHD_queue_response(connection, MHD_HTTP_NOT_MODIFIED, response);
			}
			else if (*header_range->data) {
				if (!strcmp(to_bytes_string, "-"))
					to_bytes = body_length - 1;
				body_len = to_bytes - from_bytes + 1;

				if (from_bytes > to_bytes || from_bytes >= (int) body_length) {
					response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_response(connection, MHD_HTTP_RANGE_NOT_SATISFIABLE, response);
				} else {
					response = MHD_create_response_from_buffer(body_len,
						(void *) (urls[it1].body + from_bytes), MHD_RESPMEM_MUST_COPY);
					MHD_add_response_header(response, MHD_HTTP_HEADER_ACCEPT_RANGES, "bytes");
					wget_snprintf(content_range, sizeof(content_range), "%zd-%zd/%zu", from_bytes, to_bytes, body_len);
					MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_RANGE, content_range);
					wget_snprintf(content_len, sizeof(content_len), "%zu", body_len);
					MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_LENGTH, content_len);
					ret = MHD_queue_response(connection, MHD_HTTP_PARTIAL_CONTENT, response);
				}
			} else {
				response = MHD_create_response_from_buffer(body_length, (void *) urls[it1].body, MHD_RESPMEM_MUST_COPY);
				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
			}

			// add available headers
			if (*urls[it1].headers) {
				// it2 = iteration for headers
				for (unsigned int it2 = 0; urls[it1].headers[it2] != NULL; it2++) {
					const char *header = urls[it1].headers[it2];
					if (header) {
						const char *header_value = strchr(header, ':');
						const char *header_key = wget_strmemdup(header, header_value - header);
						MHD_add_response_header(response, header_key, header_value + 2);
						wget_xfree(header_key);
					}
				}
			}

			found = 1;
		}

		wget_buffer_free(&url_iri);
	}

	// 404 with empty "body"
	if (!found) {
		response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
	}

	wget_buffer_free(&url_full);
	wget_buffer_free(&header_range);
	char server_version[50];
	wget_snprintf(server_version, sizeof(server_version), "Libmicrohttpd/%08x", (unsigned int) MHD_VERSION);
	MHD_add_response_header(response, "Server", server_version);
	MHD_destroy_response(response);
	return ret;
}

static void _http_server_stop(void)
{
	MHD_stop_daemon(httpdaemon);
	MHD_stop_daemon(httpsdaemon);
	MHD_stop_daemon(ocspdaemon);
	MHD_stop_daemon(h2daemon);

	wget_xfree(key_pem);
	wget_xfree(cert_pem);

#ifdef HAVE_GNUTLS_OCSP_H
	gnutls_global_deinit();

	if(ocsp_resp)
		wget_free(ocsp_resp->data);

	wget_xfree(ocsp_resp);
#endif
}

static int _check_to_accept(
	void *cls,
	WGET_GCC_UNUSED const struct sockaddr *addr,
	WGET_GCC_UNUSED socklen_t addrlen)
{
	int server_mode = (int) (ptrdiff_t) cls;

	if (server_mode == HTTP_MODE)
		return reject_http_connection ? MHD_NO : MHD_YES;

	return reject_https_connection ? MHD_NO : MHD_YES;
}

static int _http_server_start(int SERVER_MODE)
{
	uint16_t port_num = 0;

	if (SERVER_MODE == HTTP_MODE) {
		static char rnd[8] = "realrnd"; // fixed 'random' value

		httpdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
			port_num, _check_to_accept, (void *) (ptrdiff_t) SERVER_MODE, &_answer_to_connection, NULL,
			MHD_OPTION_DIGEST_AUTH_RANDOM, sizeof(rnd), rnd,
			MHD_OPTION_NONCE_NC_SIZE, 300,
#ifdef MHD_OPTION_STRICT_FOR_CLIENT
			MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
			MHD_OPTION_END);

		if (!httpdaemon)
			return 1;
	} else if (SERVER_MODE == HTTPS_MODE || SERVER_MODE == H2_MODE) {
		size_t size;

		if (!ocspdaemon) {
			key_pem = wget_read_file(SRCDIR "/certs/x509-server-key.pem", &size);
			cert_pem = wget_read_file(SRCDIR "/certs/x509-server-cert.pem", &size);

			if ((key_pem == NULL) || (cert_pem == NULL))
			{
				wget_error_printf(_("The key/certificate files could not be read.\n"));
				return 1;
			}

			if (SERVER_MODE == HTTPS_MODE) {
				httpsdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
#if MHD_VERSION >= 0x00096302
						| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
#endif
					,
					port_num, _check_to_accept, (void *) (ptrdiff_t) SERVER_MODE, &_answer_to_connection, NULL,
					MHD_OPTION_HTTPS_MEM_KEY, key_pem,
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
#ifdef MHD_OPTION_STRICT_FOR_CLIENT
					MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
				MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) 1*1024*1024,
				MHD_OPTION_END);

				if (!httpsdaemon) {
					wget_error_printf(_("Cannot start the HTTPS server.\n"));
					return 1;
				}
			}
			else {
#ifdef HAVE_MICROHTTPD_HTTP2_H
				h2daemon = MHD_start_daemon(MHD_USE_HTTP2 | MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
#if MHD_VERSION >= 0x00096302
						| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
#endif
					,
					port_num, _check_to_accept, (void *) (ptrdiff_t) SERVER_MODE, &_answer_to_connection, NULL,
					MHD_OPTION_HTTPS_MEM_KEY, key_pem,
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
#ifdef MHD_OPTION_STRICT_FOR_CLIENT
					MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
					//Enough to send 1MB files through
					MHD_OPTION_CONNECTION_MEMORY_LIMIT, 1*1024*1024,
					MHD_OPTION_END);
#endif

				if (!h2daemon) {
					wget_error_printf(_("Cannot start the h2 server.\n"));
					wget_error_printf(_("HTTP/2 support for MHD not found.\n"));
					return 1;
				}
			}
		}
#ifdef HAVE_GNUTLS_OCSP_H
		else {
			httpsdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
#if MHD_VERSION >= 0x00096302
					| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
#endif
				,
				port_num, _check_to_accept, (void *) (ptrdiff_t) SERVER_MODE, &_answer_to_connection, NULL,
				MHD_OPTION_HTTPS_CERT_CALLBACK, &_ocsp_cert_callback,
#ifdef MHD_OPTION_STRICT_FOR_CLIENT
				MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
				MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) 1*1024*1024,
				MHD_OPTION_END);

			int rc;
			gnutls_datum_t data;

			privkey = wget_malloc(sizeof(gnutls_privkey_t));
			gnutls_privkey_init(privkey);

			if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-key.pem", &data)) < 0)
				file_load_err(SRCDIR "/certs/ocsp/x509-server-key.pem", gnutls_strerror(rc));

			gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
			gnutls_free(data.data);

			pcrt = wget_malloc(sizeof(gnutls_pcert_st)*2);

			if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-cert.pem", &data)) < 0)
				file_load_err(SRCDIR "/certs/ocsp/x509-server-cert.pem", gnutls_strerror(rc));

			gnutls_pcert_import_x509_raw(pcrt, &data, GNUTLS_X509_FMT_PEM, 0);
			gnutls_free(data.data);

			if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-interm-cert.pem", &data)) < 0)
				file_load_err(SRCDIR "/certs/ocsp/x509-interm-cert.pem", gnutls_strerror(rc));

			gnutls_pcert_import_x509_raw(pcrt+1, &data, GNUTLS_X509_FMT_PEM, 0);
			gnutls_free(data.data);

			if (!httpsdaemon) {
				wget_error_printf(_("Cannot start the HTTPS server.\n"));
				return 1;
			}

		}
#endif
	} else if (SERVER_MODE == OCSP_MODE) {
#ifdef HAVE_GNUTLS_OCSP_H
		static char rnd[8] = "realrnd"; // fixed 'random' value

		ocspdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
			port_num, NULL, NULL, &_ocsp_ahc, NULL,
			MHD_OPTION_DIGEST_AUTH_RANDOM, sizeof(rnd), rnd,
			MHD_OPTION_NONCE_NC_SIZE, 300,
#ifdef MHD_OPTION_STRICT_FOR_CLIENT
			MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
			MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) 1*1024*1024,
			MHD_OPTION_END);

		ocsp_resp = wget_malloc(sizeof(struct ocsp_resp_t));
#endif

		if (!ocspdaemon)
			return 1;
	}
#ifdef HAVE_GNUTLS_OCSP_H
#if MHD_VERSION >= 0x00096502 && GNUTLS_VERSION_NUMBER >= 0x030603
	else if (SERVER_MODE == OCSP_STAP_MODE) {
		int rc;

		gnutls_datum_t data;

		pcrt_stap = wget_malloc(sizeof(gnutls_pcert_st));
		ocsp_stap_resp = wget_malloc(sizeof(gnutls_ocsp_data_st));
		privkey_stap = wget_malloc(sizeof(gnutls_privkey_t));

		gnutls_privkey_init(privkey_stap);

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-key.pem", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/x509-server-key.pem", gnutls_strerror(rc));

		gnutls_privkey_import_x509_raw(*privkey_stap, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
		gnutls_free(data.data);

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-cert.pem", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/x509-server-cert.pem", gnutls_strerror(rc));

		gnutls_pcert_import_x509_raw(pcrt_stap, &data, GNUTLS_X509_FMT_PEM, 0);
		gnutls_free(data.data);

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/ocsp_stapled_resp.der", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/ocsp_stapled_resp.der", gnutls_strerror(rc));

		ocsp_stap_resp->response.data = data.data;
		ocsp_stap_resp->response.size = data.size;
		ocsp_stap_resp->exptime = 0;

		httpsdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
				| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
			,
			port_num, _check_to_accept, (void *) (ptrdiff_t) SERVER_MODE, &_answer_to_connection, NULL,
			MHD_OPTION_HTTPS_CERT_CALLBACK2, _ocsp_stap_cert_callback,
#ifdef MHD_OPTION_STRICT_FOR_CLIENT
				MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
			MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) 1*1024*1024,
			MHD_OPTION_END);
	}
#endif
#endif

	// get open random port number
	if (0) {}
#if MHD_VERSION >= 0x00095501
	else if (MHD_NO != MHD_is_feature_supported(MHD_FEATURE_AUTODETECT_BIND_PORT))
	{
		const union MHD_DaemonInfo *dinfo = NULL;
		if (SERVER_MODE == HTTP_MODE)
			dinfo = MHD_get_daemon_info(httpdaemon, MHD_DAEMON_INFO_BIND_PORT);
		else if (SERVER_MODE == HTTPS_MODE || SERVER_MODE == OCSP_STAP_MODE)
			dinfo = MHD_get_daemon_info(httpsdaemon, MHD_DAEMON_INFO_BIND_PORT);
#ifdef HAVE_GNUTLS_OCSP_H
		else if (SERVER_MODE == OCSP_MODE)
			dinfo = MHD_get_daemon_info(ocspdaemon, MHD_DAEMON_INFO_BIND_PORT);
#endif
#ifdef HAVE_MICROHTTPD_HTTP2_H
		else if (SERVER_MODE == H2_MODE)
			dinfo = MHD_get_daemon_info(h2daemon, MHD_DAEMON_INFO_BIND_PORT);
#endif

		if (!dinfo || dinfo->port == 0)
			return 1;

		port_num = dinfo->port;
		if (SERVER_MODE == HTTP_MODE)
			http_server_port = port_num;
		else if (SERVER_MODE == HTTPS_MODE || SERVER_MODE == OCSP_STAP_MODE)
			https_server_port = port_num;
#ifdef HAVE_GNUTLS_OCSP_H
		else if (SERVER_MODE == OCSP_MODE)
			ocsp_server_port = port_num;
#endif
#ifdef HAVE_MICROHTTPD_HTTP2_H
		else if (SERVER_MODE == H2_MODE) {
			h2_server_port = port_num;
		}
#endif
	}
#endif /* MHD_VERSION >= 0x00095501 */
	else
	{
		const union MHD_DaemonInfo *dinfo = NULL;
		int sock_fd;

		if (SERVER_MODE == HTTP_MODE)
			dinfo = MHD_get_daemon_info(httpdaemon, MHD_DAEMON_INFO_LISTEN_FD);
		else if (SERVER_MODE == HTTPS_MODE || SERVER_MODE == OCSP_STAP_MODE)
			dinfo = MHD_get_daemon_info(httpsdaemon, MHD_DAEMON_INFO_LISTEN_FD);
#ifdef HAVE_GNUTLS_OCSP_H
		else if (SERVER_MODE == OCSP_MODE)
			dinfo = MHD_get_daemon_info(ocspdaemon, MHD_DAEMON_INFO_LISTEN_FD);
#endif
#ifdef HAVE_MICROHTTPD_HTTP2_H
		else if (SERVER_MODE == H2_MODE)
			dinfo = MHD_get_daemon_info(h2daemon, MHD_DAEMON_INFO_LISTEN_FD);
#endif

		if (!dinfo)
			return 1;
#ifdef _WIN32
		sock_fd = _open_osfhandle(dinfo->listen_fd, O_RDWR | O_BINARY);
#else
		sock_fd = dinfo->listen_fd;
#endif

		struct sockaddr_storage addr_store;
		struct sockaddr *addr = (struct sockaddr *)&addr_store;
		socklen_t addr_len = sizeof(addr_store);

		// get automatic retrieved port number
		if (getsockname(sock_fd, addr, &addr_len) == 0) {
			char s_port[NI_MAXSERV];

			if (getnameinfo(addr, addr_len, NULL, 0, s_port, sizeof(s_port), NI_NUMERICSERV) == 0) {
				port_num = (uint16_t)atoi(s_port);
				if (SERVER_MODE == HTTP_MODE)
					http_server_port = port_num;
				else if (SERVER_MODE == HTTPS_MODE || SERVER_MODE == OCSP_STAP_MODE)
					https_server_port = port_num;
#ifdef HAVE_GNUTLS_OCSP_H
				else if (SERVER_MODE == OCSP_MODE)
					ocsp_server_port = port_num;
#endif

#ifdef HAVE_MICROHTTPD_HTTP2_H
				else if (SERVER_MODE == H2_MODE)
					h2_server_port = port_num;
#endif
			}
		}
	}

	return 0;
}

#if defined __CYGWIN__
// Using opendir/readdir loop plus unlink() has a race condition
// with CygWin. Not sure if this also happens on other systems as well.
// Since we don't have valgrind, we can use system() without issues.
static void _remove_directory(const char *dirname)
{
	char cmd[strlen(dirname) + 16];

	wget_snprintf(cmd, sizeof(cmd), "rm -rf %s", dirname);
	system(cmd);
}
static void _empty_directory(const char *dirname)
{
	_remove_directory(dirname);

	if (mkdir(dirname, 0755) != 0)
		wget_error_printf_exit(_("Failed to re-create directory (%d)\n"), errno);
}
#else
// To reduce the verbosity of 'valgrind --trace-children=yes' output,
//   we avoid system("rm -rf ...") calls.
static void _remove_directory(const char *dirname);
static void _empty_directory(const char *dirname)
{
	DIR *dir;
	size_t dirlen = strlen(dirname);

	if ((dir = opendir(dirname))) {
		struct dirent *dp;

		while ((dp = readdir(dir))) {
			if (*dp->d_name == '.' && (dp->d_name[1] == 0 || (dp->d_name[1] == '.' && dp->d_name[2] == 0)))
				continue;

			char fname[dirlen + 1 + strlen(dp->d_name) + 1];
			wget_snprintf(fname, sizeof(fname), "%s/%s", dirname, dp->d_name);

			if (unlink(fname) == -1) {
				// in case fname is a directory glibc returns EISDIR but correct POSIX value would be EPERM.
				// MinGW + Wine returns EACCESS here.
				if (errno == EISDIR || errno == EPERM || errno == EACCES)
					_remove_directory(fname);
				else
					wget_error_printf(_("Failed to unlink %s (%d)\n"), fname, errno);
			}
		}

		closedir(dir);

		wget_debug_printf("Removed test directory '%s'\n", dirname);
	} else if (errno != ENOENT)
		wget_error_printf(_("Failed to opendir %s (%d)\n"), dirname, errno);
}

static void _remove_directory(const char *dirname)
{
	_empty_directory(dirname);
	if (rmdir(dirname) == -1 && errno != ENOENT)
		wget_error_printf(_("Failed to rmdir %s (%d)\n"), dirname, errno);
}
#endif

void wget_test_stop_server(void)
{
//	wget_vector_free(&response_headers);
	wget_vector_free(&request_urls);

	for (wget_test_url_t *url = urls; url < urls + nurls; url++) {
		if (url->body_original) {
			wget_xfree(url->body);
			url->body_original = NULL;
		}

		for (size_t it = 0; it < countof(url->headers); it++) {
			if (url->headers_original[it]) {
				wget_xfree(url->headers[it]);
				url->headers_original[it] = NULL;
			}
		}
	}

	if (chdir("..") != 0)
		wget_error_printf(_("Failed to chdir ..\n"));

	if (!keep_tmpfiles)
		_remove_directory(tmpdir);

	wget_global_deinit();
	_http_server_stop();
}

static char *_insert_ports(const char *src)
{
	if (!src || (!strstr(src, "{{port}}") && !strstr(src, "{{sslport}}") && !strstr(src, "{{ocspport}}")))
		return NULL;

	size_t srclen = strlen(src) + 1;
	char *ret = wget_malloc(srclen);
	char *dst = ret;

	while (*src) {
		if (*src == '{') {
			if (!strncmp(src, "{{port}}", 8)) {
				if (proto_pass == HTTP_1_1_PASS) {
					dst += wget_snprintf(dst, srclen - (dst - ret), "%d", http_server_port);
				}
#ifdef HAVE_MICROHTTPD_HTTP2_H
				else {
					dst += wget_snprintf(dst, srclen - (dst - ret), "%d", reject_https_connection ? http_server_port : h2_server_port);
				}
#endif
				src += 8;
				continue;
			}
			else if (!strncmp(src, "{{sslport}}", 11)) {
				if (proto_pass == HTTP_1_1_PASS) {
					dst += wget_snprintf(dst, srclen - (dst - ret), "%d", https_server_port);
				}
#ifdef HAVE_MICROHTTPD_HTTP2_H
				else {
					dst += wget_snprintf(dst, srclen - (dst - ret), "%d", h2_server_port);
				}
#endif
				src += 11;
				continue;
			}
			else if (!strncmp(src, "{{ocspport}}", 12)) {
				dst += wget_snprintf(dst, srclen - (dst - ret), "%d", ocsp_server_port);
				src += 12;
				continue;
			}
		}

		*dst++ = *src++;
	}
	*dst = 0;

	return ret;
}

static void _write_msg(const char *msg, size_t len)
{
#ifdef _WIN32
	fwrite(msg, 1, len, stderr);
#else
	if (isatty(fileno(stderr))) {
		if (len && msg[len - 1] == '\n')
			len--;

		wget_fprintf(stderr, "\033[33m%.*s\033[m\n", (int) len, msg);
	} else
		fwrite(msg, 1, len, stderr);
#endif
}

void wget_test_start_server(int first_key, ...)
{
	int rc, key;
	va_list args;
	bool start_http = 1;
#ifdef WITH_TLS
	bool ocsp_stap = 0;
	bool start_https = 1;
#ifdef HAVE_GNUTLS_OCSP_H
	bool start_ocsp = 0;
#endif
#ifdef HAVE_MICROHTTPD_HTTP2_H
	bool start_h2 = 1;
#endif
#endif

	wget_global_init(
		WGET_DEBUG_FUNC, _write_msg,
		WGET_ERROR_FUNC, _write_msg,
		WGET_INFO_FUNC, _write_msg,
		0);

	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
/*		case WGET_TEST_RESPONSE_BODY:
			response_body = va_arg(args, const char *);
			break;
		case WGET_TEST_RESPONSE_HEADER:
			if (!response_headers)
				response_headers = wget_vector_create(4,4,NULL);
			wget_vector_add_str(response_headers, va_arg(args, const char *));
			break;
		case WGET_TEST_RESPONSE_CODE:
			response_code = va_arg(args, const char *);
			break;
*/		case WGET_TEST_RESPONSE_URLS:
			urls = va_arg(args, wget_test_url_t *);
			nurls = va_arg(args, size_t);
			break;
		case WGET_TEST_SERVER_SEND_CONTENT_LENGTH:
			server_send_content_length = !!va_arg(args, int);
			break;
		case WGET_TEST_HTTPS_ONLY:
			start_http = 0;
			break;
		case WGET_TEST_HTTP_ONLY:
#ifdef WITH_TLS
			start_https = 0;
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
#endif
			break;
		case WGET_TEST_H2_ONLY:
			start_http = 0;
#ifdef WITH_TLS
			start_https = 0;
#endif
			break;
		case WGET_TEST_HTTP_REJECT_CONNECTIONS:
			reject_http_connection = 1;
			break;
		case WGET_TEST_HTTPS_REJECT_CONNECTIONS:
			reject_https_connection = 1;
			break;
		case WGET_TEST_FEATURE_MHD:
			break;
		case WGET_TEST_FEATURE_TLS:
#if !defined WITH_TLS
			wget_error_printf(_("Test requires TLS. Skipping\n"));
			exit(WGET_TEST_EXIT_SKIP);
#endif
			break;
		case WGET_TEST_FEATURE_IDN:
#if !defined WITH_LIBIDN && !defined WITH_LIBIDN2
			wget_error_printf(_("Support for LibIDN not found. Skipping\n"));
			exit(WGET_TEST_EXIT_SKIP);
#endif
			break;
		case WGET_TEST_FEATURE_PLUGIN:
#ifndef PLUGIN_SUPPORT
			wget_error_printf(_("Plugin Support Disabled. Skipping\n"));
			exit(WGET_TEST_EXIT_SKIP);
#endif
			break;
		case WGET_TEST_FEATURE_OCSP:
#if !defined HAVE_GNUTLS_OCSP_H
			wget_error_printf(_("Test requires GnuTLS with OCSP support. Skipping\n"));
			exit(WGET_TEST_EXIT_SKIP);
#else
			start_http = 0;
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
			start_ocsp = 1;
#endif
			break;
		case WGET_TEST_FEATURE_OCSP_STAPLING:
#if !defined HAVE_GNUTLS_OCSP_H || MHD_VERSION < 0x00096502 || GNUTLS_VERSION_NUMBER < 0x030603
			wget_error_printf(_("MHD or GnuTLS version insufficient. Skipping\n"));
			exit(WGET_TEST_EXIT_SKIP);
#else
			start_http = 0;
			start_https = 0;
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
			ocsp_stap = 1;
			break;
#endif
		case WGET_TEST_SKIP_H2:
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
			break;
		default:
			wget_error_printf(_("Unknown option %d\n"), key);
		}
	}
	va_end(args);

	atexit(wget_test_stop_server);

	wget_snprintf(tmpdir, sizeof(tmpdir), ".test_%d", (int) getpid());

	// remove tmpdir if exists from previous tests
	_remove_directory(tmpdir);

	if (mkdir(tmpdir, 0755) != 0)
		wget_error_printf_exit(_("Failed to create tmpdir (%d)\n"), errno);

	if (chdir(tmpdir) != 0)
		wget_error_printf_exit(_("Failed to change to tmpdir (%d)\n"), errno);

	// start HTTP server
	if (start_http) {
		if ((rc = _http_server_start(HTTP_MODE)) != 0)
			wget_error_printf_exit(_("Failed to start HTTP server, error %d\n"), rc);
	}

#ifdef WITH_TLS
#ifdef HAVE_GNUTLS_OCSP_H
	// start OCSP responder
	if (start_ocsp) {
		if ((rc = _http_server_start(OCSP_MODE)) != 0)
			wget_error_printf_exit(_("Failed to start OCSP server, error %d\n"), rc);
	}

	// start OCSP server (stapling)
	if (ocsp_stap) {
		if ((rc = _http_server_start(OCSP_STAP_MODE)) != 0)
			wget_error_printf_exit(_("Failed to start OCSP Stapling server, error %d\n"), rc);
	}
#endif

	// start HTTPS server
	if (start_https) {
		if ((rc = _http_server_start(HTTPS_MODE)) != 0)
			wget_error_printf_exit(_("Failed to start HTTPS server, error %d\n"), rc);
	}

#ifdef HAVE_MICROHTTPD_HTTP2_H
	// start h2 server
	if (start_h2) {
		if ((rc = _http_server_start(H2_MODE)) != 0)
			wget_error_printf_exit(_("Failed to start h2 server, error %d\n"), rc);
	}
#endif
#endif
}

static void _scan_for_unexpected(const char *dirname, const wget_test_file_t *expected_files)
{
	DIR *dir;
	struct stat st;
	size_t dirlen = strlen(dirname);

	wget_info_printf("Entering %s\n", dirname);

	if ((dir = opendir(dirname))) {
		struct dirent *dp;

		while ((dp = readdir(dir))) {
			char fname[dirlen + 1 + strlen(dp->d_name) + 1];

			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
				continue;

			if (*dirname == '.' && dirname[1] == 0)
				wget_snprintf(fname, sizeof(fname), "%s", dp->d_name);
			else
				wget_snprintf(fname, sizeof(fname), "%s/%s", dirname, dp->d_name);

			wget_info_printf(" - %s/%s\n", dirname, dp->d_name);
			if (stat(fname, &st) == 0 && S_ISDIR(st.st_mode)) {
				_scan_for_unexpected(fname, expected_files);
				continue;
			}

			if (expected_files) {
// Mac OS X converts to NFD, so we might find an unexpected file name, e.g. when using accents.
// Example: cedilla (%C3%A7) will be converted to c+composed_cedilla (%63%CC%A7)
// Since there are a few pitfalls with Apple's NFD, just skip the check here.
#if !(defined __APPLE__ && defined __MACH__)
				size_t it;

				wget_info_printf(_("search %s\n"), fname);

				for (it = 0; expected_files[it].name; it++) {
#ifdef _WIN32
					char buf[strlen(expected_files[it].name) * 3 + 1];
					const char *restricted_fname = wget_restrict_file_name(expected_files[it].name, buf,
						expected_files[it].restricted_mode ? expected_files[it].restricted_mode : WGET_RESTRICT_NAMES_WINDOWS);
#else
					const char *restricted_fname = expected_files[it].name;
#endif
/*
					{
						char b[256];
						if (it==0) {
							wget_memtohex(fname, strlen(fname), b, sizeof(b));
							wget_debug_printf("f %s\n", b);
						}
						wget_memtohex(restricted_fname, strlen(restricted_fname), b, sizeof(b));
						wget_debug_printf("r %s\n", b);
					}
*/
					if (!strcmp(restricted_fname, fname))
						break;
				}

				if (!expected_files[it].name)
					wget_error_printf_exit(_("Unexpected file %s/%s found\n"), tmpdir, fname);
#endif
			} else
				wget_error_printf_exit(_("Unexpected file %s/%s found\n"), tmpdir, fname);
		}

		closedir(dir);
	} else
		wget_error_printf_exit(_("Failed to diropen %s\n"), dirname);
}

void wget_test(int first_key, ...)
{
#if !defined WITH_LIBNGHTTP2 || !defined HAVE_MICROHTTPD_HTTP2_H
	if (!httpdaemon && !httpsdaemon)
		exit(WGET_TEST_EXIT_SKIP);
#endif

	for (proto_pass = 0; proto_pass < END_PASS; proto_pass++) {
		if (proto_pass == HTTP_1_1_PASS && !httpdaemon && !httpsdaemon)
			continue;

		if (proto_pass == H2_PASS) {
#ifndef WITH_LIBNGHTTP2
			continue;
#endif
			if (!h2daemon)
				continue;
		}

		// now replace {{port}} in the body by the actual server port
		for (wget_test_url_t *url = urls; url < urls + nurls; url++) {
			char *p = _insert_ports(url->body);

			if (p) {
				url->body_original = url->body;
				url->body = p;
			}

			for (unsigned it = 0; it < countof(url->headers) && url->headers[it]; it++) {
				p = _insert_ports(url->headers[it]);

				if (p) {
					url->headers_original[it] = url->headers[it];
					url->headers[it] = p;
				}
			}
		}

		const char
			*request_url,
			*options = "",
#ifdef HAVE_GNUTLS_OCSP_H
			*ocsp_resp_file = NULL,
#endif
			*executable;
		const wget_test_file_t
			*expected_files = NULL,
			*existing_files = NULL;
		wget_buffer
			*cmd = wget_buffer_alloc(1024);
		unsigned
			it;
		int
			key,
			fd,
			rc,
			expected_error_code2 = -1,
			expected_error_code = 0;
		va_list
			args;
		char
			server_send_content_length_old = server_send_content_length;
		bool
			options_alloc = 0;

#ifdef _WIN32
		if (proto_pass == H2_PASS)
			executable = BUILDDIR "\\..\\src\\wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 10 --https-enforce=hard --ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp";
		else
			executable = BUILDDIR "\\..\\src\\wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 10";
#else
		if (proto_pass == H2_PASS)
			executable = BUILDDIR "/../src/wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 10 --https-enforce=hard --ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp";
		else
			executable = BUILDDIR "/../src/wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 10";
#endif

		keep_tmpfiles = 0;

		if (!request_urls) {
			request_urls = wget_vector_create(8, NULL);
			wget_vector_set_destructor(request_urls, NULL);
		}

		va_start (args, first_key);
		for (key = first_key; key; key = va_arg(args, int)) {
			switch (key) {
			case WGET_TEST_REQUEST_URL:
				if ((request_url = va_arg(args, const char *)))
					wget_vector_add(request_urls, request_url);
				break;
			case WGET_TEST_REQUEST_URLS:
				while ((request_url = va_arg(args, const char *)))
					wget_vector_add(request_urls, request_url);
				break;
			case WGET_TEST_EXPECTED_ERROR_CODE:
				expected_error_code = va_arg(args, int);
				break;
			case WGET_TEST_EXPECTED_ERROR_CODE2:
				expected_error_code2 = va_arg(args, int);
				break;
			case WGET_TEST_EXPECTED_FILES:
				expected_files = va_arg(args, const wget_test_file_t *);
				break;
			case WGET_TEST_EXISTING_FILES:
				existing_files = va_arg(args, const wget_test_file_t *);
				break;
			case WGET_TEST_OPTIONS:
			{
				options = va_arg(args, const char *);
				const char *tmp = _insert_ports(options);
				if (tmp) {
					options = tmp;
					options_alloc = 1;
				}
				break;
			}
			case WGET_TEST_KEEP_TMPFILES:
				keep_tmpfiles = va_arg(args, int);
				break;
			case WGET_TEST_EXECUTABLE:
				executable = va_arg(args, const char *);
				break;
			case WGET_TEST_SERVER_SEND_CONTENT_LENGTH:
				server_send_content_length = !!va_arg(args, int);
				break;
			case WGET_TEST_POST_HANDSHAKE_AUTH:
				if (va_arg(args, int)) {
#if MHD_VERSION >= 0x00096302 && GNUTLS_VERSION_NUMBER >= 0x030603
					post_handshake_auth = wget_malloc(sizeof(enum CHECK_POST_HANDSHAKE_AUTH));
#endif
				}
				break;
			case WGET_TEST_OCSP_RESP_FILE:
#ifdef HAVE_GNUTLS_OCSP_H
				ocsp_resp_file = va_arg(args, const char *);
#endif
				break;
			default:
				wget_error_printf_exit(_("Unknown option %d [%s]\n"), key, options);
			}
		}
		va_end(args);

		// clean directory
		wget_buffer_printf(cmd, "../%s", tmpdir);
		_empty_directory(cmd->data);

#ifdef HAVE_GNUTLS_OCSP_H
		if (ocspdaemon) {
			if (ocsp_resp_file) {
				ocsp_resp->data = wget_read_file(ocsp_resp_file, &(ocsp_resp->size));
				if (ocsp_resp->data == NULL) {
					wget_error_printf_exit(_("Couldn't read the response.\n"));
				}
			} else {
				wget_error_printf_exit(_("Need value for option WGET_TEST_OCSP_RESP_FILE.\n"));
			}
		}
#endif

		// create files
		if (existing_files) {
			for (it = 0; existing_files[it].name; it++) {
				mkdir_path(existing_files[it].name, 1);

				if (existing_files[it].hardlink) {
					if (link(existing_files[it].hardlink, existing_files[it].name) != 0) {
						wget_error_printf_exit(_("Failed to link %s/%s -> %s/%s [%s]\n"),
							tmpdir, existing_files[it].hardlink,
							tmpdir, existing_files[it].name, options);
					}
				}
				else if ((fd = open(existing_files[it].name, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY, 0644)) != -1) {
					const char *existing_content = _insert_ports(existing_files[it].content);
					if (!existing_content)
						existing_content = existing_files[it].content;

					ssize_t nbytes = write(fd, existing_content, strlen(existing_content));
					close(fd);

					if (nbytes != (ssize_t)strlen(existing_content))
						wget_error_printf_exit(_("Failed to write %zu bytes to file %s/%s [%s]\n"),
							strlen(existing_content), tmpdir, existing_files[it].name, options);

					if (existing_files[it].timestamp) {
						// take the old utime() instead of utimes()
						if (utime(existing_files[it].name, &(struct utimbuf){ 0, existing_files[it].timestamp }))
							wget_error_printf_exit(_("Failed to set mtime of %s/%s [%s]\n"),
								tmpdir, existing_files[it].name, options);
					}

					if (existing_content != existing_files[it].content)
						wget_xfree(existing_content);

				} else {
					wget_error_printf_exit(_("Failed to write open file %s/%s [%s] (%d,%s)\n"),
						tmpdir, *existing_files[it].name == '/' ? existing_files[it].name + 1 : existing_files[it].name , options,
						errno, strerror(errno));
				}
			}
		}

		const char *valgrind = getenv("VALGRIND_TESTS");
		if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
			// On some system we get random IP order (v4, v6) for localhost, so we need --prefer-family for testing since
			// the test servers will listen only on the first IP and also prefers IPv4
			const char *emulator = getenv("EMULATOR");
			if (emulator && *emulator)
				wget_buffer_printf(cmd, "%s %s %s", emulator, executable, options);
			else
				wget_buffer_printf(cmd, "%s %s", executable, options);
		} else if (!strcmp(valgrind, "1")) {
			wget_buffer_printf(cmd, "valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes --child-silent-after-fork=yes --suppressions=" SRCDIR "/valgrind-suppressions %s %s", executable, options);
		} else
			wget_buffer_printf(cmd, "%s %s %s", valgrind, executable, options);

		for (it = 0; it < (size_t)wget_vector_size(request_urls); it++) {
			request_url = wget_vector_get(request_urls, it);

			if (!wget_strncasecmp_ascii(request_url, "http://", 7)
				|| !wget_strncasecmp_ascii(request_url, "https://", 8))
			{
				char *tmp = _insert_ports(request_url);
				wget_buffer_printf_append(cmd, " \"%s\"", tmp ? tmp : request_url);
				wget_xfree(tmp);
			} else {
				if (proto_pass == HTTP_1_1_PASS) {
					wget_buffer_printf_append(cmd, " \"http://localhost:%d/%s\"",
					http_server_port, request_url);
				}
#ifdef HAVE_MICROHTTPD_HTTP2_H
				else {
					wget_buffer_printf_append(cmd, " \"https://localhost:%d/%s\"",
					h2_server_port, request_url);
				}
#endif
			}
		}

		wget_buffer_strcat(cmd, " 2>&1");

		wget_info_printf("cmd=%s\n", cmd->data);
		wget_error_printf(_("\n  Testing '%s'\n"), cmd->data);

		// catch stdout and write to stderr so all output is in sync
		FILE *pp;
		if ((pp = popen(cmd->data, "r"))) {
			char buf[4096];

			while (fgets(buf, sizeof(buf), pp)) {
				fputs(buf, stderr);
				fflush(stderr);
			}

			rc = pclose(pp);
		} else
			wget_error_printf_exit(_("Failed to execute test (%d) [%s]\n"), errno, options);
		/*
			rc = system(cmd->data);
		*/
		if (!WIFEXITED(rc)) {
			wget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"), rc, expected_error_code, options);
		}
		else if (WEXITSTATUS(rc) != expected_error_code) {
			if (expected_error_code2 >= 0) {
				if (WEXITSTATUS(rc) != expected_error_code2)
					wget_error_printf_exit(_("Unexpected error code %d, expected %d or %d [%s]\n"),
						WEXITSTATUS(rc), expected_error_code, expected_error_code2, options);
			}
			else
				wget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"),
					WEXITSTATUS(rc), expected_error_code, options);
		}

		if (expected_files) {
			for (it = 0; expected_files[it].name; it++) {
				struct stat st;
#ifdef _WIN32
				char buf[strlen(expected_files[it].name) * 3 + 1];
				const char *fname = wget_restrict_file_name(expected_files[it].name, buf,
					expected_files[it].restricted_mode ? expected_files[it].restricted_mode : WGET_RESTRICT_NAMES_WINDOWS);
#else
				const char *fname = expected_files[it].name;
#endif

				if (stat(fname, &st) != 0)
					wget_error_printf_exit(_("Missing expected file '%s/%s' [%s]\n"), tmpdir, fname, options);

				if (expected_files[it].content) {
					char *content = wget_malloc(st.st_size ? st.st_size : 1);

					if ((fd = open(fname, O_RDONLY | O_BINARY)) != -1) {
						ssize_t nbytes = read(fd, content, st.st_size);
						close(fd);

						if (nbytes != st.st_size)
							wget_error_printf_exit(_("Failed to read %lld bytes from file '%s/%s', just got %zd [%s]\n"),
								(long long)st.st_size, tmpdir, fname, nbytes, options);

						const char *expected_content = _insert_ports(expected_files[it].content);
						bool expected_content_alloc = 0;
						if (!expected_content)
							expected_content = expected_files[it].content;
						else
							expected_content_alloc = 1;

						size_t content_length = expected_files[it].content_length ? expected_files[it].content_length : strlen(expected_content);

						if (content_length != (size_t) nbytes || memcmp(expected_content, content, nbytes) != 0)
							wget_error_printf_exit(_("Unexpected content in %s [%s]\n"), fname, options);

						if (expected_content_alloc)
							wget_xfree(expected_content);
					}

					wget_xfree(content);
				}

				if (expected_files[it].timestamp && st.st_mtime != expected_files[it].timestamp)
					wget_error_printf_exit(_("Unexpected timestamp '%s/%s' [%s]\n"), tmpdir, fname, options);
			}
		}

		// look if there are unexpected files in our working dir
		_scan_for_unexpected(".", expected_files);

#if MHD_VERSION >= 0x00096302 && GNUTLS_VERSION_NUMBER >= 0x030603
		if (post_handshake_auth && *post_handshake_auth == CHECK_FAILED) {
			wget_free(post_handshake_auth);
			wget_error_printf_exit(_("Post-handshake authentication failed\n"));
		} else if (post_handshake_auth)
			wget_free(post_handshake_auth);
#endif

		wget_vector_clear(request_urls);
		wget_buffer_free(&cmd);

		if (options_alloc)
			wget_xfree(options);

		server_send_content_length = server_send_content_length_old;

		// system("ls -la");

		// cleanup for next iteration
		for (wget_test_url_t *url = urls; url < urls + nurls; url++) {
			if (url->body_original) {
				wget_xfree(url->body);
				url->body = url->body_original;
				url->body_original = NULL;
			}

			for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
				if (url->headers_original[it]) {
					wget_xfree(url->headers[it]);
					url->headers[it] = url->headers_original[it];
					url->headers_original[it] = NULL;
				}
			}
		}
	}
}

int wget_test_get_http_server_port(void)
{
	return proto_pass == H2_PASS ? h2_server_port : http_server_port;
}

int wget_test_get_https_server_port(void)
{
	return proto_pass == H2_PASS ? h2_server_port : https_server_port;
}

int wget_test_get_h2_server_port(void)
{
#ifndef HAVE_MICROHTTPD_HTTP2_H
	return -1;
#else
	return h2_server_port;
#endif
}

int wget_test_get_ocsp_server_port(void)
{
	return ocsp_server_port;
}

// assume that we are in 'tmpdir'
int wget_test_check_file_system(void)
{
	static char fname[3][3] = { "Ab", "ab", "AB" };
	char buf[sizeof(fname[0])];
	int flags = 0, fd;
	ssize_t rc;

	_empty_directory(tmpdir);

	// Create 3 files with differently cased names with different content.
	// On a case-mangling file system like HFS+ there will be just one file with the contents of the last write.
	for (unsigned it = 0; it < countof(fname); it++) {
		if ((fd = open(fname[it], O_WRONLY | O_TRUNC | O_CREAT | O_BINARY, 0644)) != -1) {
			rc = write(fd, fname[it], sizeof(fname[0]));
			close(fd);

			if (rc != sizeof(fname[0])) {
				wget_debug_printf("%s: Failed to write to '%s/%s' (%d) %zd %zu\n", __func__, tmpdir, fname[it], errno, rc, sizeof(fname[0]));
				goto out;
			}
		} else {
			wget_debug_printf("%s: Failed to write open '%s/%s'\n", __func__, tmpdir, fname[it]);
			goto out;
		}
	}

	// Check file content to see if FS is case-mangling
	for (unsigned it = 0; it < countof(fname); it++) {
		if ((fd = open(fname[it], O_RDONLY | O_BINARY, 0644)) != -1) {
			rc = read(fd, buf, sizeof(fname[0]));
			close(fd);

			if (rc != sizeof(fname[0])) {
				wget_debug_printf("%s: Failed to read from '%s/%s'\n", __func__, tmpdir, fname[it]);
				goto out;
			}

			if (strcmp(buf, fname[it])) {
				wget_debug_printf("%s: Found case-mangling file system\n", __func__);
				flags = WGET_TEST_FS_CASEMATTERS;
				goto out; // we can stop here
			}
		} else {
			wget_debug_printf("%s: Failed to read open '%s/%s'\n", __func__, tmpdir, fname[it]);
			goto out;
		}
	}

	wget_debug_printf("%s: Found case-respecting file system\n", __func__);

out:
	_empty_directory(tmpdir);

	return flags;
}
