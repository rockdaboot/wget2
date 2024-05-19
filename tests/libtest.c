/*
 * Copyright (c) 2013-2014 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget
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
 * along with Wget  If not, see <https://www.gnu.org/licenses/>.
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
#if MHD_VERSION <= 0x00097000
#undef MHD_NO
#undef MHD_YES
enum MHD_Result {
	MHD_NO = 0,
	MHD_YES = 1
};
#endif

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef WITH_GNUTLS_IN_TESTSUITE
#ifdef WITH_GNUTLS_OCSP
#  include <gnutls/ocsp.h>
#  include <gnutls/x509.h>
#  include <gnutls/abstract.h>
#endif

#  include <gnutls/gnutls.h>
#  define file_load_err(fname, msg) wget_error_printf_exit("Couldn't load '%s' : %s\n", fname, msg)
#endif

static int
	http_server_port,
	https_server_port,
	ocsp_server_port,
	h2_server_port,
	keep_tmpfiles,
	clean_directory,
	reject_http_connection,
	reject_https_connection,
	ocsp_response_pos;
static wget_vector
	*request_urls,
	*ocsp_responses;
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

#ifdef WITH_GNUTLS_OCSP
static gnutls_pcert_st *pcrt;
static gnutls_privkey_t *privkey;

typedef struct {
	char
		*data;
	size_t
		size;
} ocsp_resp_t;
#endif

#ifdef WITH_GNUTLS_OCSP
#if MHD_VERSION >= 0x00096502 && GNUTLS_VERSION_NUMBER >= 0x030603
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

static const char *_parse_hostname(const char* data)
{
	if (data) {
		if (!wget_strncasecmp_ascii(data, "http://", 7)) {
			return strchr(data + 7, '/');
		}
		if (!wget_strncasecmp_ascii(data, "https://", 8)) {
			return strchr(data + 8, '/');
		}
	}

	return data;
}

static void _replace_space_with_plus(wget_buffer *buf, const char *data)
{
	for (; *data; data++)
		wget_buffer_memcat(buf, *data == ' ' ? "+" : data, 1);
}

static enum MHD_Result _print_query_string(
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

static enum MHD_Result _print_header_range(
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
	interrupt_response_mode_t interrupt_response_mode;
	size_t interrupt_response_after_nbytes;
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

	memcpy(buf, param->response_data + pos, size_to_copy);

	return size_to_copy;
}

static ssize_t _callback_interruptable (void *cls, uint64_t pos, char *buf, size_t buf_size)
{
	size_t size_to_copy;
	struct ResponseContentCallbackParam *const param =
		(struct ResponseContentCallbackParam *)cls;

	if (pos >= param->response_size)
		return MHD_CONTENT_READER_END_OF_STREAM;

	if (buf_size <= (param->response_size - pos)) {
		size_to_copy = buf_size;
	} else {
		size_to_copy = param->response_size - pos;
	}

	if (param->interrupt_response_mode != INTERRUPT_RESPONSE_DISABLED) {
		if (pos >= param->interrupt_response_after_nbytes) {
			return MHD_CONTENT_READER_END_WITH_ERROR;
		}

		if (size_to_copy > (param->interrupt_response_after_nbytes - pos)) {
			size_to_copy = param->interrupt_response_after_nbytes - pos;
		}
	}

	memcpy(buf, param->response_data + pos, size_to_copy);
	return size_to_copy;
}

static void _free_callback_param(void *cls)
{
	wget_free(cls);
}

#ifdef WITH_GNUTLS_OCSP
static enum MHD_Result _ocsp_ahc(
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

		ocsp_resp_t *ocsp_resp = wget_vector_get(ocsp_responses, ocsp_response_pos++);

		if (ocsp_resp) {
			struct MHD_Response *response = MHD_create_response_from_buffer (ocsp_resp->size, ocsp_resp->data, MHD_RESPMEM_MUST_COPY);

			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);

			MHD_destroy_response (response);
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
static int _ocsp_stap_cert_callback(
	gnutls_session_t session WGET_GCC_UNUSED,
	const struct gnutls_cert_retr_st *info WGET_GCC_UNUSED,
	gnutls_pcert_st **certs,
	unsigned int *pcert_length,
	gnutls_ocsp_data_st **ocsp,
	unsigned int *ocsp_length,
	gnutls_privkey_t *pkey,
	unsigned int *flags WGET_GCC_UNUSED)
{
	*certs = pcrt;
	*(certs+1) = pcrt+1;
	*pcert_length = 2;

	*pkey = *privkey;

	*ocsp = ocsp_stap_resp;
	*ocsp_length = 1;

	return 0;
}
#endif
#endif

static enum MHD_Result _answer_to_connection(
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
	if (post_handshake_auth) {
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
	int64_t modified;
	const char *modified_val, *to_bytes_string = "";
	ssize_t from_bytes, to_bytes;
	char content_len[100], content_range[100];

	// whether or not this connection is HTTPS
	bool https = !!MHD_get_connection_info(connection, MHD_CONNECTION_INFO_PROTOCOL);

	// get query string
	query.params = wget_buffer_alloc(1024);
	query.it = 0;
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, _print_query_string, &query);

	// get if-modified-since header
	modified_val = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
												MHD_HTTP_HEADER_IF_MODIFIED_SINCE);
	modified = 0;
	if (modified_val)
		modified = wget_http_parse_full_date(modified_val);

	// get header range
	wget_buffer *header_range = wget_buffer_alloc(1024);
	if (!strcmp(method, "GET"))
		MHD_get_connection_values(connection, MHD_HEADER_KIND, _print_header_range, header_range);

	from_bytes = to_bytes = 0;
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

	// append 'index.html' to directory and append query string
	const char *url_full, *p;
	if ((p = strrchr(url, '/')) && p[1] == 0) {
		url_full = wget_aprintf("%sindex.html%s", url, query.params->data ? query.params->data : "");
	} else {
		url_full = wget_aprintf("%s%s", url, query.params->data ? query.params->data : "");
	}
	wget_buffer_free(&query.params);

	// iterate over test urls array
	bool found = false, chunked = false;
	char *url_iri = NULL;

	for (wget_test_url_t *request_url = urls; request_url < urls + nurls; request_url++) {
		if (request_url->http_only && https)
			continue;
		if (request_url->https_only && !https)
			continue;

		// convert remote url into escaped char for iri encoding
		wget_xfree(url_iri);
		url_iri = wget_strdup(request_url->name);
		MHD_http_unescape(url_iri);

		if (!strcmp(_parse_hostname(url_full), _parse_hostname(url_iri))) {
			size_t body_length =
				request_url->body_len ? request_url->body_len
				: (request_url->body ? strlen(request_url->body) : 0);

			// check request headers
			bool bad_request = false;

			if (request_url->expected_method && strcmp(method, request_url->expected_method)) {
				wget_debug_printf("%s: Expected request method '%s', but got '%s'\n",
					__func__, request_url->expected_method, method);
				bad_request = true;
			}

			for (const char **header = request_url->expected_req_headers; *header; header++) {
				const char *header_value = strchr(*header, ':');
				const char *header_key = wget_strmemdup(*header, header_value - *header);
				const char *got_val = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, header_key);
				wget_xfree(header_key);

				// 400 Bad Request
				if (!got_val || strcmp(got_val, header_value + 2)) {
					wget_debug_printf("%s: Missing expected header '%s'\n", __func__, *header);
					bad_request = true;
					break;
				}
			}

			// check unexpected headers
			for (const char **header_key = request_url->unexpected_req_headers; *header_key; header_key++) {
				const char *got_val = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, *header_key);

				// 400 Bad Request
				if (got_val) {
					wget_debug_printf("%s: Got unexpected header '%s'\n", __func__, *header_key);
					bad_request = true;
					break;
				}
			}

			// return with "400 Bad Request"
			if (bad_request) {
				response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
				ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
				found = true;
				break;
			}

			// chunked encoding
			if (!wget_strcmp(request_url->name + 3, "bad.txt")) {
				response = MHD_create_response_from_buffer(body_length,
					(void *) request_url->body, MHD_RESPMEM_MUST_COPY);
				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
				MHD_add_response_header(response, "Transfer-Encoding", "chunked");
				MHD_add_response_header(response, "Connection", "close");
				found = true;
				break;
			}
			for (const char **header = request_url->headers; *header; header++) {
				const char *header_value = strchr(*header, ':');
				const char *header_key = wget_strmemdup(*header, header_value - *header);
				if (!strcmp(header_key, "Transfer-Encoding") && !strcmp(header_value + 2, "chunked"))
					chunked = true;
				wget_xfree(header_key);
			}
			if (chunked) {
				struct ResponseContentCallbackParam *callback_param = wget_malloc(sizeof(struct ResponseContentCallbackParam));

				callback_param->response_data = request_url->body;
				callback_param->response_size = body_length;

				response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
					1024, _callback, callback_param, _free_callback_param);
				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
				found = true;
				break;
			}

			// redirection
			if (atoi(request_url->code)/100 == 3) {
				response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);

				// add available headers
				for (const char **header = request_url->headers; *header; header++) {
					const char *header_value = strchr(*header, ':');
					const char *header_key = wget_strmemdup(*header, header_value - *header);
					MHD_add_response_header(response, header_key, header_value + 2);
					wget_xfree(header_key);
				}
				ret = MHD_queue_response(connection, atoi(request_url->code), response);
				found = true;
				break;
			}

			// 404 with non-empty "body"
			if (atoi(request_url->code) != 200) {
				response = MHD_create_response_from_buffer(body_length,
					(void *) request_url->body, MHD_RESPMEM_MUST_COPY);
				ret = MHD_queue_response(connection, atoi(request_url->code), response);
				found = true;
				break;
			}

			// basic authentication
			if (!wget_strcmp(request_url->auth_method, "Basic")) {
				char *pass = NULL;
				char *user = MHD_basic_auth_get_username_password(connection, &pass);
				if ((user == NULL && pass == NULL) ||
					wget_strcmp(user, request_url->auth_username) ||
					wget_strcmp(pass, request_url->auth_password))
				{
					response = MHD_create_response_from_buffer(strlen ("DENIED"),
						(void *) "DENIED", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_basic_auth_fail_response(connection, "basic@example.com", response);
					MHD_free(user);
					MHD_free(pass);
					found = true;
					break;
				}
				MHD_free(user);
				MHD_free(pass);
			}

			// digest authentication
			if (!wget_strcmp(request_url->auth_method, "Digest")) {
				const char *realm = "digest@example.com";
				char *user = MHD_digest_auth_get_username(connection);
				if (wget_strcmp(user, request_url->auth_username)) {
					response = MHD_create_response_from_buffer(strlen ("DENIED"),
						(void *) "DENIED", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_auth_fail_response(connection, realm, TEST_OPAQUE_STR, response, MHD_NO);
					MHD_free(user);
					found = true;
					break;
				}
				ret = MHD_digest_auth_check(connection, realm, user, request_url->auth_password, 300);
				MHD_free(user);
				if ((ret == MHD_INVALID_NONCE) || (ret == MHD_NO)) {
					response = MHD_create_response_from_buffer(strlen ("DENIED"),
						(void *) "DENIED", MHD_RESPMEM_PERSISTENT);

					if (response) {
						ret = MHD_queue_auth_fail_response(connection, realm, TEST_OPAQUE_STR, response,
							(ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);
						found = true;
					} else
						ret = MHD_NO;

					break;
				}
			}

			if (modified && request_url->modified <= modified) {
				response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
				ret = MHD_queue_response(connection, MHD_HTTP_NOT_MODIFIED, response);
			}
			else if (*header_range->data) {
				if (!strcmp(to_bytes_string, "-"))
					to_bytes = body_length - 1;

				size_t body_len = to_bytes - from_bytes + 1;

				if (from_bytes > to_bytes || from_bytes >= (int) body_length) {
					response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_response(connection, MHD_HTTP_RANGE_NOT_SATISFIABLE, response);
				} else {
					if (request_url->interrupt_response_mode != INTERRUPT_RESPONSE_DISABLED) {
						struct ResponseContentCallbackParam *callback_param = wget_malloc(sizeof(struct ResponseContentCallbackParam));
						callback_param->response_data = (void *) (request_url->body + from_bytes);
						callback_param->response_size = body_len;
						callback_param->interrupt_response_mode = request_url->interrupt_response_mode;
						callback_param->interrupt_response_after_nbytes = request_url->interrupt_response_after_nbytes;

						response = MHD_create_response_from_callback(body_len,
								1024, _callback_interruptable, callback_param, _free_callback_param);
					} else {
						response = MHD_create_response_from_buffer(body_len,
							(void *) (request_url->body + from_bytes), MHD_RESPMEM_MUST_COPY);
					}
					MHD_add_response_header(response, MHD_HTTP_HEADER_ACCEPT_RANGES, "bytes");
					wget_snprintf(content_range, sizeof(content_range), "%zd-%zd/%zu", from_bytes, to_bytes, body_len);
					MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_RANGE, content_range);
					wget_snprintf(content_len, sizeof(content_len), "%zu", body_len);
					MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_LENGTH, content_len);
					ret = MHD_queue_response(connection, MHD_HTTP_PARTIAL_CONTENT, response);
				}
			} else {
				if (request_url->interrupt_response_mode != INTERRUPT_RESPONSE_DISABLED) {
					struct ResponseContentCallbackParam *callback_param = wget_malloc(sizeof(struct ResponseContentCallbackParam));
					callback_param->response_data = request_url->body;
					callback_param->response_size = body_length;
					callback_param->interrupt_response_mode = request_url->interrupt_response_mode;
					callback_param->interrupt_response_after_nbytes = request_url->interrupt_response_after_nbytes;

					response = MHD_create_response_from_callback(body_length,
							1024, _callback_interruptable, callback_param, _free_callback_param);
				} else {
					response = MHD_create_response_from_buffer(body_length, (void *) request_url->body, MHD_RESPMEM_MUST_COPY);
				}

				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
			}

	// switch off Content-Length sanity checks
#if MHD_VERSION >= 0x00096800
			MHD_set_response_options(response,
				MHD_RF_INSANITY_HEADER_CONTENT_LENGTH,
				MHD_RO_END);
#endif

			// add available headers
			for (const char **header = request_url->headers; *header; header++) {
				const char *header_value = strchr(*header, ':');
				const char *header_key = wget_strmemdup(*header, header_value - *header);
				MHD_add_response_header(response, header_key, header_value + 2);
				wget_xfree(header_key);
			}

			found = true;
		}
	}

	// 404 with empty "body"
	if (!found) {
		response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
	}

	wget_xfree(url_iri);
	wget_xfree(url_full);
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

#ifdef WITH_GNUTLS_OCSP
	gnutls_global_deinit();
#endif
}

static enum MHD_Result _check_to_accept(
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
			port_num, _check_to_accept,
			(void *) (ptrdiff_t) SERVER_MODE, _answer_to_connection, NULL,
			MHD_OPTION_DIGEST_AUTH_RANDOM, sizeof(rnd), rnd,
			MHD_OPTION_NONCE_NC_SIZE, 300,
#if MHD_VERSION >= 0x00095400
			MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
#if MHD_VERSION >= 0x00096800
			MHD_OPTION_SERVER_INSANITY, 1,
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
				wget_error_printf("The key/certificate files could not be read.\n");
				return 1;
			}

			if (SERVER_MODE == HTTPS_MODE) {
				httpsdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
#if MHD_VERSION >= 0x00096302
						| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
#endif
					,
					port_num, _check_to_accept,
					(void *) (ptrdiff_t) SERVER_MODE, _answer_to_connection, NULL,
					MHD_OPTION_HTTPS_MEM_KEY, key_pem,
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
#if MHD_VERSION >= 0x00095400
					MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
#if MHD_VERSION >= 0x00096800
			MHD_OPTION_SERVER_INSANITY, 1,
#endif
				MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) 1*1024*1024,
				MHD_OPTION_END);

				if (!httpsdaemon) {
					wget_error_printf("Cannot start the HTTPS server.\n");
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
					port_num, (MHD_AcceptPolicyCallback)_check_to_accept,
					(void *) (ptrdiff_t) SERVER_MODE, (MHD_AccessHandlerCallback)_answer_to_connection, NULL,
					MHD_OPTION_HTTPS_MEM_KEY, key_pem,
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
#if MHD_VERSION >= 0x00095400
					MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
#if MHD_VERSION >= 0x00096800
			MHD_OPTION_SERVER_INSANITY, 1,
#endif
					//Enough to send 1MB files through
					MHD_OPTION_CONNECTION_MEMORY_LIMIT, 1*1024*1024,
					MHD_OPTION_END);
#endif

				if (!h2daemon) {
					wget_error_printf("Cannot start the h2 server.\n");
					wget_error_printf("HTTP/2 support for MHD not found.\n");
					return 1;
				}
			}
		}
#ifdef WITH_GNUTLS_OCSP
		else {
			httpsdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
#if MHD_VERSION >= 0x00096302
					| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
#endif
				,
				port_num, _check_to_accept,
				(void *) (ptrdiff_t) SERVER_MODE, _answer_to_connection, NULL,
				MHD_OPTION_HTTPS_CERT_CALLBACK, _ocsp_cert_callback,
#if MHD_VERSION >= 0x00095400
				MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
#if MHD_VERSION >= 0x00096800
			MHD_OPTION_SERVER_INSANITY, 1,
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
			wget_xfree(data.data);

			pcrt = wget_malloc(sizeof(gnutls_pcert_st)*2);

			if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-cert.pem", &data)) < 0)
				file_load_err(SRCDIR "/certs/ocsp/x509-server-cert.pem", gnutls_strerror(rc));

			gnutls_pcert_import_x509_raw(pcrt, &data, GNUTLS_X509_FMT_PEM, 0);
			wget_xfree(data.data);

			if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-interm-cert.pem", &data)) < 0)
				file_load_err(SRCDIR "/certs/ocsp/x509-interm-cert.pem", gnutls_strerror(rc));

			gnutls_pcert_import_x509_raw(pcrt+1, &data, GNUTLS_X509_FMT_PEM, 0);
			wget_xfree(data.data);

			if (!httpsdaemon) {
				wget_error_printf("Cannot start the HTTPS server.\n");
				return 1;
			}

		}
#endif
	} else if (SERVER_MODE == OCSP_MODE) {
#ifdef WITH_GNUTLS_OCSP
		static char rnd[8] = "realrnd"; // fixed 'random' value

		ocspdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
			port_num, NULL, NULL, _ocsp_ahc, NULL,
			MHD_OPTION_DIGEST_AUTH_RANDOM, sizeof(rnd), rnd,
			MHD_OPTION_NONCE_NC_SIZE, 300,
#if MHD_VERSION >= 0x00095400
			MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
#if MHD_VERSION >= 0x00096800
			MHD_OPTION_SERVER_INSANITY, 1,
#endif
			MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) 1*1024*1024,
			MHD_OPTION_END);
#endif

		if (!ocspdaemon)
			return 1;
	}
#ifdef WITH_GNUTLS_OCSP
#if MHD_VERSION >= 0x00096502 && GNUTLS_VERSION_NUMBER >= 0x030603
	else if (SERVER_MODE == OCSP_STAP_MODE) {
		int rc;

		gnutls_datum_t data;

		/* Load private key */
		privkey = wget_malloc(sizeof(gnutls_privkey_t));

		gnutls_privkey_init(privkey);

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-key.pem", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/x509-server-key.pem", gnutls_strerror(rc));

		gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
		wget_xfree(data.data);

		/* Load certificate chain */
		pcrt = wget_malloc(sizeof(gnutls_pcert_st) * 2);

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-server-cert.pem", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/x509-server-cert.pem", gnutls_strerror(rc));

		gnutls_pcert_import_x509_raw(pcrt, &data, GNUTLS_X509_FMT_PEM, 0);
		wget_xfree(data.data);

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/x509-interm-cert.pem", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/x509-interm-cert.pem", gnutls_strerror(rc));

		gnutls_pcert_import_x509_raw(pcrt+1, &data, GNUTLS_X509_FMT_PEM, 0);
		wget_xfree(data.data);

		/* Load stapled OCSP response */
		ocsp_stap_resp = wget_malloc(sizeof(gnutls_ocsp_data_st));

		if ((rc = gnutls_load_file(SRCDIR "/certs/ocsp/ocsp_stapled_resp.der", &data)) < 0)
			file_load_err(SRCDIR "/certs/ocsp/ocsp_stapled_resp.der", gnutls_strerror(rc));

		ocsp_stap_resp->response.data = data.data;
		ocsp_stap_resp->response.size = data.size;
		ocsp_stap_resp->exptime = 0;

		/* Start HTTPS daemon with stapled OCSP responses */
		httpsdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS
				| MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT
			,
			port_num, _check_to_accept,
			(void *) (ptrdiff_t) SERVER_MODE, _answer_to_connection, NULL,
			MHD_OPTION_HTTPS_CERT_CALLBACK2, _ocsp_stap_cert_callback,
#if MHD_VERSION >= 0x00095400
				MHD_OPTION_STRICT_FOR_CLIENT, 1,
#endif
#if MHD_VERSION >= 0x00096800
			MHD_OPTION_SERVER_INSANITY, 1,
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
#ifdef WITH_GNUTLS_OCSP
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
#ifdef WITH_GNUTLS_OCSP
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
#ifdef WITH_GNUTLS_OCSP
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
#ifdef WITH_GNUTLS_OCSP
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
		wget_error_printf_exit("Failed to re-create directory (%d)\n", errno);
}
#else
// To reduce the verbosity of 'valgrind --trace-children=yes' output,
//   we avoid system("rm -rf ...") calls.
static void _remove_directory(const char *dirname);
static void _empty_directory(const char *dirname)
{
	DIR *dir;

	if ((dir = opendir(dirname))) {
		struct dirent *dp;

		while ((dp = readdir(dir))) {
			if (*dp->d_name == '.' && (dp->d_name[1] == 0 || (dp->d_name[1] == '.' && dp->d_name[2] == 0)))
				continue;

			char *fname = wget_aprintf("%s/%s", dirname, dp->d_name);

			if (unlink(fname) == -1) {
				// in case fname is a directory glibc returns EISDIR but correct POSIX value would be EPERM.
				// MinGW + Wine returns EACCESS here.
				if (errno == EISDIR || errno == EPERM || errno == EACCES)
					_remove_directory(fname);
				else
					wget_error_printf("Failed to unlink %s (%d)\n", fname, errno);
			}

			wget_xfree(fname);
		}

		closedir(dir);

		wget_debug_printf("Removed test directory '%s'\n", dirname);
	} else if (errno != ENOENT)
		wget_error_printf("Failed to opendir %s (%d)\n", dirname, errno);
}

static void _remove_directory(const char *dirname)
{
	_empty_directory(dirname);
	if (rmdir(dirname) == -1 && errno != ENOENT)
		wget_error_printf("Failed to rmdir %s (%d)\n", dirname, errno);
}
#endif

void wget_test_stop_server(void)
{
//	wget_vector_free(&response_headers);
	wget_vector_free(&request_urls);
	wget_vector_free(&ocsp_responses);

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
		wget_error_printf("Failed to chdir ..\n");

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
	bool start_https = 1;
#ifdef WITH_GNUTLS_OCSP
	bool ocsp_stap = 0;
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

	wget_debug_printf("MHD compiled with 0x%08x, linked with %s\n", (unsigned) MHD_VERSION, MHD_get_version());
#if MHD_VERSION >= 0x00095400
	wget_debug_printf("MHD_OPTION_STRICT_FOR_CLIENT: yes\n");
#else
	wget_debug_printf("MHD_OPTION_STRICT_FOR_CLIENT: no\n");
#endif
#if MHD_VERSION >= 0x00096800
	wget_debug_printf("MHD_OPTION_SERVER_INSANITY: yes\n");
#else
	wget_debug_printf("MHD_OPTION_SERVER_INSANITY: no\n");
#endif
#ifdef HAVE_MICROHTTPD_HTTP2_H
	wget_debug_printf("HAVE_MICROHTTPD_HTTP2_H: yes\n");
#else
	wget_debug_printf("HAVE_MICROHTTPD_HTTP2_H: no\n");
#endif
#ifdef HAVE_GNUTLS_OCSP_H
	wget_debug_printf("HAVE_GNUTLS_OCSP_H: yes\n");
#else
	wget_debug_printf("HAVE_GNUTLS_OCSP_H: no\n");
#endif
	wget_debug_printf("\n");

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
			wget_error_printf("Test requires TLS. Skipping\n");
			exit(WGET_TEST_EXIT_SKIP);
#endif
			break;
		case WGET_TEST_FEATURE_IDN:
#if !defined WITH_LIBIDN && !defined WITH_LIBIDN2
			wget_error_printf("Support for LibIDN not found. Skipping\n");
			exit(WGET_TEST_EXIT_SKIP);
#endif
			break;
		case WGET_TEST_FEATURE_PLUGIN:
#ifndef PLUGIN_SUPPORT
			wget_error_printf("Plugin Support Disabled. Skipping\n");
			exit(WGET_TEST_EXIT_SKIP);
#endif
			break;
		case WGET_TEST_FEATURE_OCSP:
#if !defined WITH_GNUTLS_OCSP
			wget_error_printf("Test requires GnuTLS with OCSP support. Skipping\n");
			exit(WGET_TEST_EXIT_SKIP);
#else
			start_http = 0;
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
#ifdef WITH_TLS
#ifdef WITH_GNUTLS_OCSP
			start_ocsp = 1;
#endif
#endif
			break;
#endif
		case WGET_TEST_FEATURE_OCSP_STAPLING:
#if !defined WITH_GNUTLS_OCSP || MHD_VERSION < 0x00096502 || GNUTLS_VERSION_NUMBER < 0x030603
			wget_error_printf("MHD or GnuTLS version insufficient. Skipping\n");
			exit(WGET_TEST_EXIT_SKIP);
#else
			start_http = 0;
#ifdef WITH_TLS
			start_https = 0;
#endif
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
#ifdef WITH_TLS
#ifdef WITH_GNUTLS_OCSP
			ocsp_stap = 1;
#endif
#endif
			break;
#endif
		case WGET_TEST_SKIP_H2:
#ifdef HAVE_MICROHTTPD_HTTP2_H
			start_h2 = 0;
#endif
			break;
		default:
			wget_error_printf("Unknown option %d\n", key);
		}
	}
	va_end(args);

	atexit(wget_test_stop_server);

	wget_snprintf(tmpdir, sizeof(tmpdir), ".test_%d", (int) getpid());

	// remove tmpdir if exists from previous tests
	_remove_directory(tmpdir);

	if (mkdir(tmpdir, 0755) != 0)
		wget_error_printf_exit("Failed to create tmpdir (%d)\n", errno);

	if (chdir(tmpdir) != 0)
		wget_error_printf_exit("Failed to change to tmpdir (%d)\n", errno);

	// start HTTP server
	if (start_http) {
		if ((rc = _http_server_start(HTTP_MODE)) != 0)
			wget_error_printf_exit("Failed to start HTTP server, error %d\n", rc);
	}

#ifdef WITH_TLS
#ifdef WITH_GNUTLS_OCSP
	// start OCSP responder
	if (start_ocsp) {
		if ((rc = _http_server_start(OCSP_MODE)) != 0)
			wget_error_printf_exit("Failed to start OCSP server, error %d\n", rc);
	}

	// start OCSP server (stapling)
	if (ocsp_stap) {
		if ((rc = _http_server_start(OCSP_STAP_MODE)) != 0)
			wget_error_printf_exit("Failed to start OCSP Stapling server, error %d\n", rc);
	}
#endif

	// start HTTPS server
	if (start_https) {
		if ((rc = _http_server_start(HTTPS_MODE)) != 0)
			wget_error_printf_exit("Failed to start HTTPS server, error %d\n", rc);
	}

#ifdef HAVE_MICROHTTPD_HTTP2_H
	// start h2 server
	if (start_h2) {
		if ((rc = _http_server_start(H2_MODE)) != 0)
			wget_error_printf_exit("Failed to start h2 server, error %d\n", rc);
	}
#endif
#endif
}

static void _scan_for_unexpected(const char *dirname, const wget_test_file_t *expected_files)
{
	DIR *dir;
	struct stat st;

	wget_info_printf("Entering %s\n", dirname);

	if ((dir = opendir(dirname))) {
		struct dirent *dp;

		while ((dp = readdir(dir))) {
			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
				continue;

			char *fname;
			if (*dirname == '.' && dirname[1] == 0)
				fname = wget_strdup(dp->d_name);
			else
				fname = wget_aprintf("%s/%s", dirname, dp->d_name);

			wget_info_printf(" - %s/%s\n", dirname, dp->d_name);
			if (stat(fname, &st) == 0 && S_ISDIR(st.st_mode)) {
				_scan_for_unexpected(fname, expected_files);
				wget_xfree(fname);
				continue;
			}

			if (expected_files) {
// Mac OS X converts to NFD, so we might find an unexpected file name, e.g. when using accents.
// Example: cedilla (%C3%A7) will be converted to c+composed_cedilla (%63%CC%A7)
// Since there are a few pitfalls with Apple's NFD, just skip the check here.
#if !(defined __APPLE__ && defined __MACH__)
				size_t it;

				wget_info_printf("search %s\n", fname);

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
					wget_error_printf_exit("Unexpected file %s/%s found\n", tmpdir, fname);
#endif
			} else
				wget_error_printf_exit("Unexpected file %s/%s found\n", tmpdir, fname);

			wget_xfree(fname);
		}

		closedir(dir);
	} else
		wget_error_printf_exit("Failed to diropen %s\n", dirname);
}

static const char *global_executable;
void wget_test_set_executable(const char *program)
{
	global_executable = program;
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
			*executable = global_executable;
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

		if (!executable) {
#if defined _WIN32 && !defined __MINGW32__
			if (proto_pass == H2_PASS)
				executable = BUILDDIR "\\..\\src\\wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 3 --tries=1 --https-enforce=hard --ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp";
			else
				executable = BUILDDIR "\\..\\src\\wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 3 --tries=1";
#else
			if (proto_pass == H2_PASS)
				executable = BUILDDIR "/../src/wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 3  --tries=1 --https-enforce=hard --ca-certificate=" SRCDIR "/certs/x509-ca-cert.pem --no-ocsp";
			else
				executable = BUILDDIR "/../src/wget2_noinstall" EXEEXT " -d --no-config --no-local-db --max-threads=1 --prefer-family=ipv4 --no-proxy --timeout 3 --tries=1";
#endif
		}

		keep_tmpfiles = 0;
		clean_directory = 1;

		if (!request_urls) {
			request_urls = wget_vector_create(8, NULL);
			wget_vector_set_destructor(request_urls, NULL);
		}

		if (!ocsp_responses) {
			ocsp_responses = wget_vector_create(2, NULL);
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
			case WGET_TEST_CLEAN_DIRECTORY:
				clean_directory = va_arg(args, int);
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
			case WGET_TEST_OCSP_RESP_FILES:
#ifdef WITH_GNUTLS_OCSP
			{
				const char *ocsp_resp_file = NULL;
				while ((ocsp_resp_file = va_arg(args, const char *))) {
					if (ocspdaemon) {
						ocsp_resp_t ocsp_resp = { .data = NULL, .size = 0 };
						if (*ocsp_resp_file) {
							ocsp_resp.data = wget_read_file(ocsp_resp_file, &ocsp_resp.size);
							if (ocsp_resp.data == NULL) {
								wget_error_printf_exit("Couldn't read the response from '%s'.\n", ocsp_resp_file);
							}
						}
						wget_vector_add_memdup(ocsp_responses, &ocsp_resp, sizeof(ocsp_resp));
					}
				}
				ocsp_response_pos = 0;
			}
#endif
				break;
			default:
				wget_error_printf_exit("Unknown option %d [%s]\n", key, options);
			}
		}
		va_end(args);

		if (clean_directory) {
			// clean directory
			wget_buffer_printf(cmd, "../%s", tmpdir);
			_empty_directory(cmd->data);
		}

		// create files
		if (existing_files) {
			for (it = 0; existing_files[it].name; it++) {
				mkdir_path(existing_files[it].name, 1);

				if (existing_files[it].hardlink) {
					if (link(existing_files[it].hardlink, existing_files[it].name) != 0) {
						wget_error_printf_exit("Failed to link %s/%s -> %s/%s [%s]\n",
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
						wget_error_printf_exit("Failed to write %zu bytes to file %s/%s [%s]\n",
							strlen(existing_content), tmpdir, existing_files[it].name, options);

					if (existing_files[it].timestamp) {
						// take the old utime() instead of utimes()
						if (utime(existing_files[it].name, &(struct utimbuf){ 0, existing_files[it].timestamp }))
							wget_error_printf_exit("Failed to set mtime of %s/%s [%s]\n",
								tmpdir, existing_files[it].name, options);
					}

					if (existing_content != existing_files[it].content)
						wget_xfree(existing_content);

				} else {
					wget_error_printf_exit("Failed to write open file %s/%s [%s] (%d,%s)\n",
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
			wget_buffer_printf(cmd, "valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes --child-silent-after-fork=yes --suppressions=" SRCDIR "/valgrind-suppressions --gen-suppressions=all %s %s", executable, options);
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

		wget_error_printf("\n##### Testing '%s'\n", cmd->data);

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
			wget_error_printf_exit("Failed to execute test (%d) [%s]\n", errno, options);
		/*
			rc = system(cmd->data);
		*/
		if (!WIFEXITED(rc)) {
			wget_error_printf_exit("Unexpected error code %d, expected %d [%s]\n", rc, expected_error_code, options);
		}
		else if (WEXITSTATUS(rc) != expected_error_code) {
			if (expected_error_code2 >= 0) {
				if (WEXITSTATUS(rc) != expected_error_code2)
					wget_error_printf_exit("Unexpected error code %d, expected %d or %d [%s]\n",
						WEXITSTATUS(rc), expected_error_code, expected_error_code2, options);
			}
			else
				wget_error_printf_exit("Unexpected error code %d, expected %d [%s]\n",
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
					wget_error_printf_exit("Missing expected file '%s/%s' [%s]\n", tmpdir, fname, options);

				if (expected_files[it].content) {
					size_t nbytes;
					char *content = wget_read_file(fname, &nbytes);

					if (content) {
						const char *expected_content = _insert_ports(expected_files[it].content);
						bool expected_content_alloc = 0;

						if (!expected_content)
							expected_content = expected_files[it].content;
						else
							expected_content_alloc = 1;

						size_t content_length = expected_files[it].content_length ? expected_files[it].content_length : strlen(expected_content);

						if (content_length != nbytes || memcmp(expected_content, content, nbytes) != 0) {
							wget_error_printf("Unexpected content in %s [%s]\n", fname, options);
							wget_error_printf("  Expected %zu bytes:\n%s\n", content_length, expected_content);
							wget_error_printf("  Got %zu bytes:\n%s\n", nbytes, content);
							exit(EXIT_FAILURE);
						}

						if (expected_content_alloc)
							wget_xfree(expected_content);
					}

					wget_xfree(content);
				}

				if (expected_files[it].timestamp && st.st_mtime != expected_files[it].timestamp)
					wget_error_printf_exit("Unexpected timestamp '%s/%s' (%ld) [%s]\n", tmpdir, fname, st.st_mtime, options);
			}
		}

		// look if there are unexpected files in our working dir
		_scan_for_unexpected(".", expected_files);

#if MHD_VERSION >= 0x00096302 && GNUTLS_VERSION_NUMBER >= 0x030603
		if (post_handshake_auth && *post_handshake_auth == CHECK_FAILED) {
			wget_free(post_handshake_auth);
			wget_error_printf_exit("Post-handshake authentication failed\n");
		} else if (post_handshake_auth)
			wget_free(post_handshake_auth);
#endif

		for (int i = 0; i < wget_vector_size(ocsp_responses); i++) {
			ocsp_resp_t *r = wget_vector_get(ocsp_responses, i);
			wget_xfree(r->data);
		}
		wget_vector_clear(ocsp_responses);
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

			if (memcmp(buf, fname[it], sizeof(fname[0]))) {
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
