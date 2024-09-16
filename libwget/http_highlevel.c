/*
 * Copyright (c) 2013 Tim Ruehsen
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
 * Highlevel HTTP functions
 *
 * Changelog
 * 21.01.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <wget.h>
#include "private.h"
#include "http.h"

static int stream_callback(wget_http_response *resp WGET_GCC_UNUSED, void *user_data, const char *data, size_t length)
{
	FILE *stream = (FILE *) user_data;

	size_t nbytes = fwrite(data, 1, length, stream);

	if (nbytes != length) {
		error_printf(_("Failed to fwrite %zu bytes of data (%d)\n"), length, errno);

		if (feof(stream))
			return -1;
	}

	return 0;
}

static int fd_callback(wget_http_response *resp WGET_GCC_UNUSED, void *user_data, const char *data, size_t length)
{
	int fd = *(int *) user_data;
	ssize_t nbytes = write(fd, data, length);

	if (nbytes == -1 || (size_t) nbytes != length)
		error_printf(_("Failed to write %zu bytes of data (%d)\n"), length, errno);

	return 0;
}

wget_http_response *wget_http_get(int first_key, ...)
{
	wget_vector *headers;
	wget_iri *uri = NULL;
	wget_http_connection *conn = NULL, **connp = NULL;
	wget_http_request *req;
	wget_http_response *resp = NULL;
	wget_vector *challenges = NULL;
	wget_cookie_db *cookie_db = NULL;
	FILE *saveas_stream = NULL;
	wget_http_body_callback *saveas_callback = NULL;
	int saveas_fd = -1;
	wget_http_header_callback *header_callback = NULL;
	va_list args;
	const char *url = NULL,	*url_encoding = NULL, *scheme = "GET";
	const char *http_username = NULL, *http_password = NULL;
	const char *saveas_name = NULL;
	int key, it, max_redirections = 5, redirection_level = 0;
	size_t bodylen = 0;
	const void *body = NULL;
	void *header_user_data = NULL, *body_user_data = NULL;
	bool debug_skip_body = 0;

	struct {
		bool
			cookies_enabled : 1,
			keep_header : 1,
			free_uri : 1;
	} bits = {
		.cookies_enabled = wget_global_get_int(WGET_COOKIES_ENABLED) != 0
	};

	if (!(headers = wget_vector_create(8, NULL))) {
		debug_printf("no memory\n");
		return NULL;
	}

	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case WGET_HTTP_URL:
			url = va_arg(args, const char *);
			break;
		case WGET_HTTP_URI:
			uri = va_arg(args, wget_iri *);
			break;
		case WGET_HTTP_URL_ENCODING:
			url_encoding = va_arg(args, const char *);
			break;
		case WGET_HTTP_HEADER_ADD:
		{
			wget_http_header_param param = {
				.name = va_arg(args, const char *),
				.value = va_arg(args, const char *)
			};
			if (wget_vector_add_memdup(headers, &param, sizeof(param)) < 0) {
				va_end(args);
				goto out;
			}
			break;
		}
		case WGET_HTTP_CONNECTION_PTR:
			connp = va_arg(args, wget_http_connection **);
			if (connp)
				conn = *connp;
			break;
		case WGET_HTTP_RESPONSE_KEEPHEADER:
			bits.keep_header = va_arg(args, int);
			break;
		case WGET_HTTP_MAX_REDIRECTIONS:
			max_redirections = va_arg(args, int);
			break;
		case WGET_HTTP_BODY_SAVEAS:
			saveas_name = va_arg(args, const char *);
			break;
		case WGET_HTTP_BODY_SAVEAS_STREAM:
			saveas_stream = va_arg(args, FILE *);
			break;
		case WGET_HTTP_BODY_SAVEAS_FUNC:
			saveas_callback = va_arg(args, wget_http_body_callback *);
			body_user_data = va_arg(args, void *);
			break;
		case WGET_HTTP_BODY_SAVEAS_FD:
			saveas_fd = va_arg(args, int);
			break;
		case WGET_HTTP_HEADER_FUNC:
			header_callback = va_arg(args, wget_http_header_callback *);
			header_user_data = va_arg(args, void *);
			break;
		case WGET_HTTP_SCHEME:
			scheme = va_arg(args, const char *);
			break;
		case WGET_HTTP_BODY:
			body = va_arg(args, const void *);
			bodylen = va_arg(args, size_t);
			break;
		case WGET_HTTP_DEBUG_SKIP_BODY:
			debug_skip_body = 1;
			break;
		default:
			error_printf(_("Unknown option %d\n"), key);
			va_end(args);
			goto out;
		}
	}
	va_end(args);

	if (url && !uri) {
		uri = wget_iri_parse(url, url_encoding);
		if (!uri) {
			error_printf (_("Error parsing URL\n"));
			goto out;
		}
		bits.free_uri = 1;
	}

	if (!uri) {
		error_printf(_("Missing URL/URI\n"));
		goto out;
	}

	if (bits.cookies_enabled)
		cookie_db = (wget_cookie_db *)wget_global_get_ptr(WGET_COOKIE_DB);

	while (uri && redirection_level <= max_redirections) {
		// create a HTTP/1.1 GET request.
		// the only default header is 'Host: domain' (taken from uri)
		req = wget_http_create_request(uri, scheme);
		if (!req)
			goto out;

		// add HTTP headers
		for (it = 0; it < wget_vector_size(headers); it++) {
			wget_http_add_header_param(req, wget_vector_get(headers, it));
		}

		if (challenges) {
			// There might be more than one challenge, we could select the most secure one.
			// For simplicity and testing we just take the first for now.
			// the following adds an Authorization: HTTP header
			wget_http_add_credentials(req, wget_vector_get(challenges, 0), http_username, http_password, 0);
			wget_http_free_challenges(&challenges);
		}

		// use keep-alive if you want to send more requests on the same connection
		// http_add_header(req, "Connection", "keep-alive");

		// enrich the HTTP request with the uri-related cookies we have
		if (cookie_db) {
			const char *cookie_string;
			if ((cookie_string = wget_cookie_create_request_header(cookie_db, uri))) {
				wget_http_add_header(req, "Cookie", cookie_string);
				xfree(cookie_string);
			}
		}

		if (connp) {
			wget_http_add_header(req, "Connection", "keepalive");
		}

		// open/reopen/reuse HTTP/HTTPS connection
		if (conn && !wget_strcmp(conn->esc_host, uri->host) &&
			conn->scheme == uri->scheme &&
			conn->port == uri->port)
		{
			debug_printf("reuse connection %s\n", conn->esc_host);
		} else {
			if (conn) {
				debug_printf("close connection %s\n", conn->esc_host);
				wget_http_close(&conn);
			}
			if (wget_http_open(&conn, uri) == WGET_E_SUCCESS)
				debug_printf("opened connection %s\n", conn->esc_host);
		}

		if (conn) {
			int rc;

			if (body && bodylen)
				wget_http_request_set_body(req, NULL, wget_memdup(body, bodylen), bodylen);

			req->debug_skip_body = debug_skip_body;

			rc = wget_http_send_request(conn, req);

			if (rc == 0) {
				wget_http_request_set_header_cb(req, header_callback, header_user_data);
				wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);
				if (saveas_name) {
					FILE *fp;
					if ((fp = fopen(saveas_name, "wb"))) {
						wget_http_request_set_body_cb(req, stream_callback, fp);
						resp = wget_http_get_response(conn);
						fclose(fp);
					} else
						debug_printf("Failed to open '%s' for writing\n", saveas_name);
				}
				else if (saveas_stream)  {
					wget_http_request_set_body_cb(req, stream_callback, saveas_stream);
					resp = wget_http_get_response(conn);
				} else if (saveas_callback) {
					wget_http_request_set_body_cb(req, saveas_callback, body_user_data);
					resp = wget_http_get_response(conn);
				} else if (saveas_fd != -1) {
					wget_http_request_set_body_cb(req, fd_callback, &saveas_fd);
					resp = wget_http_get_response(conn);
				} else
					resp = wget_http_get_response(conn);
			}
		}

		wget_http_free_request(&req);

		if (!resp)
			goto out;

		// server doesn't support or want keep-alive
		if (!resp->keep_alive)
			wget_http_close(&conn);

		if (cookie_db) {
			// check and normalization of received cookies
			wget_cookie_normalize_cookies(uri, resp->cookies);

			// put cookies into cookie-store (also known as cookie-jar)
			wget_cookie_store_cookies(cookie_db, resp->cookies);
		}

		if (resp->code == 401 && !challenges) { // Unauthorized
			if ((challenges = resp->challenges)) {
				resp->challenges = NULL;
				wget_http_free_response(&resp);
				if (redirection_level == 0 && max_redirections) {
					redirection_level = max_redirections; // just try one more time with authentication
					continue; // try again with credentials
				}
			}
			break;
		}

		// 304 Not Modified
		if (resp->code / 100 == 2 || resp->code / 100 >= 4 || resp->code == 304)
			break; // final response

		if (resp->location) {
			char uri_sbuf[1024];
			wget_buffer uri_buf;

			// if relative location, convert to absolute
			wget_buffer_init(&uri_buf, uri_sbuf, sizeof(uri_sbuf));
			wget_iri_relative_to_abs(uri, resp->location, -1, &uri_buf);

			if (bits.free_uri)
				wget_iri_free(&uri);

			uri = wget_iri_parse(uri_buf.data, NULL);
			bits.free_uri = 1;

			wget_buffer_deinit(&uri_buf);

			redirection_level++;
			continue;
		}

		break;
	}


out:
	if (connp) {
		*connp = conn;
	} else {
		wget_http_close(&conn);
	}

	wget_http_free_challenges(&challenges);

//	wget_vector_clear_nofree(headers);
	wget_vector_free(&headers);

	if (bits.free_uri)
		wget_iri_free(&uri);

	return resp;
}
